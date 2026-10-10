//! Separate receiver durable consumption and active-lease store.
//!
//! The receiver **never** opens the issuer DB or requires an issuance row.
//! This store manages durable nonce consumption, active lease tracking,
//! and typed control reservation/claim/release independently.
//!
//! ## Lease semantics
//!
//! - Signed validity (issued_at/expires_at) is converted to a bounded
//!   local monotonic lease. Wall-clock rollback never extends the lease.
//! - A delayed grant arriving after its signed expiry starts **no** lease.
//! - Fresh renewal requires a fresh signed credential and a fresh nonce;
//!   duplicate renewal cannot extend an existing deadline.
//! - Permit/result fields are private and immutable once committed.
//! - Generation-bound stop cannot affect replacement claims.
//! - Raw lease mutation is crate-private. Public renewal goes through
//!   `V2AdmissionController::renew_with_possession`, which verifies a new
//!   signed grant and fresh Manager possession before any durable commit.

use crate::ownership::ClaimState;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Receiver store format version.
///
/// v2 adds `approved_manager_key` / `approved_account_key` on active leases
/// so renewal can bind the exact admitted Manager. Older files are rejected
/// explicitly; they are never silently treated as current.
pub const RECEIVER_FORMAT_VERSION: i64 = 2;

/// Hard default cap on consumed nonce rows.
pub const DEFAULT_MAX_CONSUMED: i64 = 10_000;

/// Hard default cap on active lease rows.
pub const DEFAULT_MAX_LEASES: i64 = 10_000;

/// Fixed hard cap on any lease lifetime (30 seconds). Never caller-supplied.
pub const FIXED_MAX_LEASE_MS: u64 = 30_000;

/// Lease state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Lease is active and permits operation.
    Active,
    /// Release has been requested; awaiting acknowledgment or fence expiry.
    PendingRelease,
    /// Lease has been released.
    Released,
}

impl LeaseState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaseState::Active => "active",
            LeaseState::PendingRelease => "pending_release",
            LeaseState::Released => "released",
        }
    }

    pub fn parse_lease_state(s: &str) -> Option<Self> {
        match s {
            "active" => Some(LeaseState::Active),
            "pending_release" => Some(LeaseState::PendingRelease),
            "released" => Some(LeaseState::Released),
            _ => None,
        }
    }
}

/// Active lease record. Fields are immutable once committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    pub intent_id: String,
    pub nonce_hex: String,
    pub endpoint_key: [u8; 32],
    pub boot_id: String,
    pub worker_id: String,
    pub operation: String,
    pub operation_intent: String,
    pub desktop_generation: u64,
    pub display_generation: u64,
    /// Exact approved Manager key admitted with this lease.
    pub approved_manager_key: [u8; 32],
    /// Exact approved account key admitted with this lease.
    pub approved_account_key: [u8; 32],
    /// Monotonic lease deadline (not wall time).
    pub lease_deadline_mono_ms: u64,
    /// When the lease was granted (monotonic ms).
    pub granted_at_mono_ms: u64,
    /// Signed expires_at from the credential.
    pub signed_expires_at_ms: u64,
    pub state: LeaseState,
    /// Generation for generation-bound stop.
    pub generation: u64,
}

/// Parameters for consume_and_lease to avoid too many arguments.
pub struct ConsumeLeaseParams<'a> {
    pub intent_id: &'a str,
    pub nonce_hex: &'a str,
    pub endpoint_key: &'a [u8; 32],
    pub boot_id: &'a str,
    pub worker_id: &'a str,
    pub operation: &'a str,
    pub operation_intent: &'a str,
    pub desktop_generation: u64,
    pub display_generation: u64,
    pub approved_manager_key: &'a [u8; 32],
    pub approved_account_key: &'a [u8; 32],
    pub signed_expires_at_ms: u64,
    pub lease_deadline_mono_ms: u64,
    pub current_mono_ms: u64,
}

/// Parameters for crate-private `renew_lease`.
///
/// Not part of the public authority surface. `fresh_signed_expires_at_ms`
/// must come from a verified fresh grant; the deadline is clamped to
/// [`FIXED_MAX_LEASE_MS`], never a caller cap.
pub struct RenewLeaseParams<'a> {
    pub intent_id: &'a str,
    pub fresh_nonce_hex: &'a str,
    /// Signed `expires_at` from the fresh renewal credential.
    pub fresh_signed_expires_at_ms: u64,
    /// Wall clock used to measure remaining signed validity.
    pub now_wall_ms: u64,
    pub current_mono_ms: u64,
}

/// Receiver store error.
#[derive(Debug, Error)]
pub enum ReceiverError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store file already exists")]
    AlreadyExists,
    #[error("store file missing")]
    NotFound,
    #[error("timestamp overflow for INTEGER column")]
    TimestampOverflow,
    #[error("negative DB integer field")]
    NegativeDbInteger,
    #[error("receiver config not initialized")]
    NotInitialized,
    #[error("receiver config mismatch")]
    ConfigMismatch,
    #[error("receiver config corrupt")]
    ConfigCorrupt,
    #[error("nonce already consumed")]
    NonceAlreadyConsumed,
    #[error("lease not found")]
    LeaseNotFound,
    #[error("lease not active")]
    LeaseNotActive,
    #[error("lease already exists for this intent")]
    LeaseAlreadyExists,
    #[error("renewal deadline would not extend")]
    RenewalNoExtension,
    #[error("lease monotonic deadline reached")]
    LeaseExpired,
    #[error("controller conflict: endpoint already has a non-released claim")]
    ControllerConflict,
    #[error("controller claim not found")]
    ControllerNotFound,
    #[error("capacity exhausted")]
    CapacityExhausted,
    #[error("gate latched closed: {0}")]
    GateLatched(String),
    #[error("storage fault (latched): {0}")]
    StorageFault(String),
    #[error("clock fault: {0}")]
    ClockFault(String),
    #[error("grant already expired at signed deadline")]
    GrantExpired,
    #[error("malformed nonce hex")]
    MalformedNonce,
    #[error("receiver format version mismatch: found {found}, expected {expected}")]
    FormatVersionMismatch { found: i64, expected: i64 },
}

impl ReceiverError {
    pub fn is_storage_fault(&self) -> bool {
        matches!(
            self,
            ReceiverError::Db(_)
                | ReceiverError::StorageFault(_)
                | ReceiverError::Io(_)
                | ReceiverError::TimestampOverflow
                | ReceiverError::NegativeDbInteger
                | ReceiverError::ConfigCorrupt
        )
    }
}

fn u64_to_i64(v: u64) -> Result<i64, ReceiverError> {
    i64::try_from(v).map_err(|_| ReceiverError::TimestampOverflow)
}

fn i64_to_u64(v: i64) -> Result<u64, ReceiverError> {
    if v < 0 {
        return Err(ReceiverError::NegativeDbInteger);
    }
    Ok(v as u64)
}

fn is_unique_violation_on(err: &rusqlite::Error, needle: &str) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, Some(msg)) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
                && (msg.contains(needle) || msg.contains("UNIQUE"))
        }
        rusqlite::Error::SqliteFailure(e, None) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
        }
        _ => false,
    }
}

fn is_nonce_unique_violation(err: &rusqlite::Error) -> bool {
    is_unique_violation_on(err, "consumed_nonces")
}

fn is_challenge_unique_violation(err: &rusqlite::Error) -> bool {
    is_unique_violation_on(err, "consumed_challenges")
}

fn is_controller_unique_violation(err: &rusqlite::Error) -> bool {
    is_unique_violation_on(err, "control_claims")
        || is_unique_violation_on(err, "one_controller_per_endpoint")
}

/// Exactly 32 raw bytes as lowercase/uppercase hex (64 chars).
fn is_valid_nonce_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Receiver durable lease store backed by SQLite.
pub struct ReceiverLeaseStore {
    conn: Connection,
    path: Option<PathBuf>,
    max_consumed: i64,
    max_leases: i64,
    latched: bool,
    latch_reason: String,
    /// Monotonic clock origin for lease calculations.
    /// On restart, resets; lease deadlines are relative to this.
    mono_origin_ms: u64,
    /// Last observed monotonic ms. Backward movement latches.
    last_mono_ms: Option<u64>,
    /// Last observed wall-clock ms used for signed validity. Backward
    /// movement latches (never revives an expired grant).
    last_wall_ms: Option<u64>,
}

impl ReceiverLeaseStore {
    /// Exclusive fresh creation.
    pub fn create(path: &Path, mono_origin_ms: u64) -> Result<Self, ReceiverError> {
        Self::create_with_limits(
            path,
            mono_origin_ms,
            DEFAULT_MAX_CONSUMED,
            DEFAULT_MAX_LEASES,
        )
    }

    pub fn create_with_limits(
        path: &Path,
        mono_origin_ms: u64,
        max_consumed: i64,
        max_leases: i64,
    ) -> Result<Self, ReceiverError> {
        {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(ReceiverError::AlreadyExists)
                }
                Err(e) => return Err(ReceiverError::Io(e)),
            }
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            max_consumed,
            max_leases,
            latched: false,
            latch_reason: String::new(),
            mono_origin_ms,
            last_mono_ms: None,
            last_wall_ms: None,
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    /// Open an existing store.
    pub fn open(path: &Path, mono_origin_ms: u64) -> Result<Self, ReceiverError> {
        Self::open_with_limits(
            path,
            mono_origin_ms,
            DEFAULT_MAX_CONSUMED,
            DEFAULT_MAX_LEASES,
        )
    }

    pub fn open_with_limits(
        path: &Path,
        mono_origin_ms: u64,
        max_consumed: i64,
        max_leases: i64,
    ) -> Result<Self, ReceiverError> {
        if !path.exists() {
            return Err(ReceiverError::NotFound);
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            max_consumed,
            max_leases,
            latched: false,
            latch_reason: String::new(),
            mono_origin_ms,
            last_mono_ms: None,
            last_wall_ms: None,
        };
        store.configure_connection()?;
        store.validate_existing()?;
        store.refresh_fault_state()?;
        // Fence all pre-restart active leases and controller claims:
        // monotonic deadlines are invalid across process restart because
        // the clock origin resets. Consumed nonces/challenges are preserved
        // (replay history must not be lost).
        store.fence_old_leases()?;
        store.fence_old_control_claims()?;
        Ok(store)
    }

    /// In-memory store for fixtures.
    pub fn create_memory(mono_origin_ms: u64) -> Result<Self, ReceiverError> {
        Self::create_memory_with_limits(mono_origin_ms, DEFAULT_MAX_CONSUMED, DEFAULT_MAX_LEASES)
    }

    pub fn create_memory_with_limits(
        mono_origin_ms: u64,
        max_consumed: i64,
        max_leases: i64,
    ) -> Result<Self, ReceiverError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self {
            conn,
            path: None,
            max_consumed,
            max_leases,
            latched: false,
            latch_reason: String::new(),
            mono_origin_ms,
            last_mono_ms: None,
            last_wall_ms: None,
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    fn configure_connection(&mut self) -> Result<(), ReceiverError> {
        self.conn.pragma_update(None, "synchronous", "FULL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(200))?;
        Ok(())
    }

    fn create_schema(&mut self) -> Result<(), ReceiverError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            r#"
            CREATE TABLE receiver_config (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                format_version    INTEGER NOT NULL,
                issuer_public_key BLOB NOT NULL,
                issuer_generation INTEGER NOT NULL,
                endpoint_key      BLOB NOT NULL,
                initialized       INTEGER NOT NULL CHECK (initialized IN (0, 1)),
                created_at_ms     INTEGER NOT NULL
            );

            CREATE TABLE active_leases (
                intent_id              TEXT PRIMARY KEY,
                nonce_hex              TEXT NOT NULL,
                endpoint_key           BLOB NOT NULL,
                boot_id                TEXT NOT NULL,
                worker_id              TEXT NOT NULL,
                operation              TEXT NOT NULL,
                operation_intent       TEXT NOT NULL,
                desktop_generation     INTEGER NOT NULL,
                display_generation     INTEGER NOT NULL,
                approved_manager_key   BLOB NOT NULL,
                approved_account_key   BLOB NOT NULL,
                lease_deadline_mono_ms INTEGER NOT NULL,
                granted_at_mono_ms     INTEGER NOT NULL,
                signed_expires_at_ms   INTEGER NOT NULL,
                state                  TEXT NOT NULL,
                generation             INTEGER NOT NULL
            );

            CREATE TABLE consumed_nonces (
                nonce_hex      TEXT PRIMARY KEY,
                consumed_at_ms INTEGER NOT NULL,
                intent_id      TEXT NOT NULL
            );

            CREATE TABLE consumed_challenges (
                nonce_hex      TEXT PRIMARY KEY,
                consumed_at_ms INTEGER NOT NULL,
                intent_id      TEXT NOT NULL
            );

            CREATE TABLE control_claims (
                intent_id           TEXT PRIMARY KEY,
                endpoint_key        BLOB NOT NULL,
                generation          INTEGER NOT NULL,
                state               TEXT NOT NULL,
                claimed_at_mono_ms  INTEGER NOT NULL
            );

            -- At most one non-released controller per endpoint (includes
            -- reserved and pending_release). Released rows free the slot.
            CREATE UNIQUE INDEX one_controller_per_endpoint
                ON control_claims(endpoint_key)
                WHERE state != 'released';

            CREATE TABLE fault_state (
                id         INTEGER PRIMARY KEY CHECK (id = 1),
                latched    INTEGER NOT NULL CHECK (latched IN (0, 1)),
                reason     TEXT NOT NULL,
                latched_at INTEGER NOT NULL
            );
            "#,
        )?;
        let now = now_i64();
        tx.execute(
            "INSERT INTO receiver_config (id, format_version, issuer_public_key, issuer_generation, endpoint_key, initialized, created_at_ms) VALUES (1, ?1, X'', 0, X'', 0, ?2)",
            params![RECEIVER_FORMAT_VERSION, now],
        )?;
        tx.execute(
            "INSERT INTO fault_state (id, latched, reason, latched_at) VALUES (1, 0, 'healthy', ?1)",
            params![now],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn validate_existing(&mut self) -> Result<(), ReceiverError> {
        let result = (|| -> Result<(), ReceiverError> {
            let names = [
                "receiver_config",
                "active_leases",
                "consumed_nonces",
                "consumed_challenges",
                "control_claims",
                "fault_state",
            ];
            for name in names {
                let found: Option<i64> = self
                    .conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        params![name],
                        |_| Ok(1),
                    )
                    .optional()?;
                if found.is_none() {
                    return Err(ReceiverError::ConfigCorrupt);
                }
            }
            let fmt: Option<(i64, i64)> = self
                .conn
                .query_row(
                    "SELECT format_version, initialized FROM receiver_config WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (ver, init) = fmt.ok_or(ReceiverError::ConfigCorrupt)?;
            if ver != RECEIVER_FORMAT_VERSION || !(init == 0 || init == 1) {
                // Explicit format mismatch — never treat an older
                // schema as current.
                return Err(ReceiverError::FormatVersionMismatch {
                    found: ver,
                    expected: RECEIVER_FORMAT_VERSION,
                });
            }
            // v2 lease binding columns must be present.
            let has_mgr: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM pragma_table_info('active_leases') WHERE name = 'approved_manager_key'",
                    [],
                    |_| Ok(1),
                )
                .optional()?;
            if has_mgr.is_none() {
                return Err(ReceiverError::FormatVersionMismatch {
                    found: 1,
                    expected: RECEIVER_FORMAT_VERSION,
                });
            }
            Ok(())
        })();
        result.inspect_err(|e| {
            let msg = e.to_string();
            self.latch_fault(&msg);
        })
    }

    fn sidecar_path(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| {
            let mut os = p.as_os_str().to_owned();
            os.push(".fault");
            PathBuf::from(os)
        })
    }

    fn write_durable_sidecar(&self, reason: &str) -> Result<(), std::io::Error> {
        let Some(side) = self.sidecar_path() else {
            return Err(std::io::Error::other("no sidecar path"));
        };
        let mut f = std::fs::File::create(&side)?;
        f.write_all(reason.as_bytes())?;
        f.sync_all()?;
        if let Some(parent) = side.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn latch_fault(&mut self, reason: &str) {
        self.latched = true;
        if self.latch_reason.is_empty() {
            self.latch_reason = reason.to_string();
        }
        let now = now_i64();
        let db_ok = self
            .conn
            .execute(
                "INSERT OR REPLACE INTO fault_state (id, latched, reason, latched_at) VALUES (1, 1, ?1, ?2)",
                params![reason, now],
            )
            .is_ok();
        // Belt-and-braces: sidecar too regardless of DB outcome.
        let _ = self.write_durable_sidecar(reason);
        let _ = db_ok;
    }

    fn refresh_fault_state(&mut self) -> Result<(), ReceiverError> {
        if let Some(side) = self.sidecar_path() {
            match std::fs::symlink_metadata(side) {
                Ok(_) => {
                    self.latched = true;
                    if self.latch_reason.is_empty() {
                        self.latch_reason = "sidecar fault latch present".into();
                    }
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(self.map_fault(ReceiverError::Io(e))),
            }
        }
        let result = (|| -> Result<(), ReceiverError> {
            let row: Option<i64> = self
                .conn
                .query_row("SELECT latched FROM fault_state WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .optional()?;
            match row {
                Some(0) => Ok(()),
                Some(1) => Err(ReceiverError::GateLatched("fault_state latched=1".into())),
                _ => Err(ReceiverError::ConfigCorrupt),
            }
        })();
        match result {
            Ok(()) => Ok(()),
            Err(ReceiverError::GateLatched(reason)) => {
                self.latched = true;
                if self.latch_reason.is_empty() {
                    self.latch_reason = reason;
                }
                Ok(())
            }
            Err(e) => Err(self.map_fault(e)),
        }
    }

    fn map_fault(&mut self, err: ReceiverError) -> ReceiverError {
        if err.is_storage_fault() {
            let msg = err.to_string();
            self.latch_fault(&msg);
            if matches!(err, ReceiverError::Db(_) | ReceiverError::Io(_)) {
                return ReceiverError::StorageFault(self.latch_reason.clone());
            }
        }
        err
    }

    /// Fence all pre-restart active/pending_release leases.
    /// Monotonic deadlines are invalid across process restart.
    /// Consumed nonces are preserved (replay history must not be lost).
    fn fence_old_leases(&mut self) -> Result<(), ReceiverError> {
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let fenced = tx.execute(
                "UPDATE active_leases SET state = ?1 WHERE state IN (?2, ?3)",
                params![
                    LeaseState::Released.as_str(),
                    LeaseState::Active.as_str(),
                    LeaseState::PendingRelease.as_str(),
                ],
            )?;
            tx.commit()?;
            if fenced > 0 {
                // Log that leases were fenced (for diagnostics)
                let _ = fenced;
            }
            Ok(())
        })();
        // Fence failures are a storage fault that closes the gate.
        result.map_err(|e| self.map_fault(e))
    }

    /// Fence all pre-restart non-released controller claims.
    /// Process-local controller authority cannot reactivate after restart.
    fn fence_old_control_claims(&mut self) -> Result<(), ReceiverError> {
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE control_claims SET state = ?1 WHERE state != ?1",
                params![LeaseState::Released.as_str()],
            )?;
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    fn ensure_open(&mut self) -> Result<(), ReceiverError> {
        self.refresh_fault_state()?;
        if self.latched {
            return Err(ReceiverError::GateLatched(self.latch_reason.clone()));
        }
        Ok(())
    }

    pub fn is_latched(&self) -> bool {
        self.latched
    }

    pub fn mono_origin_ms(&self) -> u64 {
        self.mono_origin_ms
    }

    pub fn latch_reason(&self) -> &str {
        &self.latch_reason
    }

    /// Check and advance the monotonic clock. Backward movement latches.
    pub fn check_monotonic(&mut self, current_mono_ms: u64) -> Result<(), ReceiverError> {
        if let Some(last) = self.last_mono_ms {
            if current_mono_ms < last {
                self.latch_fault(&format!(
                    "monotonic rollback: last={last} now={current_mono_ms}"
                ));
                return Err(ReceiverError::ClockFault(format!(
                    "monotonic rollback: last={last} now={current_mono_ms}"
                )));
            }
        }
        self.last_mono_ms = Some(current_mono_ms);
        Ok(())
    }

    /// Compute a monotonic lease deadline from a signed expiry.
    /// Does not extend lifetime if the grant arrives late.
    pub fn compute_lease_deadline(
        &self,
        signed_expires_at_ms: u64,
        current_mono_ms: u64,
        max_lifetime_ms: u64,
        now_wall_ms: u64,
    ) -> Result<u64, ReceiverError> {
        // Remaining signed validity from now
        if now_wall_ms >= signed_expires_at_ms {
            return Err(ReceiverError::GrantExpired);
        }
        let remaining_wall = signed_expires_at_ms - now_wall_ms;
        // Cap at max lifetime
        let lease_duration = remaining_wall.min(max_lifetime_ms);
        // Convert to monotonic deadline
        current_mono_ms
            .checked_add(lease_duration)
            .ok_or(ReceiverError::TimestampOverflow)
    }

    /// Initialize receiver config. One-shot on a fresh handle.
    pub fn initialize(
        &mut self,
        issuer_public_key: &[u8; 32],
        issuer_generation: u64,
        endpoint_key: &[u8; 32],
    ) -> Result<(), ReceiverError> {
        self.ensure_open()?;
        if issuer_generation == 0 {
            return Err(ReceiverError::ConfigMismatch);
        }
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<(i64, Vec<u8>, i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT initialized, issuer_public_key, issuer_generation, endpoint_key FROM receiver_config WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let Some((init, key, gen, ep)) = existing else {
                tx.rollback()?;
                return Err(ReceiverError::ConfigCorrupt);
            };
            if init == 1 {
                if key.as_slice() != issuer_public_key.as_slice()
                    || i64_to_u64(gen)? != issuer_generation
                    || ep.as_slice() != endpoint_key.as_slice()
                {
                    tx.rollback()?;
                    return Err(ReceiverError::ConfigMismatch);
                }
                tx.rollback()?;
                return Ok(());
            }
            tx.execute(
                "UPDATE receiver_config SET initialized = 1, issuer_public_key = ?1, issuer_generation = ?2, endpoint_key = ?3 WHERE id = 1",
                params![issuer_public_key.as_slice(), u64_to_i64(issuer_generation)?, endpoint_key.as_slice()],
            )?;
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Atomically consume a nonce and create an active lease.
    /// The nonce is consumed exactly once; duplicate nonces are rejected.
    /// The lease deadline is computed from signed validity using monotonic time.
    ///
    /// Public for integration test access; production callers must use
    /// `V2AdmissionController::admit_with_possession` which performs
    /// cryptographic verification before calling this.
    pub fn consume_and_lease(
        &mut self,
        params: ConsumeLeaseParams<'_>,
    ) -> Result<(), ReceiverError> {
        if !is_valid_nonce_hex(params.nonce_hex) {
            return Err(ReceiverError::MalformedNonce);
        }
        self.ensure_open()?;
        self.check_monotonic(params.current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Fault check
            let fault: Option<i64> = tx
                .query_row("SELECT latched FROM fault_state WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .optional()?;
            match fault {
                Some(0) => {}
                Some(1) => {
                    tx.rollback()?;
                    return Err(ReceiverError::GateLatched("fault_state latched=1".into()));
                }
                _ => {
                    tx.rollback()?;
                    return Err(ReceiverError::ConfigCorrupt);
                }
            }

            // Replay of a known nonce is denied before capacity so a
            // consumed nonce can never be re-accepted under exhaustion.
            let existing: Option<String> = tx
                .query_row(
                    "SELECT nonce_hex FROM consumed_nonces WHERE nonce_hex = ?1",
                    params![params.nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }

            // Capacity checks
            let consumed_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM consumed_nonces", [], |r| r.get(0))?;
            if consumed_count >= self.max_consumed {
                tx.rollback()?;
                return Err(ReceiverError::CapacityExhausted);
            }
            let lease_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM active_leases", [], |r| r.get(0))?;
            if lease_count >= self.max_leases {
                tx.rollback()?;
                return Err(ReceiverError::CapacityExhausted);
            }

            // Consume nonce atomically
            let changed = tx.execute(
                "INSERT INTO consumed_nonces (nonce_hex, consumed_at_ms, intent_id) VALUES (?1, ?2, ?3)",
                params![params.nonce_hex, u64_to_i64(params.current_mono_ms)?, params.intent_id],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }

            // Create active lease
            let changed = tx.execute(
                "INSERT INTO active_leases (
                    intent_id, nonce_hex, endpoint_key, boot_id, worker_id,
                    operation, operation_intent, desktop_generation, display_generation,
                    approved_manager_key, approved_account_key,
                    lease_deadline_mono_ms, granted_at_mono_ms, signed_expires_at_ms,
                    state, generation
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 1)",
                params![
                    params.intent_id,
                    params.nonce_hex,
                    params.endpoint_key,
                    params.boot_id,
                    params.worker_id,
                    params.operation,
                    params.operation_intent,
                    u64_to_i64(params.desktop_generation)?,
                    u64_to_i64(params.display_generation)?,
                    params.approved_manager_key.as_slice(),
                    params.approved_account_key.as_slice(),
                    u64_to_i64(params.lease_deadline_mono_ms)?,
                    u64_to_i64(params.current_mono_ms)?,
                    u64_to_i64(params.signed_expires_at_ms)?,
                    LeaseState::Active.as_str(),
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::LeaseAlreadyExists);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, ReceiverError::Db(ref de) if is_nonce_unique_violation(de)) {
                return ReceiverError::NonceAlreadyConsumed;
            }
            self.map_fault(e)
        })
    }

    /// Check if a lease is active and not expired at the given monotonic time.
    pub fn is_lease_active(
        &mut self,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<bool, ReceiverError> {
        self.ensure_open()?;
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<bool, ReceiverError> {
            let row: Option<(String, i64)> = self
                .conn
                .query_row(
                    "SELECT state, lease_deadline_mono_ms FROM active_leases WHERE intent_id = ?1",
                    params![intent_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => Ok(false),
                Some((state_str, deadline_i64)) => {
                    let state = LeaseState::parse_lease_state(&state_str)
                        .ok_or(ReceiverError::ConfigCorrupt)?;
                    let deadline = i64_to_u64(deadline_i64)?;
                    Ok(state == LeaseState::Active && current_mono_ms < deadline)
                }
            }
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Get lease record by intent_id.
    pub fn get_lease(&mut self, intent_id: &str) -> Result<Option<LeaseRecord>, ReceiverError> {
        self.ensure_open()?;
        let result = (|| -> Result<Option<LeaseRecord>, ReceiverError> {
            let row = self
                .conn
                .query_row(
                    "SELECT intent_id, nonce_hex, endpoint_key, boot_id, worker_id,
                            operation, operation_intent, desktop_generation, display_generation,
                            approved_manager_key, approved_account_key,
                            lease_deadline_mono_ms, granted_at_mono_ms, signed_expires_at_ms,
                            state, generation
                     FROM active_leases WHERE intent_id = ?1",
                    params![intent_id],
                    |r| {
                        let ep_key: Vec<u8> = r.get(2)?;
                        let mgr_key: Vec<u8> = r.get(9)?;
                        let acct_key: Vec<u8> = r.get(10)?;
                        if ep_key.len() != 32 || mgr_key.len() != 32 || acct_key.len() != 32 {
                            return Err(rusqlite::Error::InvalidColumnType(
                                2,
                                "key length".into(),
                                rusqlite::types::Type::Blob,
                            ));
                        }
                        let mut ek = [0u8; 32];
                        ek.copy_from_slice(&ep_key);
                        let mut mk = [0u8; 32];
                        mk.copy_from_slice(&mgr_key);
                        let mut ak = [0u8; 32];
                        ak.copy_from_slice(&acct_key);
                        let desk_i64: i64 = r.get(7)?;
                        let disp_i64: i64 = r.get(8)?;
                        let deadline_i64: i64 = r.get(11)?;
                        let granted_i64: i64 = r.get(12)?;
                        let signed_i64: i64 = r.get(13)?;
                        let gen_i64: i64 = r.get(15)?;
                        if desk_i64 < 0
                            || disp_i64 < 0
                            || deadline_i64 < 0
                            || granted_i64 < 0
                            || signed_i64 < 0
                            || gen_i64 < 0
                        {
                            return Err(rusqlite::Error::InvalidColumnType(
                                7,
                                "negative integer".into(),
                                rusqlite::types::Type::Integer,
                            ));
                        }
                        let state_str: String = r.get(14)?;
                        let state = LeaseState::parse_lease_state(&state_str).ok_or(
                            rusqlite::Error::InvalidColumnType(
                                14,
                                "invalid state".into(),
                                rusqlite::types::Type::Text,
                            ),
                        )?;
                        Ok(LeaseRecord {
                            intent_id: r.get(0)?,
                            nonce_hex: r.get(1)?,
                            endpoint_key: ek,
                            boot_id: r.get(3)?,
                            worker_id: r.get(4)?,
                            operation: r.get(5)?,
                            operation_intent: r.get(6)?,
                            desktop_generation: desk_i64 as u64,
                            display_generation: disp_i64 as u64,
                            approved_manager_key: mk,
                            approved_account_key: ak,
                            lease_deadline_mono_ms: deadline_i64 as u64,
                            granted_at_mono_ms: granted_i64 as u64,
                            signed_expires_at_ms: signed_i64 as u64,
                            state,
                            generation: gen_i64 as u64,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Request release of a lease (PendingRelease).
    /// Stop cleanup remains possible without audit persistence: this path
    /// does not require a healthy gate and never fails closed on a latch.
    pub fn request_release(
        &mut self,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE active_leases SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    LeaseState::PendingRelease.as_str(),
                    intent_id,
                    LeaseState::Active.as_str()
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Err(ReceiverError::LeaseNotActive);
            }
            tx.commit()?;
            Ok(())
        })();
        // Do not latch on release-path storage faults; cleanup must proceed.
        result
    }

    /// Confirm release (acknowledged).
    /// Stop cleanup remains possible without audit persistence.
    pub fn confirm_release(
        &mut self,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE active_leases SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    LeaseState::Released.as_str(),
                    intent_id,
                    LeaseState::PendingRelease.as_str()
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Err(ReceiverError::LeaseNotActive);
            }
            tx.commit()?;
            Ok(())
        })();
        // Do not latch on release-path storage faults; cleanup must proceed.
        result
    }

    /// Is the nonce already consumed?
    pub fn is_nonce_consumed(&mut self, nonce_hex: &str) -> Result<bool, ReceiverError> {
        self.ensure_open()?;
        let result = (|| -> Result<bool, ReceiverError> {
            let found: Option<String> = self
                .conn
                .query_row(
                    "SELECT nonce_hex FROM consumed_nonces WHERE nonce_hex = ?1",
                    params![nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(found.is_some())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Durably consume a possession challenge nonce exactly once.
    /// Survives process restart; a consumed challenge remains denied.
    ///
    /// Fail-closed bounded state: input must be 32-byte hex and the
    /// durable table is capacity-capped (same policy as consumed nonces).
    pub fn consume_challenge(
        &mut self,
        challenge_nonce_hex: &str,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        if !is_valid_nonce_hex(challenge_nonce_hex) {
            return Err(ReceiverError::MalformedNonce);
        }
        self.ensure_open()?;
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Replay of a known challenge is denied before capacity so a
            // consumed nonce can never be re-accepted under exhaustion.
            let existing: Option<String> = tx
                .query_row(
                    "SELECT nonce_hex FROM consumed_challenges WHERE nonce_hex = ?1",
                    params![challenge_nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }
            let count: i64 =
                tx.query_row("SELECT COUNT(*) FROM consumed_challenges", [], |r| r.get(0))?;
            if count >= self.max_consumed {
                tx.rollback()?;
                return Err(ReceiverError::CapacityExhausted);
            }
            let changed = tx.execute(
                "INSERT INTO consumed_challenges (nonce_hex, consumed_at_ms, intent_id) VALUES (?1, ?2, ?3)",
                params![
                    challenge_nonce_hex,
                    u64_to_i64(current_mono_ms)?,
                    intent_id
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, ReceiverError::Db(ref de) if is_challenge_unique_violation(de)) {
                return ReceiverError::NonceAlreadyConsumed;
            }
            self.map_fault(e)
        })
    }

    /// Has this possession challenge nonce already been consumed?
    pub fn is_challenge_consumed(
        &mut self,
        challenge_nonce_hex: &str,
    ) -> Result<bool, ReceiverError> {
        self.ensure_open()?;
        let result = (|| -> Result<bool, ReceiverError> {
            let found: Option<String> = self
                .conn
                .query_row(
                    "SELECT nonce_hex FROM consumed_challenges WHERE nonce_hex = ?1",
                    params![challenge_nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(found.is_some())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Renew an active lease with a fresh one-shot nonce and fresh signed
    /// validity.
    ///
    /// Crate-private: callers must not mutate leases without prior
    /// cryptographic verification. Public renewal is
    /// `V2AdmissionController::renew_with_possession`.
    ///
    /// - The lease must already be Active **and** unexpired:
    ///   `current_mono_ms < lease_deadline_mono_ms` (exact boundary denies).
    ///   An expired lease cannot be revived; a new explicit intent/admission
    ///   is required after safe cleanup.
    /// - `fresh_nonce_hex` must be unused; duplicate renewal cannot extend.
    /// - The new deadline is computed from the fresh signed expiry and
    ///   clamped to [`FIXED_MAX_LEASE_MS`] (never a caller cap).
    pub(crate) fn renew_lease(
        &mut self,
        params: RenewLeaseParams<'_>,
    ) -> Result<(), ReceiverError> {
        if !is_valid_nonce_hex(params.fresh_nonce_hex) {
            return Err(ReceiverError::MalformedNonce);
        }
        self.ensure_open()?;
        self.check_monotonic(params.current_mono_ms)?;
        // Deadline comes from fresh signed validity, clamped to the fixed cap.
        if params.now_wall_ms >= params.fresh_signed_expires_at_ms {
            return Err(ReceiverError::GrantExpired);
        }
        let remaining_wall = params.fresh_signed_expires_at_ms - params.now_wall_ms;
        let lease_duration = remaining_wall.min(FIXED_MAX_LEASE_MS);
        let new_deadline = params
            .current_mono_ms
            .checked_add(lease_duration)
            .ok_or(ReceiverError::TimestampOverflow)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(String, i64)> = tx
                .query_row(
                    "SELECT state, lease_deadline_mono_ms FROM active_leases WHERE intent_id = ?1",
                    params![params.intent_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((state_str, deadline_i64)) = row else {
                tx.rollback()?;
                return Err(ReceiverError::LeaseNotFound);
            };
            let state =
                LeaseState::parse_lease_state(&state_str).ok_or(ReceiverError::ConfigCorrupt)?;
            if state != LeaseState::Active {
                tx.rollback()?;
                return Err(ReceiverError::LeaseNotActive);
            }
            let current_deadline = i64_to_u64(deadline_i64)?;
            // Expiry is re-checked inside the transaction, not only in the
            // controller. Exact boundary (>=) denies: an expired Active row
            // must not be revived by a fresh credential.
            if params.current_mono_ms >= current_deadline {
                tx.rollback()?;
                return Err(ReceiverError::LeaseExpired);
            }
            if new_deadline <= current_deadline {
                tx.rollback()?;
                return Err(ReceiverError::RenewalNoExtension);
            }
            // Replay check before capacity so a known nonce is never
            // re-accepted under exhaustion.
            let existing: Option<String> = tx
                .query_row(
                    "SELECT nonce_hex FROM consumed_nonces WHERE nonce_hex = ?1",
                    params![params.fresh_nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }
            // Same fail-closed bounded-state policy as consume_and_lease.
            let consumed_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM consumed_nonces", [], |r| r.get(0))?;
            if consumed_count >= self.max_consumed {
                tx.rollback()?;
                return Err(ReceiverError::CapacityExhausted);
            }
            let changed = tx.execute(
                "INSERT INTO consumed_nonces (nonce_hex, consumed_at_ms, intent_id) VALUES (?1, ?2, ?3)",
                params![
                    params.fresh_nonce_hex,
                    u64_to_i64(params.current_mono_ms)?,
                    params.intent_id
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::NonceAlreadyConsumed);
            }
            let changed = tx.execute(
                "UPDATE active_leases SET lease_deadline_mono_ms = ?1, nonce_hex = ?2, signed_expires_at_ms = ?3
                 WHERE intent_id = ?4 AND state = ?5",
                params![
                    u64_to_i64(new_deadline)?,
                    params.fresh_nonce_hex,
                    u64_to_i64(params.fresh_signed_expires_at_ms)?,
                    params.intent_id,
                    LeaseState::Active.as_str()
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::LeaseNotActive);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, ReceiverError::Db(ref de) if is_nonce_unique_violation(de)) {
                return ReceiverError::NonceAlreadyConsumed;
            }
            self.map_fault(e)
        })
    }

    // ---- Durable control claims (exactly one controller) ----

    /// Atomically reserve the controller slot for an endpoint.
    /// A non-released claim (Reserved, Active, or PendingRelease) on the
    /// same endpoint conflicts. The partial unique index is the race
    /// backstop; the pre-check gives a typed conflict without relying on
    /// SQLite error strings.
    pub fn reserve_controller(
        &mut self,
        intent_id: &str,
        endpoint_key: &[u8; 32],
        generation: u64,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        self.ensure_open()?;
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT intent_id FROM control_claims
                     WHERE endpoint_key = ?1 AND state != ?2 LIMIT 1",
                    params![endpoint_key.as_slice(), ClaimState::Released.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                tx.rollback()?;
                return Err(ReceiverError::ControllerConflict);
            }
            let changed = tx.execute(
                "INSERT INTO control_claims (intent_id, endpoint_key, generation, state, claimed_at_mono_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    intent_id,
                    endpoint_key.as_slice(),
                    u64_to_i64(generation)?,
                    ClaimState::Reserved.as_str(),
                    u64_to_i64(current_mono_ms)?,
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(ReceiverError::ConfigCorrupt);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, ReceiverError::Db(ref de) if is_controller_unique_violation(de)) {
                return ReceiverError::ControllerConflict;
            }
            self.map_fault(e)
        })
    }

    /// Acknowledge a reserved controller claim, making it Active.
    pub fn acknowledge_controller(&mut self, intent_id: &str) -> Result<(), ReceiverError> {
        self.ensure_open()?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE control_claims SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    ClaimState::Active.as_str(),
                    intent_id,
                    ClaimState::Reserved.as_str()
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Err(ReceiverError::ControllerNotFound);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Abandon a Reserved controller claim (failed admit rollback).
    /// Frees the controller slot without granting authority.
    pub fn abandon_controller(&mut self, intent_id: &str) -> Result<(), ReceiverError> {
        // Stop cleanup: allowed even when latched.
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE control_claims SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    ClaimState::Released.as_str(),
                    intent_id,
                    ClaimState::Reserved.as_str()
                ],
            )?;
            tx.commit()?;
            Ok(())
        })();
        result
    }

    /// Request release of an Active controller claim (PendingRelease).
    /// Stop cleanup remains possible without audit persistence.
    pub fn request_controller_release(
        &mut self,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE control_claims SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    ClaimState::PendingRelease.as_str(),
                    intent_id,
                    ClaimState::Active.as_str()
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Err(ReceiverError::ControllerNotFound);
            }
            tx.commit()?;
            Ok(())
        })();
        result
    }

    /// Confirm controller release. Frees the controller slot.
    /// Stop cleanup remains possible without audit persistence.
    pub fn confirm_controller_release(
        &mut self,
        intent_id: &str,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<(), ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE control_claims SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![
                    ClaimState::Released.as_str(),
                    intent_id,
                    ClaimState::PendingRelease.as_str()
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Err(ReceiverError::ControllerNotFound);
            }
            tx.commit()?;
            Ok(())
        })();
        result
    }

    /// Generation-bound stop of control claims. Higher generations unaffected.
    /// Stop cleanup remains possible without audit persistence.
    pub fn stop_controller_generation(
        &mut self,
        endpoint_key: &[u8; 32],
        generation: u64,
        current_mono_ms: u64,
    ) -> Result<usize, ReceiverError> {
        self.check_monotonic(current_mono_ms)?;
        let result = (|| -> Result<usize, ReceiverError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let stopped = tx.execute(
                "UPDATE control_claims SET state = ?1
                 WHERE endpoint_key = ?2 AND generation = ?3 AND state != ?1",
                params![
                    ClaimState::Released.as_str(),
                    endpoint_key.as_slice(),
                    u64_to_i64(generation)?,
                ],
            )?;
            tx.commit()?;
            Ok(stopped)
        })();
        result
    }

    /// Current controller claim state for an intent, if any.
    /// Readable even when latched so stop cleanup can observe state.
    pub fn get_controller_claim(
        &mut self,
        intent_id: &str,
    ) -> Result<Option<(ClaimState, u64)>, ReceiverError> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT state, generation FROM control_claims WHERE intent_id = ?1",
                params![intent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((state_str, gen)) => {
                let state =
                    ClaimState::parse_state(&state_str).ok_or(ReceiverError::ConfigCorrupt)?;
                Ok(Some((state, i64_to_u64(gen)?)))
            }
        }
    }

    /// Count non-released controller claims for an endpoint.
    pub fn active_controller_claims(
        &mut self,
        endpoint_key: &[u8; 32],
    ) -> Result<usize, ReceiverError> {
        self.ensure_open()?;
        let result = (|| -> Result<usize, ReceiverError> {
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM control_claims WHERE endpoint_key = ?1 AND state != ?2",
                params![endpoint_key.as_slice(), ClaimState::Released.as_str()],
                |r| r.get(0),
            )?;
            Ok(count as usize)
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Check wall-clock for signed-validity use. Backward movement latches.
    pub fn check_wall_clock(&mut self, now_ms: u64) -> Result<(), ReceiverError> {
        if let Some(last) = self.last_wall_ms {
            if now_ms < last {
                self.latch_fault(&format!("wall clock rollback: last={last} now={now_ms}"));
                return Err(ReceiverError::ClockFault(format!(
                    "wall clock rollback: last={last} now={now_ms}"
                )));
            }
        }
        self.last_wall_ms = Some(now_ms);
        Ok(())
    }
}

fn now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_create_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv.db");
        let s = ReceiverLeaseStore::create(&path, 0).unwrap();
        assert!(!s.is_latched());
        drop(s);
        let s2 = ReceiverLeaseStore::open(&path, 0).unwrap();
        assert!(!s2.is_latched());
    }

    #[test]
    fn receiver_create_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("excl.db");
        assert!(ReceiverLeaseStore::create(&path, 0).is_ok());
        assert!(matches!(
            ReceiverLeaseStore::create(&path, 0),
            Err(ReceiverError::AlreadyExists)
        ));
    }

    #[test]
    fn receiver_open_missing_denies() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            ReceiverLeaseStore::open(&dir.path().join("nope.db"), 0),
            Err(ReceiverError::NotFound)
        ));
    }

    #[test]
    fn receiver_initialize_and_consume() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "intent-1",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();
        assert!(s.is_nonce_consumed(&hex::encode([1u8; 32])).unwrap());
        assert!(s.is_lease_active("intent-1", 100).unwrap());
        assert!(!s.is_lease_active("intent-1", 30_001).unwrap()); // past deadline
    }

    #[test]
    fn receiver_nonce_uniqueness() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "intent-1",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();
        // Same nonce different intent → conflict
        assert!(matches!(
            s.consume_and_lease(ConsumeLeaseParams {
                intent_id: "intent-2",
                nonce_hex: &hex::encode([1u8; 32]),
                endpoint_key: &[0xDDu8; 32],
                boot_id: "boot-1",
                worker_id: "worker-1",
                operation: "observe",
                operation_intent: "view-stream",
                desktop_generation: 3,
                display_generation: 2,
                approved_manager_key: &[0xAAu8; 32],
                approved_account_key: &[0xBBu8; 32],
                signed_expires_at_ms: 100_000,
                lease_deadline_mono_ms: 30_000,
                current_mono_ms: 100,
            }),
            Err(ReceiverError::NonceAlreadyConsumed)
        ));
    }

    #[test]
    fn receiver_monotonic_rollback_latches() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.check_monotonic(100).unwrap();
        assert!(matches!(
            s.check_monotonic(99),
            Err(ReceiverError::ClockFault(_))
        ));
        assert!(s.is_latched());
    }

    #[test]
    fn receiver_release_lifecycle() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "intent-1",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();

        s.request_release("intent-1", 200).unwrap();
        let lease = s.get_lease("intent-1").unwrap().unwrap();
        assert_eq!(lease.state, LeaseState::PendingRelease);

        s.confirm_release("intent-1", 300).unwrap();
        let lease = s.get_lease("intent-1").unwrap().unwrap();
        assert_eq!(lease.state, LeaseState::Released);
    }

    #[test]
    fn receiver_capacity_exhaustion() {
        let mut s = ReceiverLeaseStore::create_memory_with_limits(0, 1, 1).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "intent-1",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();
        // Nonce capacity exhausted
        assert!(matches!(
            s.consume_and_lease(ConsumeLeaseParams {
                intent_id: "intent-2",
                nonce_hex: &hex::encode([2u8; 32]),
                endpoint_key: &[0xDDu8; 32],
                boot_id: "boot-1",
                worker_id: "worker-1",
                operation: "observe",
                operation_intent: "view-stream",
                desktop_generation: 3,
                display_generation: 2,
                approved_manager_key: &[0xAAu8; 32],
                approved_account_key: &[0xBBu8; 32],
                signed_expires_at_ms: 100_000,
                lease_deadline_mono_ms: 30_000,
                current_mono_ms: 200,
            }),
            Err(ReceiverError::CapacityExhausted)
        ));
    }

    #[test]
    fn receiver_file_reopen_preserves_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.db");
        {
            let mut s = ReceiverLeaseStore::create(&path, 0).unwrap();
            s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
            s.consume_and_lease(ConsumeLeaseParams {
                intent_id: "intent-1",
                nonce_hex: &hex::encode([1u8; 32]),
                endpoint_key: &[0xDDu8; 32],
                boot_id: "boot-1",
                worker_id: "worker-1",
                operation: "observe",
                operation_intent: "view-stream",
                desktop_generation: 3,
                display_generation: 2,
                approved_manager_key: &[0xAAu8; 32],
                approved_account_key: &[0xBBu8; 32],
                signed_expires_at_ms: 100_000,
                lease_deadline_mono_ms: 30_000,
                current_mono_ms: 100,
            })
            .unwrap();
        }
        let mut s2 = ReceiverLeaseStore::open(&path, 0).unwrap();
        assert!(s2.is_nonce_consumed(&hex::encode([1u8; 32])).unwrap());
    }

    #[test]
    fn crate_private_renew_clamps_to_fixed_max_and_rejects_duplicate_nonce() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "renew-unit",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 10_000,
            current_mono_ms: 100,
        })
        .unwrap();
        let fresh = hex::encode([9u8; 32]);
        // Caller cannot grow authority: deadline clamped to FIXED_MAX_LEASE_MS.
        s.renew_lease(RenewLeaseParams {
            intent_id: "renew-unit",
            fresh_nonce_hex: &fresh,
            fresh_signed_expires_at_ms: 1_000_000,
            now_wall_ms: 1_000,
            current_mono_ms: 200,
        })
        .unwrap();
        let lease = s.get_lease("renew-unit").unwrap().unwrap();
        assert_eq!(
            lease.lease_deadline_mono_ms,
            200 + FIXED_MAX_LEASE_MS,
            "must clamp to the fixed 30s maximum, not a caller cap"
        );
        // Duplicate nonce cannot extend.
        assert!(matches!(
            s.renew_lease(RenewLeaseParams {
                intent_id: "renew-unit",
                fresh_nonce_hex: &fresh,
                fresh_signed_expires_at_ms: 1_000_000,
                now_wall_ms: 1_100,
                current_mono_ms: 300,
            }),
            Err(ReceiverError::NonceAlreadyConsumed)
        ));
    }

    #[test]
    fn format_version_mismatch_is_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old-format.db");
        {
            let mut s = ReceiverLeaseStore::create(&path, 0).unwrap();
            s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
            // Simulate an older schema stamp.
            s.conn
                .execute(
                    "UPDATE receiver_config SET format_version = 1 WHERE id = 1",
                    [],
                )
                .unwrap();
        }
        match ReceiverLeaseStore::open(&path, 0) {
            Err(ReceiverError::FormatVersionMismatch { found: 1, expected }) => {
                assert_eq!(expected, RECEIVER_FORMAT_VERSION);
            }
            Err(e) => panic!("old format must be rejected explicitly: {e}"),
            Ok(_) => panic!("old format must not open as current"),
        }
    }

    #[test]
    fn crate_private_renew_denies_at_and_after_deadline_without_nonce_commit() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "exp-renew",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 5_000,
            current_mono_ms: 100,
        })
        .unwrap();
        let fresh = hex::encode([9u8; 32]);
        // Exact boundary denies.
        assert!(matches!(
            s.renew_lease(RenewLeaseParams {
                intent_id: "exp-renew",
                fresh_nonce_hex: &fresh,
                fresh_signed_expires_at_ms: 1_000_000,
                now_wall_ms: 1_000,
                current_mono_ms: 5_000,
            }),
            Err(ReceiverError::LeaseExpired)
        ));
        // After deadline denies.
        assert!(matches!(
            s.renew_lease(RenewLeaseParams {
                intent_id: "exp-renew",
                fresh_nonce_hex: &hex::encode([8u8; 32]),
                fresh_signed_expires_at_ms: 1_000_000,
                now_wall_ms: 1_000,
                current_mono_ms: 5_001,
            }),
            Err(ReceiverError::LeaseExpired)
        ));
        // No fresh nonce committed on denial.
        assert!(!s.is_nonce_consumed(&fresh).unwrap());
        assert!(!s.is_nonce_consumed(&hex::encode([8u8; 32])).unwrap());
    }

    #[test]
    fn crate_private_renew_enforces_nonce_capacity() {
        let mut s = ReceiverLeaseStore::create_memory_with_limits(0, 1, 10).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.consume_and_lease(ConsumeLeaseParams {
            intent_id: "cap-renew",
            nonce_hex: &hex::encode([1u8; 32]),
            endpoint_key: &[0xDDu8; 32],
            boot_id: "boot-1",
            worker_id: "worker-1",
            operation: "observe",
            operation_intent: "view-stream",
            desktop_generation: 3,
            display_generation: 2,
            approved_manager_key: &[0xAAu8; 32],
            approved_account_key: &[0xBBu8; 32],
            signed_expires_at_ms: 100_000,
            lease_deadline_mono_ms: 10_000,
            current_mono_ms: 100,
        })
        .unwrap();
        // max_consumed = 1 already filled by the initial nonce.
        let fresh = hex::encode([9u8; 32]);
        assert!(matches!(
            s.renew_lease(RenewLeaseParams {
                intent_id: "cap-renew",
                fresh_nonce_hex: &fresh,
                fresh_signed_expires_at_ms: 1_000_000,
                now_wall_ms: 1_000,
                current_mono_ms: 200,
            }),
            Err(ReceiverError::CapacityExhausted)
        ));
        assert!(
            !s.is_nonce_consumed(&fresh).unwrap(),
            "no commit on capacity deny"
        );
    }

    #[test]
    fn acknowledge_requires_reserved_and_abandon_frees_slot() {
        let mut s = ReceiverLeaseStore::create_memory(0).unwrap();
        s.initialize(&[0xAAu8; 32], 1, &[0xDDu8; 32]).unwrap();
        s.reserve_controller("ack", &[0xDDu8; 32], 1, 100).unwrap();
        // Acknowledge while Reserved succeeds.
        s.acknowledge_controller("ack").unwrap();
        // Second acknowledge (not Reserved) fails — admit must deny, not Grant.
        assert!(matches!(
            s.acknowledge_controller("ack"),
            Err(ReceiverError::ControllerNotFound)
        ));
        // Abandon of a Reserved claim frees the slot (failed-admit cleanup).
        s.reserve_controller("abandon-me", &[0xEEu8; 32], 1, 200)
            .unwrap();
        s.abandon_controller("abandon-me").unwrap();
        s.reserve_controller("after-abandon", &[0xEEu8; 32], 1, 300)
            .unwrap();
    }
}
