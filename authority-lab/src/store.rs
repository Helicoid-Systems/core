//! Durable SQLite store for admission records.
//!
//! Design constraints:
//! - Exclusive fresh creation (`create`) is separate from existing open (`open`).
//!   Open never mutates schema and never heals/reinitializes missing state.
//! - Explicit one-time trust initialization on a fresh store only.
//! - Mandatory healthy fault record (`latched = 0`); missing/corrupt denies.
//! - Issuance and receiver consumption validate binding/epoch/fault/issued
//!   hash+intent inside the SAME `IMMEDIATE` transaction.
//! - Required read/write/commit/lock failures latch in-memory and durably.
//! - No recovery API and no production migration/recovery path.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Hard default cap on issued credential rows (fail closed; never prune
/// unexpired replay records to make room).
pub const DEFAULT_MAX_ISSUED: i64 = 10_000;

/// Hard default cap on receiver nonce-claim rows.
pub const DEFAULT_MAX_CLAIMED: i64 = 10_000;

/// Store format version written at initialization.
pub const STORE_FORMAT_VERSION: i64 = 1;

/// Capacity limits for one store. Zero is allowed in tests to prove
/// exhaustion fail-closed behaviour.
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    pub max_issued: i64,
    pub max_claimed: i64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_issued: DEFAULT_MAX_ISSUED,
            max_claimed: DEFAULT_MAX_CLAIMED,
        }
    }
}

/// Persisted immutable authority binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBinding {
    pub issuer_public_key: [u8; 32],
    pub issuer_generation: u64,
    pub authority_revision: String,
    pub deployment: String,
    pub schema: String,
}

/// Full credential binding written at issuance (not just computer + times).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub intent_id: String,
    pub nonce_hex: String,
    pub body_hash_hex: String,
    pub computer_id: String,
    pub incarnation_id: String,
    pub account_id: String,
    pub manager_id: String,
    pub desktop_generation: u64,
    pub scope_ops: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub issuer_public_key: [u8; 32],
    pub issuer_generation: u64,
    pub authority_revision: String,
    pub deployment: String,
    pub schema: String,
}

/// Storage error.
#[derive(Debug, Error)]
pub enum StoreError {
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
    #[error("trust binding not initialized")]
    TrustNotInitialized,
    #[error("trust binding already initialized")]
    TrustAlreadyInitialized,
    #[error("trust binding mismatch")]
    TrustBindingMismatch,
    #[error("trust/epoch/fault state corrupt")]
    TrustStateCorrupt,
    #[error("epoch closed")]
    EpochClosed,
    #[error("nonce already claimed")]
    NonceReplayed,
    #[error("issued credential mismatch")]
    IssuedMismatch,
    #[error("intent mismatch")]
    IntentMismatch,
    #[error("credential already issued")]
    AlreadyIssued,
    #[error("capacity exhausted")]
    CapacityExhausted,
    #[error("gate latched closed: {0}")]
    GateLatched(String),
    #[error("storage fault (latched): {0}")]
    StorageFault(String),
    #[error("initialization not permitted on this handle")]
    InitNotAllowed,
}

impl StoreError {
    /// Logical/expected denials do not latch. IO/lock/commit faults do.
    pub fn is_storage_fault(&self) -> bool {
        matches!(
            self,
            StoreError::Db(_)
                | StoreError::StorageFault(_)
                | StoreError::Io(_)
                | StoreError::TimestampOverflow
                | StoreError::NegativeDbInteger
                | StoreError::TrustStateCorrupt
        )
    }
}

fn u64_to_i64(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::TimestampOverflow)
}

fn i64_to_u64(v: i64) -> Result<u64, StoreError> {
    if v < 0 {
        return Err(StoreError::NegativeDbInteger);
    }
    Ok(v as u64)
}

/// Only the `claimed_nonces.nonce_hex` unique index is an expected replay.
fn is_nonce_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, Some(msg)) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
                && msg.contains("claimed_nonces.nonce_hex")
        }
        _ => false,
    }
}

pub fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Durable store backed by concrete file (or memory) SQLite.
pub struct DurableStore {
    conn: Connection,
    path: Option<PathBuf>,
    limits: StoreLimits,
    latched: bool,
    latch_reason: String,
    /// True only on the handle returned by `create`/`create_memory`, and
    /// only until `initialize_trust` succeeds exactly once.
    may_initialize: bool,
}

impl DurableStore {
    /// Exclusive fresh creation. Fails if the path already exists.
    /// Creates schema only; trust initialization is a separate one-shot step.
    pub fn create(path: &Path) -> Result<Self, StoreError> {
        Self::create_with_limits(path, StoreLimits::default())
    }

    pub fn create_with_limits(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_file) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(StoreError::AlreadyExists)
                }
                Err(e) => return Err(StoreError::Io(e)),
            }
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            limits,
            latched: false,
            latch_reason: String::new(),
            may_initialize: true,
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    /// Open an existing store. Never mutates schema. Never heals or
    /// reinitializes missing/corrupt state — those latch closed.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_limits(path, StoreLimits::default())
    }

    pub fn open_with_limits(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        if !path.exists() {
            return Err(StoreError::NotFound);
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            limits,
            latched: false,
            latch_reason: String::new(),
            may_initialize: false,
        };
        store.configure_connection()?;
        store.validate_existing()?;
        store.refresh_fault_state()?;
        Ok(store)
    }

    /// Fresh in-memory store (still real SQLite). Use for fixtures.
    pub fn create_memory() -> Result<Self, StoreError> {
        Self::create_memory_with_limits(StoreLimits::default())
    }

    pub fn create_memory_with_limits(limits: StoreLimits) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self {
            conn,
            path: None,
            limits,
            latched: false,
            latch_reason: String::new(),
            may_initialize: true,
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    fn configure_connection(&mut self) -> Result<(), StoreError> {
        self.conn.pragma_update(None, "synchronous", "FULL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(200))?;
        Ok(())
    }

    fn create_schema(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            r#"
            CREATE TABLE store_format (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                format_version  INTEGER NOT NULL,
                initialized     INTEGER NOT NULL CHECK (initialized IN (0, 1)),
                created_at_ms   INTEGER NOT NULL
            );

            CREATE TABLE trust_binding (
                id                   INTEGER PRIMARY KEY CHECK (id = 1),
                issuer_public_key    BLOB NOT NULL,
                issuer_generation    INTEGER NOT NULL,
                authority_revision   TEXT NOT NULL,
                deployment           TEXT NOT NULL,
                schema_version       TEXT NOT NULL
            );

            CREATE TABLE epoch_state (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                closed       INTEGER NOT NULL CHECK (closed IN (0, 1)),
                closed_at    INTEGER,
                close_reason TEXT
            );

            CREATE TABLE issued_credentials (
                intent_id          TEXT PRIMARY KEY,
                nonce_hex          TEXT NOT NULL UNIQUE,
                body_hash_hex      TEXT NOT NULL,
                computer_id        TEXT NOT NULL,
                incarnation_id     TEXT NOT NULL,
                account_id         TEXT NOT NULL,
                manager_id         TEXT NOT NULL,
                desktop_generation INTEGER NOT NULL,
                scope_ops          TEXT NOT NULL,
                issued_at_ms       INTEGER NOT NULL,
                expires_at_ms      INTEGER NOT NULL,
                issuer_public_key  BLOB NOT NULL,
                issuer_generation  INTEGER NOT NULL,
                authority_revision TEXT NOT NULL,
                deployment         TEXT NOT NULL,
                schema_version     TEXT NOT NULL
            );

            CREATE TABLE claimed_nonces (
                nonce_hex     TEXT PRIMARY KEY,
                claimed_at_ms INTEGER NOT NULL,
                intent_id     TEXT NOT NULL
            );

            CREATE TABLE fault_state (
                id         INTEGER PRIMARY KEY CHECK (id = 1),
                latched    INTEGER NOT NULL CHECK (latched IN (0, 1)),
                reason     TEXT NOT NULL,
                latched_at INTEGER NOT NULL
            );
            "#,
        )?;
        // Uninitialized format marker + mandatory healthy fault record.
        let now = now_i64();
        tx.execute(
            "INSERT INTO store_format (id, format_version, initialized, created_at_ms) VALUES (1, ?1, 0, ?2)",
            params![STORE_FORMAT_VERSION, now],
        )?;
        tx.execute(
            "INSERT INTO fault_state (id, latched, reason, latched_at) VALUES (1, 0, 'healthy', ?1)",
            params![now],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn required_tables_present(conn: &Connection) -> Result<bool, StoreError> {
        let names = [
            "store_format",
            "trust_binding",
            "epoch_state",
            "issued_credentials",
            "claimed_nonces",
            "fault_state",
        ];
        for name in names {
            let found: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![name],
                    |_| Ok(1),
                )
                .optional()?;
            if found.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Validate an existing database without schema mutation or healing.
    fn validate_existing(&mut self) -> Result<(), StoreError> {
        let result = (|| -> Result<(), StoreError> {
            if !Self::required_tables_present(&self.conn)? {
                return Err(StoreError::TrustStateCorrupt);
            }
            let fmt: Option<(i64, i64)> = self
                .conn
                .query_row(
                    "SELECT format_version, initialized FROM store_format WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match fmt {
                None => return Err(StoreError::TrustStateCorrupt),
                Some((ver, initialized)) => {
                    if ver != STORE_FORMAT_VERSION || !(initialized == 0 || initialized == 1) {
                        return Err(StoreError::TrustStateCorrupt);
                    }
                    if initialized == 1 {
                        // Initialized stores must have complete required state.
                        self.read_trust_row_txless()?
                            .ok_or(StoreError::TrustStateCorrupt)?;
                        self.epoch_closed_txless()?;
                        self.read_fault_row_txless()?;
                    }
                }
            }
            Ok(())
        })();
        result.inspect_err(|e| {
            let msg = e.to_string();
            self.latch_fault(msg);
        })
    }

    fn sidecar_path(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| {
            let mut os = p.as_os_str().to_owned();
            os.push(".fault");
            PathBuf::from(os)
        })
    }

    /// Durable sidecar write: file sync + parent directory sync where supported.
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

    /// Latch the gate closed. Durable DB row first (FULL sync), else synced
    /// sidecar. Never resets. Sidecar presence always latches even if the DB
    /// row later claims healthy.
    pub fn latch_fault(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.latched = true;
        if self.latch_reason.is_empty() {
            self.latch_reason = reason.clone();
        }
        let now = now_i64();
        let db_ok = self
            .conn
            .execute(
                "INSERT OR REPLACE INTO fault_state (id, latched, reason, latched_at) VALUES (1, 1, ?1, ?2)",
                params![reason, now],
            )
            .is_ok();
        if !db_ok {
            let _ = self.write_durable_sidecar(&reason);
        } else {
            // Belt-and-braces: sidecar too, so a later healthy DB row cannot
            // hide a fault if only the row were rewritten without a recovery API.
            let _ = self.write_durable_sidecar(&reason);
        }
    }

    /// Re-read durable fault state so other already-open handles observe
    /// latches written by a different handle.
    pub fn refresh_fault_state(&mut self) -> Result<(), StoreError> {
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
                Err(e) => return Err(self.map_fault(StoreError::Io(e))),
            }
        }
        let result = (|| -> Result<(), StoreError> {
            if !Self::required_tables_present(&self.conn)? {
                return Err(StoreError::TrustStateCorrupt);
            }
            match self.read_fault_row_txless()? {
                Some(0) => Ok(()),
                Some(1) => Err(StoreError::GateLatched("fault_state latched=1".into())),
                _ => Err(StoreError::TrustStateCorrupt),
            }
        })();
        match result {
            Ok(()) => Ok(()),
            Err(StoreError::GateLatched(reason)) => {
                self.latched = true;
                if self.latch_reason.is_empty() {
                    self.latch_reason = reason;
                }
                Ok(())
            }
            // Required reads must use the same durable fault path as writes.
            // A transient read failure cannot silently heal after restart.
            Err(e) => Err(self.map_fault(e)),
        }
    }

    fn read_fault_row_txless(&self) -> Result<Option<i64>, StoreError> {
        let row: Option<i64> = self
            .conn
            .query_row("SELECT latched FROM fault_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(row)
    }

    pub fn is_latched(&self) -> bool {
        self.latched
    }

    pub fn latch_reason(&self) -> &str {
        &self.latch_reason
    }

    fn ensure_open(&mut self) -> Result<(), StoreError> {
        self.refresh_fault_state()?;
        if self.latched {
            return Err(StoreError::GateLatched(self.latch_reason.clone()));
        }
        Ok(())
    }

    fn map_fault(&mut self, err: StoreError) -> StoreError {
        if err.is_storage_fault() {
            let msg = err.to_string();
            self.latch_fault(msg);
            if matches!(err, StoreError::Db(_) | StoreError::Io(_)) {
                return StoreError::StorageFault(self.latch_reason.clone());
            }
        }
        err
    }

    fn read_trust_row_txless(&self) -> Result<Option<TrustBinding>, StoreError> {
        let row: Option<(Vec<u8>, i64, String, String, String)> = self
            .conn
            .query_row(
                "SELECT issuer_public_key, issuer_generation, authority_revision, deployment, schema_version FROM trust_binding WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((key, gen, rev, dep, schema)) => {
                if key.len() != 32 {
                    return Err(StoreError::TrustStateCorrupt);
                }
                let generation = i64_to_u64(gen)?;
                if generation == 0 {
                    return Err(StoreError::TrustStateCorrupt);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&key);
                Ok(Some(TrustBinding {
                    issuer_public_key: pk,
                    issuer_generation: generation,
                    authority_revision: rev,
                    deployment: dep,
                    schema,
                }))
            }
        }
    }

    fn epoch_closed_txless(&self) -> Result<bool, StoreError> {
        let row: Option<i64> = self
            .conn
            .query_row("SELECT closed FROM epoch_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match row {
            None => Err(StoreError::TrustStateCorrupt),
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(StoreError::TrustStateCorrupt),
        }
    }

    fn fault_in_tx(tx: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
        let row: Option<i64> = tx
            .query_row("SELECT latched FROM fault_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match row {
            Some(0) => Ok(()),
            Some(1) => Err(StoreError::GateLatched("fault_state latched=1".into())),
            Some(_) => Err(StoreError::TrustStateCorrupt),
            None => Err(StoreError::TrustStateCorrupt),
        }
    }

    fn trust_in_tx(tx: &rusqlite::Transaction<'_>) -> Result<TrustBinding, StoreError> {
        let row: Option<(Vec<u8>, i64, String, String, String)> = tx
            .query_row(
                "SELECT issuer_public_key, issuer_generation, authority_revision, deployment, schema_version FROM trust_binding WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let format: Option<(i64, i64)> = tx
            .query_row(
                "SELECT format_version, initialized FROM store_format WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match format {
            Some((STORE_FORMAT_VERSION, 1)) => {}
            Some((STORE_FORMAT_VERSION, 0)) if row.is_none() => {
                return Err(StoreError::TrustNotInitialized)
            }
            _ => return Err(StoreError::TrustStateCorrupt),
        }
        let row = row.ok_or(StoreError::TrustStateCorrupt)?;
        if row.0.len() != 32 {
            return Err(StoreError::TrustStateCorrupt);
        }
        let generation = i64_to_u64(row.1)?;
        if generation == 0 {
            return Err(StoreError::TrustStateCorrupt);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&row.0);
        Ok(TrustBinding {
            issuer_public_key: pk,
            issuer_generation: generation,
            authority_revision: row.2,
            deployment: row.3,
            schema: row.4,
        })
    }

    fn epoch_in_tx(tx: &rusqlite::Transaction<'_>) -> Result<bool, StoreError> {
        let row: Option<i64> = tx
            .query_row("SELECT closed FROM epoch_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match row {
            None => Err(StoreError::TrustStateCorrupt),
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(StoreError::TrustStateCorrupt),
        }
    }

    /// One-shot initialization on a fresh `create` handle only.
    /// Immutable binding + open epoch + healthy fault + format metadata
    /// under one IMMEDIATE transaction.
    pub fn initialize_trust(&mut self, binding: &TrustBinding) -> Result<(), StoreError> {
        self.ensure_open()?;
        if !self.may_initialize {
            return Err(StoreError::InitNotAllowed);
        }
        if binding.issuer_generation == 0 {
            return Err(StoreError::TrustBindingMismatch);
        }
        let result = (|| -> Result<(), StoreError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            Self::fault_in_tx(&tx)?;

            let fmt: Option<i64> = tx
                .query_row(
                    "SELECT initialized FROM store_format WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let initialized = fmt.ok_or(StoreError::TrustStateCorrupt)?;
            if initialized == 1 {
                // Same binding is a no-op only when all required state is valid.
                let existing = {
                    let row: Option<(Vec<u8>, i64, String, String, String)> = tx
                        .query_row(
                            "SELECT issuer_public_key, issuer_generation, authority_revision, deployment, schema_version FROM trust_binding WHERE id = 1",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                        )
                        .optional()?;
                    row.ok_or(StoreError::TrustStateCorrupt)?
                };
                if existing.0.as_slice() != binding.issuer_public_key.as_slice()
                    || i64_to_u64(existing.1)? != binding.issuer_generation
                    || existing.2 != binding.authority_revision
                    || existing.3 != binding.deployment
                    || existing.4 != binding.schema
                {
                    tx.rollback()?;
                    return Err(StoreError::TrustBindingMismatch);
                }
                tx.rollback()?;
                return Ok(());
            }
            if initialized != 0 {
                tx.rollback()?;
                return Err(StoreError::TrustStateCorrupt);
            }

            // Must not already have a binding/epoch on an uninitialized format.
            let has_trust: Option<i64> = tx
                .query_row("SELECT 1 FROM trust_binding WHERE id = 1", [], |_| Ok(1))
                .optional()?;
            if has_trust.is_some() {
                tx.rollback()?;
                return Err(StoreError::TrustStateCorrupt);
            }

            let now = now_i64();
            tx.execute(
                "INSERT INTO trust_binding (id, issuer_public_key, issuer_generation, authority_revision, deployment, schema_version) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    binding.issuer_public_key.as_slice(),
                    u64_to_i64(binding.issuer_generation)?,
                    binding.authority_revision,
                    binding.deployment,
                    binding.schema
                ],
            )?;
            tx.execute(
                "INSERT INTO epoch_state (id, closed, closed_at, close_reason) VALUES (1, 0, NULL, NULL)",
                [],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO fault_state (id, latched, reason, latched_at) VALUES (1, 0, 'healthy', ?1)",
                params![now],
            )?;
            tx.execute("UPDATE store_format SET initialized = 1 WHERE id = 1", [])?;
            tx.commit()?;
            // Keep may_initialize on the fresh handle so a same-binding
            // re-init is a validated no-op; the one-shot is format.initialized.
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Load the persisted binding. `Ok(None)` only if format is uninitialized.
    pub fn trust_binding(&mut self) -> Result<Option<TrustBinding>, StoreError> {
        self.ensure_open()?;
        self.read_trust_row_txless().map_err(|e| self.map_fault(e))
    }

    pub fn is_epoch_closed(&mut self) -> Result<bool, StoreError> {
        self.ensure_open()?;
        self.epoch_closed_txless().map_err(|e| self.map_fault(e))
    }

    /// One-way close. Atomic against issue/consume via IMMEDIATE.
    pub fn close_epoch(&mut self, reason: &str) -> Result<(), StoreError> {
        self.ensure_open()?;
        let result = (|| -> Result<(), StoreError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            Self::fault_in_tx(&tx)?;
            Self::trust_in_tx(&tx)?;
            let now = now_i64();
            let changed = tx.execute(
                "UPDATE epoch_state SET closed = 1, closed_at = ?1, close_reason = ?2 WHERE id = 1 AND closed = 0",
                params![now, reason],
            )?;
            if changed == 0 {
                match Self::epoch_in_tx(&tx)? {
                    true => {
                        tx.commit()?;
                        return Ok(());
                    }
                    false => {
                        tx.rollback()?;
                        return Err(StoreError::TrustStateCorrupt);
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Atomic issuance commit. All binding/epoch/fault/capacity checks are
    /// inside this IMMEDIATE transaction. Crate-private: public issuance goes
    /// through the controller commit seam only.
    pub(crate) fn commit_issuance(&mut self, cred: &IssuedCredential) -> Result<(), StoreError> {
        self.ensure_open()?;
        let result = (|| -> Result<(), StoreError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            Self::fault_in_tx(&tx)?;
            let trust = Self::trust_in_tx(&tx)?;
            if trust.issuer_public_key != cred.issuer_public_key
                || trust.issuer_generation != cred.issuer_generation
                || trust.authority_revision != cred.authority_revision
                || trust.deployment != cred.deployment
                || trust.schema != cred.schema
            {
                tx.rollback()?;
                return Err(StoreError::TrustBindingMismatch);
            }
            if Self::epoch_in_tx(&tx)? {
                tx.rollback()?;
                return Err(StoreError::EpochClosed);
            }

            let issued_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM issued_credentials", [], |r| r.get(0))?;
            if issued_count < 0 {
                tx.rollback()?;
                return Err(StoreError::TrustStateCorrupt);
            }
            if issued_count >= self.limits.max_issued {
                tx.rollback()?;
                return Err(StoreError::CapacityExhausted);
            }

            // Reject non-positive / non-fitting integer bindings before write.
            let _ = u64_to_i64(cred.desktop_generation)?;
            let _ = u64_to_i64(cred.issued_at_ms)?;
            let _ = u64_to_i64(cred.expires_at_ms)?;
            let _ = u64_to_i64(cred.issuer_generation)?;

            let changed = tx.execute(
                "INSERT INTO issued_credentials (
                    intent_id, nonce_hex, body_hash_hex, computer_id, incarnation_id,
                    account_id, manager_id, desktop_generation, scope_ops,
                    issued_at_ms, expires_at_ms, issuer_public_key, issuer_generation,
                    authority_revision, deployment, schema_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    cred.intent_id,
                    cred.nonce_hex,
                    cred.body_hash_hex,
                    cred.computer_id,
                    cred.incarnation_id,
                    cred.account_id,
                    cred.manager_id,
                    u64_to_i64(cred.desktop_generation)?,
                    cred.scope_ops,
                    u64_to_i64(cred.issued_at_ms)?,
                    u64_to_i64(cred.expires_at_ms)?,
                    cred.issuer_public_key.as_slice(),
                    u64_to_i64(cred.issuer_generation)?,
                    cred.authority_revision,
                    cred.deployment,
                    cred.schema,
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(StoreError::AlreadyIssued);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Atomic receiver consumption. Compares the exact expected full issued
    /// credential (hash, nonce, intent, identity, authority) and trusted
    /// binding inside the same IMMEDIATE transaction as the unique claim.
    pub(crate) fn claim_nonce(
        &mut self,
        expected: &IssuedCredential,
        claimed_at_ms: u64,
    ) -> Result<(), StoreError> {
        self.ensure_open()?;
        let result = (|| -> Result<(), StoreError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            Self::fault_in_tx(&tx)?;
            let trust = Self::trust_in_tx(&tx)?;
            if trust.issuer_public_key != expected.issuer_public_key
                || trust.issuer_generation != expected.issuer_generation
                || trust.authority_revision != expected.authority_revision
                || trust.deployment != expected.deployment
                || trust.schema != expected.schema
            {
                tx.rollback()?;
                return Err(StoreError::TrustBindingMismatch);
            }
            if Self::epoch_in_tx(&tx)? {
                tx.rollback()?;
                return Err(StoreError::EpochClosed);
            }

            type IssuedRow = (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                i64,
                String,
                i64,
                i64,
                Vec<u8>,
                i64,
                String,
                String,
                String,
            );
            let row: Option<IssuedRow> = tx
                .query_row(
                    "SELECT intent_id, nonce_hex, body_hash_hex, computer_id, incarnation_id,
                            account_id, manager_id, desktop_generation, scope_ops,
                            issued_at_ms, expires_at_ms, issuer_public_key, issuer_generation,
                            authority_revision, deployment, schema_version
                     FROM issued_credentials WHERE nonce_hex = ?1",
                    params![expected.nonce_hex],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                            r.get(10)?,
                            r.get(11)?,
                            r.get(12)?,
                            r.get(13)?,
                            r.get(14)?,
                            r.get(15)?,
                        ))
                    },
                )
                .optional()?;
            let Some(row) = row else {
                tx.rollback()?;
                return Err(StoreError::NonceReplayed);
            };

            // Exact full binding / hash / nonce / intent comparison.
            let (
                intent_id,
                nonce_hex,
                body_hash_hex,
                computer_id,
                incarnation_id,
                account_id,
                manager_id,
                desktop_generation,
                scope_ops,
                issued_at_ms,
                expires_at_ms,
                issuer_public_key,
                issuer_generation,
                authority_revision,
                deployment,
                schema,
            ) = row;

            if intent_id != expected.intent_id {
                tx.rollback()?;
                return Err(StoreError::IntentMismatch);
            }
            if nonce_hex != expected.nonce_hex
                || body_hash_hex != expected.body_hash_hex
                || computer_id != expected.computer_id
                || incarnation_id != expected.incarnation_id
                || account_id != expected.account_id
                || manager_id != expected.manager_id
                || scope_ops != expected.scope_ops
                || authority_revision != expected.authority_revision
                || deployment != expected.deployment
                || schema != expected.schema
            {
                tx.rollback()?;
                return Err(StoreError::IssuedMismatch);
            }
            if i64_to_u64(desktop_generation)? != expected.desktop_generation
                || i64_to_u64(issued_at_ms)? != expected.issued_at_ms
                || i64_to_u64(expires_at_ms)? != expected.expires_at_ms
                || i64_to_u64(issuer_generation)? != expected.issuer_generation
                || issuer_public_key.as_slice() != expected.issuer_public_key.as_slice()
            {
                tx.rollback()?;
                return Err(StoreError::IssuedMismatch);
            }

            let claimed_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM claimed_nonces", [], |r| r.get(0))?;
            if claimed_count < 0 {
                tx.rollback()?;
                return Err(StoreError::TrustStateCorrupt);
            }
            if claimed_count >= self.limits.max_claimed {
                tx.rollback()?;
                return Err(StoreError::CapacityExhausted);
            }

            let changed = tx.execute(
                "INSERT INTO claimed_nonces (nonce_hex, claimed_at_ms, intent_id) VALUES (?1, ?2, ?3)",
                params![expected.nonce_hex, u64_to_i64(claimed_at_ms)?, expected.intent_id],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(StoreError::NonceReplayed);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, StoreError::Db(ref de) if is_nonce_unique_violation(de)) {
                return StoreError::NonceReplayed;
            }
            self.map_fault(e)
        })
    }

    pub fn is_nonce_claimed(&mut self, nonce_hex: &str) -> Result<bool, StoreError> {
        self.ensure_open()?;
        let result = (|| -> Result<bool, StoreError> {
            let found: Option<String> = self
                .conn
                .query_row(
                    "SELECT nonce_hex FROM claimed_nonces WHERE nonce_hex = ?1",
                    params![nonce_hex],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(found.is_some())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Read-only issued-record lookup (proof/reporting). Not a write seam.
    pub fn get_issued(&mut self, intent_id: &str) -> Result<Option<IssuedCredential>, StoreError> {
        self.ensure_open()?;
        let result = (|| -> Result<Option<IssuedCredential>, StoreError> {
            let row = self
                .conn
                .query_row(
                    "SELECT intent_id, nonce_hex, body_hash_hex, computer_id, incarnation_id,
                            account_id, manager_id, desktop_generation, scope_ops,
                            issued_at_ms, expires_at_ms, issuer_public_key, issuer_generation,
                            authority_revision, deployment, schema_version
                     FROM issued_credentials WHERE intent_id = ?1",
                    params![intent_id],
                    |r| {
                        let key: Vec<u8> = r.get(11)?;
                        if key.len() != 32 {
                            return Err(rusqlite::Error::InvalidColumnType(
                                11,
                                "issuer_public_key".into(),
                                rusqlite::types::Type::Blob,
                            ));
                        }
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&key);
                        let desktop_generation: i64 = r.get(7)?;
                        let issued_at_ms: i64 = r.get(9)?;
                        let expires_at_ms: i64 = r.get(10)?;
                        let issuer_generation: i64 = r.get(12)?;
                        if desktop_generation < 0
                            || issued_at_ms < 0
                            || expires_at_ms < 0
                            || issuer_generation < 0
                        {
                            return Err(rusqlite::Error::InvalidColumnType(
                                7,
                                "negative integer".into(),
                                rusqlite::types::Type::Integer,
                            ));
                        }
                        Ok(IssuedCredential {
                            intent_id: r.get(0)?,
                            nonce_hex: r.get(1)?,
                            body_hash_hex: r.get(2)?,
                            computer_id: r.get(3)?,
                            incarnation_id: r.get(4)?,
                            account_id: r.get(5)?,
                            manager_id: r.get(6)?,
                            desktop_generation: desktop_generation as u64,
                            scope_ops: r.get(8)?,
                            issued_at_ms: issued_at_ms as u64,
                            expires_at_ms: expires_at_ms as u64,
                            issuer_public_key: pk,
                            issuer_generation: issuer_generation as u64,
                            authority_revision: r.get(13)?,
                            deployment: r.get(14)?,
                            schema: r.get(15)?,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// True when a durable fault latch (DB row or sidecar) is present.
    pub fn has_durable_fault(&self) -> bool {
        if self.latched {
            return true;
        }
        if let Some(side) = self.sidecar_path() {
            return side.exists();
        }
        false
    }
}

fn now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
