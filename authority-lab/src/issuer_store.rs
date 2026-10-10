//! Separate issuer issuance journal.
//!
//! This store is used exclusively by the issuer to record issued grants.
//! The receiver never opens this database. It tracks the issuance journal
//! with full v2 credential binding, nonce uniqueness, and fault state.
//!
//! ## Design constraints
//!
//! - Issuer writes a journal entry only after signing the grant.
//! - Nonce uniqueness prevents double-issuance.
//! - Fault latch follows the same pattern as `DurableStore`.
//! - Receiver never requires access to this store.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Issuer journal format version.
pub const ISSUER_FORMAT_VERSION: i64 = 1;

/// Hard default cap on journal entries.
pub const DEFAULT_MAX_JOURNAL: i64 = 10_000;

/// Issuer journal entry — full v2 credential binding at issuance time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub intent_id: String,
    pub nonce_hex: String,
    pub body_hash_hex: String,
    pub deployment: String,
    pub issuer_generation: u64,
    pub issuer_public_key: [u8; 32],
    pub approved_account_key: [u8; 32],
    pub approved_manager_key: [u8; 32],
    pub endpoint_key: [u8; 32],
    pub endpoint_incarnation: String,
    pub boot_id: String,
    pub worker_id: String,
    pub computer_id: String,
    pub incarnation_id: String,
    pub desktop_generation: u64,
    pub display_generation: u64,
    pub operation: String,
    pub operation_intent: String,
    pub interaction_generation: u64,
    pub policy_revision: String,
    pub authority_revision: String,
    pub channel_binding: Vec<u8>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub schema_version: String,
}

/// Issuer journal error.
#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal file already exists")]
    AlreadyExists,
    #[error("journal file missing")]
    NotFound,
    #[error("timestamp overflow for INTEGER column")]
    TimestampOverflow,
    #[error("negative DB integer field")]
    NegativeDbInteger,
    #[error("issuer config not initialized")]
    NotInitialized,
    #[error("issuer config mismatch")]
    ConfigMismatch,
    #[error("issuer config corrupt")]
    ConfigCorrupt,
    #[error("nonce already issued")]
    NonceAlreadyIssued,
    #[error("capacity exhausted")]
    CapacityExhausted,
    #[error("gate latched closed: {0}")]
    GateLatched(String),
    #[error("storage fault (latched): {0}")]
    StorageFault(String),
}

impl IssuerError {
    pub fn is_storage_fault(&self) -> bool {
        matches!(
            self,
            IssuerError::Db(_)
                | IssuerError::StorageFault(_)
                | IssuerError::Io(_)
                | IssuerError::TimestampOverflow
                | IssuerError::NegativeDbInteger
                | IssuerError::ConfigCorrupt
        )
    }
}

fn u64_to_i64(v: u64) -> Result<i64, IssuerError> {
    i64::try_from(v).map_err(|_| IssuerError::TimestampOverflow)
}

fn i64_to_u64(v: i64) -> Result<u64, IssuerError> {
    if v < 0 {
        return Err(IssuerError::NegativeDbInteger);
    }
    Ok(v as u64)
}

fn is_nonce_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, Some(msg)) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
                && msg.contains("issued_journal.nonce_hex")
        }
        _ => false,
    }
}

/// Separate issuer issuance journal backed by SQLite.
pub struct IssuerJournal {
    conn: Connection,
    path: Option<PathBuf>,
    max_journal: i64,
    latched: bool,
    latch_reason: String,
}

impl IssuerJournal {
    /// Exclusive fresh creation.
    pub fn create(path: &Path) -> Result<Self, IssuerError> {
        Self::create_with_limit(path, DEFAULT_MAX_JOURNAL)
    }

    pub fn create_with_limit(path: &Path, max_journal: i64) -> Result<Self, IssuerError> {
        {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(IssuerError::AlreadyExists)
                }
                Err(e) => return Err(IssuerError::Io(e)),
            }
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            max_journal,
            latched: false,
            latch_reason: String::new(),
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    /// Open an existing journal. Never mutates schema.
    pub fn open(path: &Path) -> Result<Self, IssuerError> {
        Self::open_with_limit(path, DEFAULT_MAX_JOURNAL)
    }

    pub fn open_with_limit(path: &Path, max_journal: i64) -> Result<Self, IssuerError> {
        if !path.exists() {
            return Err(IssuerError::NotFound);
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: Some(path.to_path_buf()),
            max_journal,
            latched: false,
            latch_reason: String::new(),
        };
        store.configure_connection()?;
        store.validate_existing()?;
        store.refresh_fault_state()?;
        Ok(store)
    }

    /// In-memory journal for fixtures.
    pub fn create_memory() -> Result<Self, IssuerError> {
        Self::create_memory_with_limit(DEFAULT_MAX_JOURNAL)
    }

    pub fn create_memory_with_limit(max_journal: i64) -> Result<Self, IssuerError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self {
            conn,
            path: None,
            max_journal,
            latched: false,
            latch_reason: String::new(),
        };
        store.configure_connection()?;
        store.create_schema()?;
        Ok(store)
    }

    fn configure_connection(&mut self) -> Result<(), IssuerError> {
        self.conn.pragma_update(None, "synchronous", "FULL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(200))?;
        Ok(())
    }

    fn create_schema(&mut self) -> Result<(), IssuerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            r#"
            CREATE TABLE issuer_config (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                format_version    INTEGER NOT NULL,
                issuer_public_key BLOB NOT NULL,
                issuer_generation INTEGER NOT NULL,
                initialized       INTEGER NOT NULL CHECK (initialized IN (0, 1)),
                created_at_ms     INTEGER NOT NULL
            );

            CREATE TABLE issued_journal (
                intent_id              TEXT PRIMARY KEY,
                nonce_hex              TEXT NOT NULL UNIQUE,
                body_hash_hex          TEXT NOT NULL,
                deployment             TEXT NOT NULL,
                issuer_generation      INTEGER NOT NULL,
                issuer_public_key      BLOB NOT NULL,
                approved_account_key   BLOB NOT NULL,
                approved_manager_key   BLOB NOT NULL,
                endpoint_key           BLOB NOT NULL,
                endpoint_incarnation   TEXT NOT NULL,
                boot_id                TEXT NOT NULL,
                worker_id              TEXT NOT NULL,
                computer_id            TEXT NOT NULL,
                incarnation_id         TEXT NOT NULL,
                desktop_generation     INTEGER NOT NULL,
                display_generation     INTEGER NOT NULL,
                operation              TEXT NOT NULL,
                operation_intent       TEXT NOT NULL,
                interaction_generation INTEGER NOT NULL,
                policy_revision        TEXT NOT NULL,
                authority_revision     TEXT NOT NULL,
                channel_binding        BLOB NOT NULL,
                issued_at_ms           INTEGER NOT NULL,
                expires_at_ms          INTEGER NOT NULL,
                schema_version         TEXT NOT NULL,
                signed_at_ms           INTEGER NOT NULL
            );

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
            "INSERT INTO issuer_config (id, format_version, issuer_public_key, issuer_generation, initialized, created_at_ms) VALUES (1, ?1, X'', 0, 0, ?2)",
            params![ISSUER_FORMAT_VERSION, now],
        )?;
        tx.execute(
            "INSERT INTO fault_state (id, latched, reason, latched_at) VALUES (1, 0, 'healthy', ?1)",
            params![now],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn validate_existing(&mut self) -> Result<(), IssuerError> {
        let result = (|| -> Result<(), IssuerError> {
            let names = ["issuer_config", "issued_journal", "fault_state"];
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
                    return Err(IssuerError::ConfigCorrupt);
                }
            }
            let fmt: Option<(i64, i64)> = self
                .conn
                .query_row(
                    "SELECT format_version, initialized FROM issuer_config WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match fmt {
                None => Err(IssuerError::ConfigCorrupt),
                Some((ver, init)) => {
                    if ver != ISSUER_FORMAT_VERSION || !(init == 0 || init == 1) {
                        return Err(IssuerError::ConfigCorrupt);
                    }
                    Ok(())
                }
            }
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
        // Belt-and-braces: sidecar too regardless of DB outcome
        // so a later healthy DB row cannot hide a fault.
        let _ = self.write_durable_sidecar(reason);
        let _ = db_ok;
    }

    fn refresh_fault_state(&mut self) -> Result<(), IssuerError> {
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
                Err(e) => return Err(self.map_fault(IssuerError::Io(e))),
            }
        }
        let result = (|| -> Result<(), IssuerError> {
            let row: Option<i64> = self
                .conn
                .query_row("SELECT latched FROM fault_state WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .optional()?;
            match row {
                Some(0) => Ok(()),
                Some(1) => Err(IssuerError::GateLatched("fault_state latched=1".into())),
                _ => Err(IssuerError::ConfigCorrupt),
            }
        })();
        match result {
            Ok(()) => Ok(()),
            Err(IssuerError::GateLatched(reason)) => {
                self.latched = true;
                if self.latch_reason.is_empty() {
                    self.latch_reason = reason;
                }
                Ok(())
            }
            Err(e) => Err(self.map_fault(e)),
        }
    }

    fn map_fault(&mut self, err: IssuerError) -> IssuerError {
        if err.is_storage_fault() {
            let msg = err.to_string();
            self.latch_fault(&msg);
            if matches!(err, IssuerError::Db(_) | IssuerError::Io(_)) {
                return IssuerError::StorageFault(self.latch_reason.clone());
            }
        }
        err
    }

    fn ensure_open(&mut self) -> Result<(), IssuerError> {
        self.refresh_fault_state()?;
        if self.latched {
            return Err(IssuerError::GateLatched(self.latch_reason.clone()));
        }
        Ok(())
    }

    pub fn is_latched(&self) -> bool {
        self.latched
    }

    pub fn latch_reason(&self) -> &str {
        &self.latch_reason
    }

    /// Initialize issuer config. One-shot on a fresh handle.
    pub fn initialize(
        &mut self,
        issuer_public_key: &[u8; 32],
        issuer_generation: u64,
    ) -> Result<(), IssuerError> {
        self.ensure_open()?;
        if issuer_generation == 0 {
            return Err(IssuerError::ConfigMismatch);
        }
        let result = (|| -> Result<(), IssuerError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<(i64, Vec<u8>, i64)> = tx
                .query_row(
                    "SELECT initialized, issuer_public_key, issuer_generation FROM issuer_config WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((init, key, gen)) = existing else {
                tx.rollback()?;
                return Err(IssuerError::ConfigCorrupt);
            };
            if init == 1 {
                if key.as_slice() != issuer_public_key.as_slice()
                    || i64_to_u64(gen)? != issuer_generation
                {
                    tx.rollback()?;
                    return Err(IssuerError::ConfigMismatch);
                }
                tx.rollback()?;
                return Ok(());
            }
            tx.execute(
                "UPDATE issuer_config SET initialized = 1, issuer_public_key = ?1, issuer_generation = ?2 WHERE id = 1",
                params![issuer_public_key.as_slice(), u64_to_i64(issuer_generation)?],
            )?;
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| self.map_fault(e))
    }

    /// Record an issuance in the journal. Atomic with fault/capacity checks.
    pub fn record_issuance(&mut self, entry: &JournalEntry) -> Result<(), IssuerError> {
        self.ensure_open()?;
        let result = (|| -> Result<(), IssuerError> {
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
                    return Err(IssuerError::GateLatched("fault_state latched=1".into()));
                }
                _ => {
                    tx.rollback()?;
                    return Err(IssuerError::ConfigCorrupt);
                }
            }

            // Capacity check
            let count: i64 =
                tx.query_row("SELECT COUNT(*) FROM issued_journal", [], |r| r.get(0))?;
            if count < 0 {
                tx.rollback()?;
                return Err(IssuerError::ConfigCorrupt);
            }
            if count >= self.max_journal {
                tx.rollback()?;
                return Err(IssuerError::CapacityExhausted);
            }

            let now = now_i64();
            let changed = tx.execute(
                "INSERT INTO issued_journal (
                    intent_id, nonce_hex, body_hash_hex, deployment, issuer_generation,
                    issuer_public_key, approved_account_key, approved_manager_key,
                    endpoint_key, endpoint_incarnation, boot_id, worker_id,
                    computer_id, incarnation_id, desktop_generation, display_generation,
                    operation, operation_intent, interaction_generation, policy_revision,
                    authority_revision, channel_binding, issued_at_ms, expires_at_ms,
                    schema_version, signed_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
                params![
                    entry.intent_id,
                    entry.nonce_hex,
                    entry.body_hash_hex,
                    entry.deployment,
                    u64_to_i64(entry.issuer_generation)?,
                    entry.issuer_public_key.as_slice(),
                    entry.approved_account_key.as_slice(),
                    entry.approved_manager_key.as_slice(),
                    entry.endpoint_key.as_slice(),
                    entry.endpoint_incarnation,
                    entry.boot_id,
                    entry.worker_id,
                    entry.computer_id,
                    entry.incarnation_id,
                    u64_to_i64(entry.desktop_generation)?,
                    u64_to_i64(entry.display_generation)?,
                    entry.operation,
                    entry.operation_intent,
                    u64_to_i64(entry.interaction_generation)?,
                    entry.policy_revision,
                    entry.authority_revision,
                    entry.channel_binding,
                    u64_to_i64(entry.issued_at_ms)?,
                    u64_to_i64(entry.expires_at_ms)?,
                    entry.schema_version,
                    now,
                ],
            )?;
            if changed != 1 {
                tx.rollback()?;
                return Err(IssuerError::NonceAlreadyIssued);
            }
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|e| {
            if matches!(e, IssuerError::Db(ref de) if is_nonce_unique_violation(de)) {
                return IssuerError::NonceAlreadyIssued;
            }
            self.map_fault(e)
        })
    }

    /// Look up a journal entry by intent_id.
    pub fn get_entry(&mut self, intent_id: &str) -> Result<Option<JournalEntry>, IssuerError> {
        self.ensure_open()?;
        let result = (|| -> Result<Option<JournalEntry>, IssuerError> {
            let row = self
                .conn
                .query_row(
                    "SELECT intent_id, nonce_hex, body_hash_hex, deployment, issuer_generation,
                            issuer_public_key, approved_account_key, approved_manager_key,
                            endpoint_key, endpoint_incarnation, boot_id, worker_id,
                            computer_id, incarnation_id, desktop_generation, display_generation,
                            operation, operation_intent, interaction_generation, policy_revision,
                            authority_revision, channel_binding, issued_at_ms, expires_at_ms,
                            schema_version
                     FROM issued_journal WHERE intent_id = ?1",
                    params![intent_id],
                    |r| {
                        let issuer_key: Vec<u8> = r.get(5)?;
                        let account_key: Vec<u8> = r.get(6)?;
                        let manager_key: Vec<u8> = r.get(7)?;
                        let ep_key: Vec<u8> = r.get(8)?;
                        let channel: Vec<u8> = r.get(21)?;
                        if issuer_key.len() != 32
                            || account_key.len() != 32
                            || manager_key.len() != 32
                            || ep_key.len() != 32
                        {
                            return Err(rusqlite::Error::InvalidColumnType(
                                5,
                                "key length".into(),
                                rusqlite::types::Type::Blob,
                            ));
                        }
                        let mut ik = [0u8; 32];
                        ik.copy_from_slice(&issuer_key);
                        let mut ak = [0u8; 32];
                        ak.copy_from_slice(&account_key);
                        let mut mk = [0u8; 32];
                        mk.copy_from_slice(&manager_key);
                        let mut ek = [0u8; 32];
                        ek.copy_from_slice(&ep_key);
                        let gen_i64: i64 = r.get(4)?;
                        let desk_i64: i64 = r.get(14)?;
                        let disp_i64: i64 = r.get(15)?;
                        let inter_i64: i64 = r.get(18)?;
                        let issued_i64: i64 = r.get(22)?;
                        let expires_i64: i64 = r.get(23)?;
                        if gen_i64 < 0
                            || desk_i64 < 0
                            || disp_i64 < 0
                            || inter_i64 < 0
                            || issued_i64 < 0
                            || expires_i64 < 0
                        {
                            return Err(rusqlite::Error::InvalidColumnType(
                                4,
                                "negative integer".into(),
                                rusqlite::types::Type::Integer,
                            ));
                        }
                        Ok(JournalEntry {
                            intent_id: r.get(0)?,
                            nonce_hex: r.get(1)?,
                            body_hash_hex: r.get(2)?,
                            deployment: r.get(3)?,
                            issuer_generation: gen_i64 as u64,
                            issuer_public_key: ik,
                            approved_account_key: ak,
                            approved_manager_key: mk,
                            endpoint_key: ek,
                            endpoint_incarnation: r.get(9)?,
                            boot_id: r.get(10)?,
                            worker_id: r.get(11)?,
                            computer_id: r.get(12)?,
                            incarnation_id: r.get(13)?,
                            desktop_generation: desk_i64 as u64,
                            display_generation: disp_i64 as u64,
                            operation: r.get(16)?,
                            operation_intent: r.get(17)?,
                            interaction_generation: inter_i64 as u64,
                            policy_revision: r.get(19)?,
                            authority_revision: r.get(20)?,
                            channel_binding: channel,
                            issued_at_ms: issued_i64 as u64,
                            expires_at_ms: expires_i64 as u64,
                            schema_version: r.get(24)?,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })();
        result.map_err(|e| self.map_fault(e))
    }
}

fn now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> JournalEntry {
        JournalEntry {
            intent_id: "intent-1".to_string(),
            nonce_hex: hex::encode([1u8; 32]),
            body_hash_hex: hex::encode([2u8; 32]),
            deployment: "deploy-1".to_string(),
            issuer_generation: 1,
            issuer_public_key: [0xAAu8; 32],
            approved_account_key: [0xBBu8; 32],
            approved_manager_key: [0xCCu8; 32],
            endpoint_key: [0xDDu8; 32],
            endpoint_incarnation: "ep-inc-1".to_string(),
            boot_id: "boot-1".to_string(),
            worker_id: "worker-1".to_string(),
            computer_id: "room7-a03".to_string(),
            incarnation_id: "inc-abc".to_string(),
            desktop_generation: 3,
            display_generation: 2,
            operation: "observe".to_string(),
            operation_intent: "view-stream".to_string(),
            interaction_generation: 1,
            policy_revision: "policy-2026".to_string(),
            authority_revision: "rev-1".to_string(),
            channel_binding: b"channel-v2".to_vec(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            schema_version: "v2".to_string(),
        }
    }

    #[test]
    fn issuer_create_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer.db");
        let j = IssuerJournal::create(&path).unwrap();
        assert!(!j.is_latched());
        drop(j);
        let j2 = IssuerJournal::open(&path).unwrap();
        assert!(!j2.is_latched());
    }

    #[test]
    fn issuer_create_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("excl.db");
        assert!(IssuerJournal::create(&path).is_ok());
        assert!(matches!(
            IssuerJournal::create(&path),
            Err(IssuerError::AlreadyExists)
        ));
    }

    #[test]
    fn issuer_open_missing_denies() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            IssuerJournal::open(&dir.path().join("nope.db")),
            Err(IssuerError::NotFound)
        ));
    }

    #[test]
    fn issuer_initialize_and_record() {
        let mut j = IssuerJournal::create_memory().unwrap();
        j.initialize(&[0xAAu8; 32], 1).unwrap();
        j.record_issuance(&sample_entry()).unwrap();
        let got = j.get_entry("intent-1").unwrap().unwrap();
        assert_eq!(got.nonce_hex, hex::encode([1u8; 32]));
        assert_eq!(got.issuer_public_key, [0xAAu8; 32]);
        assert_eq!(got.approved_account_key, [0xBBu8; 32]);
        assert_eq!(got.endpoint_key, [0xDDu8; 32]);
        assert_eq!(got.desktop_generation, 3);
    }

    #[test]
    fn issuer_nonce_uniqueness() {
        let mut j = IssuerJournal::create_memory().unwrap();
        j.initialize(&[0xAAu8; 32], 1).unwrap();
        j.record_issuance(&sample_entry()).unwrap();
        // Same nonce → conflict
        let mut dup = sample_entry();
        dup.intent_id = "intent-2".to_string(); // different intent, same nonce
        assert!(matches!(
            j.record_issuance(&dup),
            Err(IssuerError::NonceAlreadyIssued)
        ));
    }

    #[test]
    fn issuer_capacity_exhaustion() {
        let mut j = IssuerJournal::create_memory_with_limit(1).unwrap();
        j.initialize(&[0xAAu8; 32], 1).unwrap();
        j.record_issuance(&sample_entry()).unwrap();
        let mut second = sample_entry();
        second.intent_id = "intent-2".to_string();
        second.nonce_hex = hex::encode([3u8; 32]);
        assert!(matches!(
            j.record_issuance(&second),
            Err(IssuerError::CapacityExhausted)
        ));
    }

    #[test]
    fn issuer_memory_roundtrip() {
        let mut j = IssuerJournal::create_memory().unwrap();
        j.initialize(&[0xAAu8; 32], 1).unwrap();
        j.record_issuance(&sample_entry()).unwrap();
        assert!(j.get_entry("nonexistent").unwrap().is_none());
    }
}
