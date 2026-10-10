//! Public admission-boundary proofs for the second review.
//!
//! Drives `DurableStore::create`/`open`, `AdmissionController::issue`, and
//! `AdmissionController::admit` only. Automatic fail-closed behaviour is
//! evidenced by public issue/admit hitting real storage faults — not by
//! calling `latch_fault` by hand.

use authority_lab::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

fn binding_for(key: &IssuerSigningKey) -> TrustBinding {
    TrustBinding {
        issuer_public_key: *key.verifying_key().as_bytes(),
        issuer_generation: 1,
        authority_revision: "rev-1".to_string(),
        deployment: "deploy-1".to_string(),
        schema: SCHEMA_VERSION.to_string(),
    }
}

fn receiver() -> ReceiverContext {
    ReceiverContext {
        computer: ComputerId::new("room7-a03").unwrap(),
        incarnation: IncarnationId::new("inc-abc").unwrap(),
        account: AccountId::new("acct-42").unwrap(),
        manager: ManagerId::new("mgr-7").unwrap(),
        desktop_generation: DesktopGeneration::new(3).unwrap(),
    }
}

fn fields(now: u64) -> CanonicalFields {
    let issued = TimestampMs::new(now.saturating_sub(500).max(1)).unwrap();
    let expires = TimestampMs::new(
        now.saturating_add(5_000)
            .min(issued.as_u64() + MAX_CANDIDATE_LIFETIME_MS),
    )
    .unwrap();
    CanonicalFields {
        schema: SCHEMA_VERSION.to_string(),
        deployment: DeploymentId::new("deploy-1").unwrap(),
        issuer_generation: 1,
        authority_revision: AuthorityRevision::new("rev-1").unwrap(),
        computer: ComputerId::new("room7-a03").unwrap(),
        incarnation: IncarnationId::new("inc-abc").unwrap(),
        account: AccountId::new("acct-42").unwrap(),
        manager: ManagerId::new("mgr-7").unwrap(),
        action_scope: ActionScope::observe_only(),
        desktop_generation: DesktopGeneration::new(3).unwrap(),
        session_nonce: Nonce::new(random_32()).unwrap(),
        issued_at: issued,
        expires_at: expires,
    }
}

struct Fixture {
    key: IssuerSigningKey,
    store: DurableStore,
    ctrl: AdmissionController,
    intent: String,
}

fn fixture_memory(start_ms: u64) -> Fixture {
    let key = IssuerSigningKey::generate();
    let mut store = DurableStore::create_memory().unwrap();
    store.initialize_trust(&binding_for(&key)).unwrap();
    let ctrl =
        AdmissionController::try_new(binding_for(&key), Box::new(ManualEpochClock::new(start_ms)))
            .unwrap();
    Fixture {
        key,
        store,
        ctrl,
        intent: unique_intent("mem"),
    }
}

fn fixture_file(dir: &Path, start_ms: u64) -> (Fixture, PathBuf) {
    let key = IssuerSigningKey::generate();
    let path = dir.join("admission.db");
    let mut store = DurableStore::create(&path).unwrap();
    store.initialize_trust(&binding_for(&key)).unwrap();
    let ctrl =
        AdmissionController::try_new(binding_for(&key), Box::new(ManualEpochClock::new(start_ms)))
            .unwrap();
    (
        Fixture {
            key,
            store,
            ctrl,
            intent: unique_intent("file"),
        },
        path,
    )
}

fn unique_intent(tag: &str) -> String {
    format!("{tag}-{}", hex::encode(random_32()))
}

fn admit_ok(f: &mut Fixture, grant: &Grant) -> AdmissionDecision {
    f.ctrl.admit(
        grant,
        Operation::Observe,
        &receiver(),
        &mut f.store,
        &f.intent,
    )
}

#[test]
fn lifetime_rejects_over_30s_allows_exact() {
    let mut f = fixture_memory(1_000);
    let mut over = fields(1_000);
    over.issued_at = TimestampMs::new(1_000).unwrap();
    over.expires_at = TimestampMs::new(1_000 + MAX_CANDIDATE_LIFETIME_MS + 1).unwrap();
    assert!(matches!(
        f.ctrl
            .issue(over, &f.key, &mut f.store, &unique_intent("over")),
        Err(IssueError::DurationExceedsBound)
    ));

    let mut exact = fields(1_000);
    exact.issued_at = TimestampMs::new(1_000).unwrap();
    exact.expires_at = TimestampMs::new(1_000 + MAX_CANDIDATE_LIFETIME_MS).unwrap();
    let issued = f
        .ctrl
        .issue(exact, &f.key, &mut f.store, &unique_intent("exact"))
        .expect("exact 30s lifetime must be allowed");
    assert_eq!(
        f.ctrl.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Granted
    );
}

#[test]
fn create_is_exclusive_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("excl.db");
    assert!(DurableStore::create(&path).is_ok());
    assert!(matches!(
        DurableStore::create(&path),
        Err(StoreError::AlreadyExists)
    ));
}

#[test]
fn open_missing_file_denies() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        DurableStore::open(&dir.path().join("nope.db")),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn reopen_uninitialized_denies_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uninit.db");
    let key = IssuerSigningKey::generate();
    {
        let _fresh = DurableStore::create(&path).unwrap();
    }
    let mut store = DurableStore::open(&path).unwrap();
    assert!(matches!(
        store.initialize_trust(&binding_for(&key)),
        Err(StoreError::InitNotAllowed)
    ));
}

#[test]
fn initialize_twice_on_fresh_handle_is_one_shot() {
    let mut store = DurableStore::create_memory().unwrap();
    let key = IssuerSigningKey::generate();
    store.initialize_trust(&binding_for(&key)).unwrap();
    // Same binding no-op only when required state remains valid.
    store.initialize_trust(&binding_for(&key)).unwrap();
    let mut other = binding_for(&key);
    other.issuer_generation = 2;
    assert!(matches!(
        store.initialize_trust(&other),
        Err(StoreError::TrustBindingMismatch) | Err(StoreError::InitNotAllowed)
    ));
}

#[test]
fn issue_then_admit_and_replay() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    assert_eq!(admit_ok(&mut f, &issued.grant), AdmissionDecision::Granted);
    assert_eq!(
        admit_ok(&mut f, &issued.grant),
        AdmissionDecision::Denied(DenyReason::ReplayDetected)
    );
}

#[test]
fn observe_control_stop_separation() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    assert_eq!(
        f.ctrl.admit(
            &issued.grant,
            Operation::Control,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::OperationNotPermitted)
    );
    assert_eq!(admit_ok(&mut f, &issued.grant), AdmissionDecision::Granted);

    let mut f2 = fixture_memory(1_500);
    let mut flds = fields(1_500);
    flds.action_scope = ActionScope::stop_only();
    let issued = f2
        .ctrl
        .issue(flds, &f2.key, &mut f2.store, &f2.intent)
        .unwrap();
    for op in [Operation::Observe, Operation::Control] {
        assert_eq!(
            f2.ctrl.admit(
                &issued.grant,
                op,
                &receiver(),
                &mut f2.store,
                &issued.intent_id
            ),
            AdmissionDecision::Denied(DenyReason::OperationNotPermitted)
        );
    }
    assert_eq!(
        f2.ctrl.admit(
            &issued.grant,
            Operation::StopOnly,
            &receiver(),
            &mut f2.store,
            &issued.intent_id
        ),
        AdmissionDecision::Granted
    );
}

#[test]
fn expiry_equality_and_not_yet_valid() {
    let mut f = fixture_memory(1_000);
    let mut flds = fields(1_000);
    flds.issued_at = TimestampMs::new(1_000).unwrap();
    flds.expires_at = TimestampMs::new(2_000).unwrap();
    let issued = f.ctrl.issue(flds, &f.key, &mut f.store, &f.intent).unwrap();

    let at_eq =
        AdmissionController::try_new(binding_for(&f.key), Box::new(ManualEpochClock::new(2_000)))
            .unwrap();
    assert_eq!(
        at_eq.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::Expired)
    );

    let early =
        AdmissionController::try_new(binding_for(&f.key), Box::new(ManualEpochClock::new(500)))
            .unwrap();
    assert_eq!(
        early.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::NotYetValid)
    );
}

#[test]
fn wrong_issuer_key_rejected_before_store() {
    let mut f = fixture_memory(1_500);
    let other = IssuerSigningKey::generate();
    assert!(matches!(
        f.ctrl
            .issue(fields(1_500), &other, &mut f.store, &unique_intent("w")),
        Err(IssueError::SigningKeyMismatch)
    ));
}

#[test]
fn signature_substitution_and_field_mutation_do_not_consume() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    let nonce_hex = hex::encode(issued.grant.fields.session_nonce.as_bytes());

    let mut bad_sig = issued.grant.clone();
    bad_sig.signature[0] ^= 0xFF;
    assert_eq!(
        f.ctrl.admit(
            &bad_sig,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::SignatureInvalid)
    );

    type Mutator = fn(&mut CanonicalFields);
    let mutators: [Mutator; 13] = [
        |c| c.computer = ComputerId::new("room7-x").unwrap(),
        |c| c.incarnation = IncarnationId::new("inc-x").unwrap(),
        |c| c.account = AccountId::new("acct-x").unwrap(),
        |c| c.manager = ManagerId::new("mgr-x").unwrap(),
        |c| c.desktop_generation = DesktopGeneration::new(9).unwrap(),
        |c| c.session_nonce = Nonce::new(random_32()).unwrap(),
        |c| c.issued_at = TimestampMs::new(1).unwrap(),
        |c| c.expires_at = TimestampMs::new(9_999).unwrap(),
        |c| c.issuer_generation = 2,
        |c| c.deployment = DeploymentId::new("deploy-x").unwrap(),
        |c| c.authority_revision = AuthorityRevision::new("rev-x").unwrap(),
        |c| c.schema = "v99".to_string(),
        |c| c.action_scope = ActionScope::stop_only(),
    ];
    for mutator in mutators {
        let mut g = issued.grant.clone();
        mutator(&mut g.fields);
        let d = f.ctrl.admit(
            &g,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id,
        );
        assert!(
            matches!(
                d,
                AdmissionDecision::Denied(
                    DenyReason::SignatureInvalid
                        | DenyReason::TargetMismatch
                        | DenyReason::MalformedCredential
                        | DenyReason::SchemaMismatch
                        | DenyReason::DeploymentMismatch
                        | DenyReason::IssuerGenerationMismatch
                        | DenyReason::AuthorityRevisionMismatch
                        | DenyReason::OperationNotPermitted
                        | DenyReason::NotYetValid
                        | DenyReason::Expired
                )
            ),
            "mutated field unexpectedly admitted: {d:?}"
        );
    }
    assert!(!f.store.is_nonce_claimed(&nonce_hex).unwrap());
}

#[test]
fn trusted_wrong_identity_rejected() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    let cases = [
        ReceiverContext {
            account: AccountId::new("acct-other").unwrap(),
            ..receiver()
        },
        ReceiverContext {
            manager: ManagerId::new("mgr-other").unwrap(),
            ..receiver()
        },
        ReceiverContext {
            computer: ComputerId::new("room7-b01").unwrap(),
            ..receiver()
        },
        ReceiverContext {
            incarnation: IncarnationId::new("inc-other").unwrap(),
            ..receiver()
        },
        ReceiverContext {
            desktop_generation: DesktopGeneration::new(4).unwrap(),
            ..receiver()
        },
    ];
    for ctx in cases {
        assert_eq!(
            f.ctrl.admit(
                &issued.grant,
                Operation::Observe,
                &ctx,
                &mut f.store,
                &issued.intent_id
            ),
            AdmissionDecision::Denied(DenyReason::TargetMismatch)
        );
    }
}

#[test]
fn intent_mismatch_denied() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    let wrong = unique_intent("other");
    assert_eq!(
        f.ctrl.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &wrong
        ),
        AdmissionDecision::Denied(DenyReason::MalformedCredential)
    );
}

#[test]
fn closed_epoch_blocks_and_cannot_reopen() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    f.store.close_epoch("revoke").unwrap();
    assert!(matches!(
        f.ctrl
            .issue(fields(1_500), &f.key, &mut f.store, &unique_intent("b")),
        Err(IssueError::EpochClosed)
    ));
    assert_eq!(
        f.ctrl.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::EpochClosed)
    );
    f.store.close_epoch("again").unwrap();
    assert!(f.store.is_epoch_closed().unwrap());
}

#[test]
fn closed_epoch_survives_deleted_binding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("closed.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
        store.close_epoch("down").unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM trust_binding", []).unwrap();
    }
    // Fail closed: open latches/errors, and initialization is impossible.
    match DurableStore::open(&path) {
        Err(_) => {}
        Ok(mut store) => {
            assert!(store.is_latched() || store.trust_binding().is_err());
            assert!(store.initialize_trust(&binding_for(&key)).is_err());
        }
    }
}

#[test]
fn deleted_trust_table_never_heals_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deltrust.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM trust_binding", []).unwrap();
    }
    // Open must fail closed / latch; must not recreate the row.
    match DurableStore::open(&path) {
        Err(_) => {}
        Ok(mut store) => {
            assert!(store.is_latched() || store.trust_binding().is_err());
            assert!(store.initialize_trust(&binding_for(&key)).is_err());
        }
    }
}

#[test]
fn deleted_fault_row_never_heals_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delfault.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM fault_state", []).unwrap();
    }
    assert!(matches!(
        DurableStore::open(&path),
        Err(StoreError::TrustStateCorrupt)
    ));
    let reopened = DurableStore::open(&path).unwrap();
    assert!(
        reopened.is_latched(),
        "observed missing fault row must leave a durable latch"
    );
}

#[test]
fn missing_epoch_row_latches_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delepoch.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM epoch_state", []).unwrap();
    }
    match DurableStore::open(&path) {
        Err(_) => {}
        Ok(mut store) => {
            assert!(store.is_latched() || store.is_epoch_closed().is_err());
        }
    }
}

#[test]
fn simultaneous_consumption_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut f, path) = fixture_file(dir.path(), 1_500);
    let key_bytes = *f.key.verifying_key().as_bytes();
    let intent = f.intent.clone();
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &intent)
        .unwrap();
    drop(f.store);

    let grant = issued.grant;
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let path = path.clone();
        let grant = grant.clone();
        let intent = intent.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = DurableStore::open(&path).unwrap();
            let binding = TrustBinding {
                issuer_public_key: key_bytes,
                issuer_generation: 1,
                authority_revision: "rev-1".into(),
                deployment: "deploy-1".into(),
                schema: SCHEMA_VERSION.into(),
            };
            let ctrl =
                AdmissionController::try_new(binding, Box::new(ManualEpochClock::new(1_500)))
                    .unwrap();
            barrier.wait();
            ctrl.admit(&grant, Operation::Observe, &receiver(), &mut store, &intent)
        }));
    }
    let results: Vec<AdmissionDecision> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let granted = results
        .iter()
        .filter(|d| **d == AdmissionDecision::Granted)
        .count();
    assert_eq!(granted, 1, "results: {results:?}");

    let mut store = DurableStore::open(&path).unwrap();
    let binding = TrustBinding {
        issuer_public_key: key_bytes,
        issuer_generation: 1,
        authority_revision: "rev-1".into(),
        deployment: "deploy-1".into(),
        schema: SCHEMA_VERSION.into(),
    };
    let ctrl =
        AdmissionController::try_new(binding, Box::new(ManualEpochClock::new(1_500))).unwrap();
    assert_eq!(
        ctrl.admit(&grant, Operation::Observe, &receiver(), &mut store, &intent),
        AdmissionDecision::Denied(DenyReason::ReplayDetected)
    );
}

#[test]
fn capacity_fails_closed_without_pruning() {
    let key = IssuerSigningKey::generate();
    let mut store = DurableStore::create_memory_with_limits(StoreLimits {
        max_issued: 2,
        max_claimed: 1,
    })
    .unwrap();
    store.initialize_trust(&binding_for(&key)).unwrap();
    let ctrl =
        AdmissionController::try_new(binding_for(&key), Box::new(ManualEpochClock::new(1_500)))
            .unwrap();

    let ia = unique_intent("a");
    let ib = unique_intent("b");
    let a = ctrl.issue(fields(1_500), &key, &mut store, &ia).unwrap();
    let b = ctrl.issue(fields(1_500), &key, &mut store, &ib).unwrap();
    assert!(matches!(
        ctrl.issue(fields(1_500), &key, &mut store, &unique_intent("c")),
        Err(IssueError::Store(StoreError::CapacityExhausted))
    ));

    assert_eq!(
        ctrl.admit(&a.grant, Operation::Observe, &receiver(), &mut store, &ia),
        AdmissionDecision::Granted
    );
    assert_eq!(
        ctrl.admit(&b.grant, Operation::Observe, &receiver(), &mut store, &ib),
        AdmissionDecision::Denied(DenyReason::CapacityExhausted)
    );
    assert!(store
        .is_nonce_claimed(&hex::encode(a.grant.fields.session_nonce.as_bytes()))
        .unwrap());
}

#[test]
fn real_lock_fault_auto_latches_public_issue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lock.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }

    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let mut store = DurableStore::open(&path).unwrap();
    let ctrl =
        AdmissionController::try_new(binding_for(&key), Box::new(ManualEpochClock::new(1_500)))
            .unwrap();
    // Public issue under write-lock contention must fail closed and latch.
    let res = ctrl.issue(fields(1_500), &key, &mut store, &unique_intent("lock"));
    assert!(res.is_err(), "issue under lock must fail");
    assert!(store.is_latched() || store.has_durable_fault());

    let _ = blocker.execute_batch("ROLLBACK");
    let reopened = DurableStore::open(&path).unwrap();
    assert!(
        reopened.is_latched(),
        "automatic lock fault must survive reopen"
    );
}

#[test]
fn read_only_db_auto_latches_public_issue() {
    let dir = tempfile::tempdir().unwrap();
    let (f, path) = fixture_file(dir.path(), 1_500);
    drop(f.store);

    // Genuine read-only fault injection (FILE_ATTRIBUTE_READONLY on Windows,
    // mode bits on Unix). Save the original permissions metadata so cleanup
    // restores what was actually on disk — never a hardcoded 0644.
    let original_perms = std::fs::metadata(&path).unwrap().permissions();
    let mut readonly_perms = original_perms.clone();
    readonly_perms.set_readonly(true);
    std::fs::set_permissions(&path, readonly_perms).unwrap();

    let mut store = DurableStore::open(&path).unwrap();
    // May open for read; public issue must fail closed and latch.
    let ctrl =
        AdmissionController::try_new(binding_for(&f.key), Box::new(ManualEpochClock::new(1_500)))
            .unwrap();
    let res = ctrl.issue(fields(1_500), &f.key, &mut store, &unique_intent("ro"));
    assert!(
        res.is_err(),
        "read-only database must fail public issue on this platform"
    );
    assert!(store.is_latched() || store.has_durable_fault());

    // Restore the exact original permissions metadata.
    let _ = std::fs::set_permissions(&path, original_perms);
}

#[test]
fn other_open_handle_stops_after_sibling_latches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sibling.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }

    let mut a = DurableStore::open(&path).unwrap();
    let mut b = DurableStore::open(&path).unwrap();
    let ctrl =
        AdmissionController::try_new(binding_for(&key), Box::new(ManualEpochClock::new(1_500)))
            .unwrap();

    // Force a real write failure on A via a held write lock.
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let res = ctrl.issue(fields(1_500), &key, &mut a, &unique_intent("a"));
    assert!(res.is_err());
    assert!(a.is_latched());

    let _ = blocker.execute_batch("ROLLBACK");

    // B must observe the durable latch on its next public operation.
    let res_b = ctrl.issue(fields(1_500), &key, &mut b, &unique_intent("b"));
    assert!(
        res_b.is_err(),
        "sibling handle must not continue: {res_b:?}"
    );
    assert!(b.is_latched());
}

#[test]
fn corrupt_epoch_boolean_denies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.db");
    let key = IssuerSigningKey::generate();
    {
        let mut store = DurableStore::create(&path).unwrap();
        store.initialize_trust(&binding_for(&key)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Rebuild epoch_state without CHECK so a corrupt boolean can be stored.
        conn.execute_batch(
            "DROP TABLE epoch_state;
             CREATE TABLE epoch_state (id INTEGER PRIMARY KEY, closed INTEGER NOT NULL, closed_at INTEGER, close_reason TEXT);
             INSERT INTO epoch_state (id, closed, closed_at, close_reason) VALUES (1, 7, NULL, 'corrupt');",
        )
        .unwrap();
    }
    match DurableStore::open(&path) {
        Err(_) => {}
        Ok(mut store) => {
            assert!(store.is_latched() || store.is_epoch_closed().is_err());
        }
    }
}

#[test]
fn issue_record_binds_full_credential() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    let rec = f.store.get_issued(&f.intent).unwrap().unwrap();
    assert_eq!(
        rec.nonce_hex,
        hex::encode(issued.grant.fields.session_nonce.as_bytes())
    );
    assert_eq!(rec.body_hash_hex, issued.body_hash_hex);
    assert_eq!(rec.computer_id, "room7-a03");
    assert_eq!(rec.account_id, "acct-42");
    assert_eq!(rec.manager_id, "mgr-7");
    assert_eq!(rec.desktop_generation, 3);
    assert_eq!(rec.issuer_generation, 1);
    assert_eq!(rec.intent_id, f.intent);
}

#[test]
fn clock_rollback_auto_latches() {
    let mut f = fixture_memory(1_500);
    let issued = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, &f.intent)
        .unwrap();
    let clock = ManualEpochClock::new(1_500);
    let _ = clock.now_ms().unwrap();
    clock.set(1_000);
    let ctrl = AdmissionController::try_new(binding_for(&f.key), Box::new(clock)).unwrap();
    assert_eq!(
        ctrl.admit(
            &issued.grant,
            Operation::Observe,
            &receiver(),
            &mut f.store,
            &issued.intent_id
        ),
        AdmissionDecision::Denied(DenyReason::ClockFault)
    );
    assert!(f.store.is_latched());
}

#[test]
fn manual_clock_overflow_no_wrap() {
    let clock = ManualEpochClock::new(u64::MAX - 1);
    assert!(matches!(
        clock.advance(5),
        Err(ClockError::CounterExhausted)
    ));
}

#[test]
fn public_read_lock_fault_latches_after_lock_release_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut f, path) = fixture_file(dir.path(), 1_500);
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let result = f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, "read-lock");
    assert!(result.is_err());
    blocker.execute_batch("ROLLBACK").unwrap();
    assert!(
        f.store.is_latched(),
        "required read fault must automatically latch"
    );
    let mut reopened = DurableStore::open(&path).unwrap();
    assert!(
        reopened.is_latched(),
        "reopened handle must see durable latch"
    );
    assert!(f
        .ctrl
        .issue(fields(1_500), &f.key, &mut reopened, "after-read-lock")
        .is_err());
}

#[test]
fn missing_fault_row_observed_by_public_issue_cannot_be_healed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut f, path) = fixture_file(dir.path(), 1_500);
    let outsider = rusqlite::Connection::open(&path).unwrap();
    outsider
        .execute("DELETE FROM fault_state WHERE id = 1", [])
        .unwrap();
    assert!(f
        .ctrl
        .issue(fields(1_500), &f.key, &mut f.store, "missing-fault")
        .is_err());
    outsider
        .execute(
            "INSERT OR REPLACE INTO fault_state VALUES (1, 0, 'healthy', 0)",
            [],
        )
        .unwrap();
    let mut reopened = DurableStore::open(&path).unwrap();
    assert!(
        reopened.is_latched(),
        "observed corruption must leave a durable latch"
    );
    assert!(f
        .ctrl
        .issue(fields(1_500), &f.key, &mut reopened, "after-corruption")
        .is_err());
}

#[test]
fn required_format_marker_checked_at_public_issue_boundary() {
    for mutation in [
        "DELETE FROM store_format",
        "UPDATE store_format SET initialized = 0",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (mut f, path) = fixture_file(dir.path(), 1_500);
        let outsider = rusqlite::Connection::open(&path).unwrap();
        outsider.execute_batch(mutation).unwrap();
        assert!(
            f.ctrl
                .issue(fields(1_500), &f.key, &mut f.store, "corrupt-format")
                .is_err(),
            "required format corruption accepted: {mutation}"
        );
        assert!(f.store.is_latched());
    }
}

#[test]
fn public_intents_are_bounded_and_nonempty() {
    let mut f = fixture_memory(1_500);
    for intent in [
        String::new(),
        "x".repeat(MAX_ID_LEN + 1),
        "bad\nintent".to_string(),
    ] {
        assert!(f
            .ctrl
            .issue(fields(1_500), &f.key, &mut f.store, &intent)
            .is_err());
        assert!(!f.store.is_latched(), "invalid input is a logical denial");
    }
}
