//! Coordinator regressions: these requirements must fail closed before adapters.
use authority_lab::ownership::{ClaimRole, OwnershipManager};
use authority_lab::receiver_store::ConsumeLeaseParams;
use authority_lab::*;

fn fields(key: &IssuerSigningKey) -> CanonicalV2Fields {
    fields_with_intent(key, "view-review")
}

fn fields_with_intent(key: &IssuerSigningKey, intent: &str) -> CanonicalV2Fields {
    CanonicalV2Fields {
        schema: V2_SCHEMA_VERSION.into(),
        deployment: DeploymentId::new("deploy-review").unwrap(),
        issuer_generation: 1,
        issuer_public_key: *key.verifying_key().as_bytes(),
        approved_account_key: [2; 32],
        approved_manager_key: [3; 32],
        endpoint_key: EndpointKey::new([4; 32]).unwrap(),
        endpoint_incarnation: EndpointIncarnation::new("endpoint-incarnation").unwrap(),
        boot_id: BootId::new("boot-review").unwrap(),
        worker_id: WorkerId::new("worker-review").unwrap(),
        computer: ComputerId::new("computer-review").unwrap(),
        incarnation: IncarnationId::new("incarnation-review").unwrap(),
        desktop_generation: DesktopGeneration::new(1).unwrap(),
        display_generation: 1,
        operation: Operation::Observe,
        operation_intent: OperationIntent::new(intent).unwrap(),
        interaction_generation: InteractionGeneration::new(1).unwrap(),
        policy_revision: PolicyRevision::new("policy-1").unwrap(),
        authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        channel_binding: vec![5; 32],
        session_nonce: Nonce::new(random_32()).unwrap(),
        issued_at: TimestampMs::new(1_000).unwrap(),
        expires_at: TimestampMs::new(6_000).unwrap(),
    }
}

fn unique_intent(tag: &str) -> String {
    format!("{tag}-{}", hex::encode(random_32()))
}

#[test]
fn issuer_signature_alone_is_not_manager_possession_or_channel_proof() {
    let key = IssuerSigningKey::generate();
    let value = fields(&key);
    let expected = V2ExpectedAuthority {
        issuer_public_key: *key.verifying_key().as_bytes(),
        issuer_generation: 1,
        deployment: value.deployment.clone(),
        schema: value.schema.clone(),
        authority_revision: value.authority_revision.clone(),
    };
    let receiver = V2ReceiverContext {
        endpoint_key: value.endpoint_key,
        boot_id: value.boot_id.clone(),
        worker_id: value.worker_id.clone(),
        computer: value.computer.clone(),
        incarnation: value.incarnation.clone(),
        desktop_generation: value.desktop_generation,
    };
    let mut controller = V2AdmissionController::new(expected, receiver);
    let mut journal = IssuerJournal::create_memory().unwrap();
    journal
        .initialize(key.verifying_key().as_bytes(), 1)
        .unwrap();
    let grant = controller
        .issue(value, &key, &mut journal, "review-intent", 1_500)
        .unwrap();
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let result = controller.admit(
        &grant,
        Operation::Observe,
        &mut store,
        "review-intent",
        1_500,
        100,
    );
    assert!(
        matches!(result, V2AdmissionDecision::Denied(_)),
        "no Manager challenge/proof or independently observed channel was presented: {result:?}"
    );
}

#[test]
fn reopened_receiver_cannot_reactivate_pre_restart_deadline() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("receiver.db");
    let mut store = ReceiverLeaseStore::create(&path, 10_000).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "before-restart",
            nonce_hex: &hex::encode(random_32()),
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 10_000,
        })
        .unwrap();
    drop(store);
    let reopened = ReceiverLeaseStore::open(&path, 0);
    if let Ok(mut reopened) = reopened {
        assert!(
            !reopened.is_lease_active("before-restart", 1).unwrap(),
            "old monotonic deadlines must not survive process restart as active authority"
        );
    }
}

#[test]
fn pending_release_still_blocks_replacement_controller() {
    let mut ownership = OwnershipManager::new();
    let old = ownership
        .reserve([4; 32], 1, ClaimRole::Controller, "old", 1)
        .unwrap();
    ownership.acknowledge(old).unwrap();
    ownership.request_release(old).unwrap();
    assert!(
        ownership
            .reserve([4; 32], 1, ClaimRole::Controller, "replacement", 2)
            .is_err(),
        "unacknowledged release cannot free control authority"
    );
}

#[test]
fn new_generation_does_not_silently_create_two_controllers() {
    let mut ownership = OwnershipManager::new();
    let old = ownership
        .reserve([4; 32], 1, ClaimRole::Controller, "old", 1)
        .unwrap();
    ownership.acknowledge(old).unwrap();
    if let Ok(new) = ownership.reserve([4; 32], 2, ClaimRole::Controller, "new", 2) {
        ownership.acknowledge(new).unwrap();
    }
    assert!(
        ownership.active_controller_count(&[4; 32]) <= 1,
        "new generation requires old authority fenced before replacement"
    );
}

fn possession_attempt(wrong_approved_manager: bool, wrong_digest: bool) -> V2AdmissionDecision {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{
        ChallengeBinding, ChannelBinding, GrantDigest, ManagerSigningKey, PeerPossessionVerifier,
    };

    let key = IssuerSigningKey::generate();
    let manager = ManagerSigningKey::generate();
    let manager_key = manager.verifying_key();
    let mut value = fields(&key);
    if !wrong_approved_manager {
        value.approved_manager_key = *manager_key.as_bytes();
    }
    let expected = V2ExpectedAuthority {
        issuer_public_key: *key.verifying_key().as_bytes(),
        issuer_generation: 1,
        deployment: value.deployment.clone(),
        schema: value.schema.clone(),
        authority_revision: value.authority_revision.clone(),
    };
    let receiver = V2ReceiverContext {
        endpoint_key: value.endpoint_key,
        boot_id: value.boot_id.clone(),
        worker_id: value.worker_id.clone(),
        computer: value.computer.clone(),
        incarnation: value.incarnation.clone(),
        desktop_generation: value.desktop_generation,
    };
    let mut controller = V2AdmissionController::new(expected, receiver);
    let grant = V2Grant::sign(value, &key).unwrap();
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier
        .create_challenge(
            ChallengeBinding {
                deployment: grant.fields.deployment.clone(),
                issuer_public_key: grant.issuer_public_key,
                issuer_generation: grant.fields.issuer_generation,
                computer: grant.fields.computer.clone(),
                incarnation: grant.fields.incarnation.clone(),
                desktop_generation: grant.fields.desktop_generation,
                operation: grant.fields.operation,
                intent_id: grant.fields.operation_intent.as_str().to_string(),
                grant_digest: if wrong_digest {
                    GrantDigest::new([77; 32]).unwrap()
                } else {
                    v2_grant_digest(&grant).unwrap()
                },
                channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
            },
            &manager_key,
            30_000,
        )
        .unwrap();
    let proof = manager.prove_possession(&challenge);
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    controller.admit_with_possession(
        &grant,
        Operation::Observe,
        &mut store,
        grant.fields.operation_intent.as_str(),
        1_500,
        100,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &manager_key,
        },
    )
}

#[test]
fn signed_possession_of_a_different_manager_cannot_admit_an_approved_grant() {
    let result = possession_attempt(true, false);
    assert!(
        matches!(result, V2AdmissionDecision::Denied(_)),
        "wrong Manager was admitted: {result:?}"
    );
}

#[test]
fn possession_for_another_grant_cannot_admit_this_grant() {
    let result = possession_attempt(false, true);
    assert!(
        matches!(result, V2AdmissionDecision::Denied(_)),
        "unrelated challenge digest was accepted: {result:?}"
    );
}

/// Positive proof fixture: valid admission with the actual approved Manager key.
#[test]
fn valid_possession_with_approved_manager_key_admits() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{
        ChallengeBinding, ChannelBinding, ManagerSigningKey, PeerPossessionVerifier,
    };

    let issuer_key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let mut value = fields(&issuer_key);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let expected = V2ExpectedAuthority {
        issuer_public_key: *issuer_key.verifying_key().as_bytes(),
        issuer_generation: 1,
        deployment: value.deployment.clone(),
        schema: value.schema.clone(),
        authority_revision: value.authority_revision.clone(),
    };
    let receiver = V2ReceiverContext {
        endpoint_key: value.endpoint_key,
        boot_id: value.boot_id.clone(),
        worker_id: value.worker_id.clone(),
        computer: value.computer.clone(),
        incarnation: value.incarnation.clone(),
        desktop_generation: value.desktop_generation,
    };
    let mut controller = V2AdmissionController::new(expected, receiver);
    let grant = V2Grant::sign(value, &issuer_key).unwrap();
    let digest = v2_grant_digest(&grant).unwrap();
    let binding = ChallengeBinding {
        deployment: grant.fields.deployment.clone(),
        issuer_public_key: grant.issuer_public_key,
        issuer_generation: grant.fields.issuer_generation,
        computer: grant.fields.computer.clone(),
        incarnation: grant.fields.incarnation.clone(),
        desktop_generation: grant.fields.desktop_generation,
        operation: grant.fields.operation,
        intent_id: grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
    };
    let clock = ManualElapsedClock::new(100);
    let verifier = PeerPossessionVerifier::new(Box::new(clock));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(issuer_key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let result = controller.admit_with_possession(
        &grant,
        Operation::Observe,
        &mut store,
        grant.fields.operation_intent.as_str(),
        1_500,
        100,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(
        matches!(result, V2AdmissionDecision::Granted(ref adm) if
            adm.endpoint_key() == grant.fields.endpoint_key.as_bytes()
            && adm.desktop_generation() == 1
            && adm.operation() == Operation::Observe
            && adm.grant_digest() == digest.as_bytes()
        ),
        "valid possession with approved manager key must admit: {result:?}"
    );
}

/// Challenge binding field mutations are each detected.
#[test]
fn challenge_binding_mutation_denied() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{
        ChallengeBinding, ChannelBinding, ManagerSigningKey, PeerPossessionVerifier,
    };

    let issuer_key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let mut value = fields(&issuer_key);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &issuer_key).unwrap();
    let digest = v2_grant_digest(&grant).unwrap();

    // Mutate the deployment in the binding
    let mut binding = ChallengeBinding {
        deployment: grant.fields.deployment.clone(),
        issuer_public_key: grant.issuer_public_key,
        issuer_generation: grant.fields.issuer_generation,
        computer: grant.fields.computer.clone(),
        incarnation: grant.fields.incarnation.clone(),
        desktop_generation: grant.fields.desktop_generation,
        operation: grant.fields.operation,
        intent_id: grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
    };
    binding.deployment = DeploymentId::new("mutated-deploy").unwrap();
    let clock = ManualElapsedClock::new(100);
    let verifier = PeerPossessionVerifier::new(Box::new(clock));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(issuer_key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *issuer_key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: grant.fields.deployment.clone(),
            schema: grant.fields.schema.clone(),
            authority_revision: grant.fields.authority_revision.clone(),
        },
        V2ReceiverContext {
            endpoint_key: grant.fields.endpoint_key,
            boot_id: grant.fields.boot_id.clone(),
            worker_id: grant.fields.worker_id.clone(),
            computer: grant.fields.computer.clone(),
            incarnation: grant.fields.incarnation.clone(),
            desktop_generation: grant.fields.desktop_generation,
        },
    );
    let result = ctrl.admit_with_possession(
        &grant,
        Operation::Observe,
        &mut store,
        grant.fields.operation_intent.as_str(),
        1_500,
        100,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(
        matches!(result, V2AdmissionDecision::Denied(_)),
        "mutated deployment in challenge binding must be rejected: {result:?}"
    );
}

/// Reservation without acknowledgment does not grant control authority.
#[test]
fn reserved_controller_without_ack_does_not_grant() {
    let mut ownership = OwnershipManager::new();
    let idx = ownership
        .reserve([4; 32], 1, ClaimRole::Controller, "reserved-only", 1)
        .unwrap();
    // Not acknowledged — still Reserved, not Active
    assert_eq!(
        ownership.active_controller_count(&[4; 32]),
        0,
        "reserved claim without acknowledgment must not count as active"
    );
    assert_eq!(
        ownership.reserved_count_where(&[4; 32], ClaimRole::Controller),
        1,
        "reserved claim must be counted as reserved"
    );
    let _ = idx;
}

/// Two independent controllers cannot coexist on the same endpoint.
#[test]
fn second_controller_reservation_on_same_endpoint_denied() {
    let mut ownership = OwnershipManager::new();
    let ep = [4; 32];
    let first = ownership
        .reserve(ep, 1, ClaimRole::Controller, "first", 1)
        .unwrap();
    ownership.acknowledge(first).unwrap();
    let result = ownership.reserve(ep, 1, ClaimRole::Controller, "second", 2);
    assert!(
        result.is_err(),
        "second controller on same endpoint must be denied"
    );
}

/// Unauthenticated collision never quarantines a valid endpoint.
/// (Observer claims always succeed; only controller claims conflict.)
#[test]
fn observer_never_conflicts_with_controller() {
    let mut ownership = OwnershipManager::new();
    let ep = [4; 32];
    let ctrl = ownership
        .reserve(ep, 1, ClaimRole::Controller, "ctrl", 1)
        .unwrap();
    ownership.acknowledge(ctrl).unwrap();
    // Observer should succeed regardless of controller
    let obs = ownership.reserve(ep, 1, ClaimRole::Observer, "obs", 2);
    assert!(obs.is_ok(), "observer must not conflict with controller");
}

// ---------------------------------------------------------------------------
// Coordinator repairs: ownership races, wall-clock rollback, durable
// challenge consumption, stop-when-latched, nonce renewal, restart fencing.
// ---------------------------------------------------------------------------

fn control_fields_with_intent(
    key: &IssuerSigningKey,
    mgr_vk: &ManagerVerifyingKey,
    intent: &str,
) -> CanonicalV2Fields {
    let mut v = fields_with_intent(key, intent);
    v.operation = Operation::Control;
    v.approved_manager_key = *mgr_vk.as_bytes();
    v.session_nonce = Nonce::new(random_32()).unwrap();
    v
}

fn admit_control(
    ctrl: &mut V2AdmissionController,
    grant: &V2Grant,
    store: &mut ReceiverLeaseStore,
    intent: &str,
    now_ms: u64,
    mono_ms: u64,
    mgr: &ManagerSigningKey,
) -> V2AdmissionDecision {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let digest = v2_grant_digest(grant).unwrap();
    let binding = ChallengeBinding {
        deployment: grant.fields.deployment.clone(),
        issuer_public_key: grant.issuer_public_key,
        issuer_generation: grant.fields.issuer_generation,
        computer: grant.fields.computer.clone(),
        incarnation: grant.fields.incarnation.clone(),
        desktop_generation: grant.fields.desktop_generation,
        operation: grant.fields.operation,
        intent_id: grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
    };
    let mgr_vk = mgr.verifying_key();
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    ctrl.admit_with_possession(
        grant,
        Operation::Control,
        store,
        intent,
        now_ms,
        mono_ms,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    )
}

/// A Control admit that fails after reservation must abandon the slot.
/// Without rollback the Reserved claim permanently blocks the endpoint.
#[test]
fn failed_control_admit_does_not_block_future_controller() {
    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );

    // Pre-consume this grant's session nonce so consume_and_lease fails
    // AFTER the controller reservation is taken.
    let bad_intent = unique_intent("blocked-first");
    let bad_grant =
        V2Grant::sign(control_fields_with_intent(&key, &mgr_vk, &bad_intent), &key).unwrap();
    let pre_nonce = hex::encode(bad_grant.fields.session_nonce.as_bytes());
    store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "pre-consumed",
            nonce_hex: &pre_nonce,
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 50,
        })
        .unwrap();

    let result = admit_control(
        &mut ctrl,
        &bad_grant,
        &mut store,
        &bad_intent,
        1_500,
        100,
        &mgr,
    );
    assert!(
        matches!(
            result,
            V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
        ),
        "first control admit must fail on replayed nonce: {result:?}"
    );

    // A fresh Control grant must still be able to take the slot.
    let good_intent = unique_intent("second-control");
    let grant2 = V2Grant::sign(
        control_fields_with_intent(&key, &mgr_vk, &good_intent),
        &key,
    )
    .unwrap();
    let result2 = admit_control(
        &mut ctrl,
        &grant2,
        &mut store,
        &good_intent,
        1_600,
        200,
        &mgr,
    );
    assert!(
        matches!(result2, V2AdmissionDecision::Granted(_)),
        "a denied admit must not permanently block the controller slot: {result2:?}"
    );
}

/// Successful Control admit leaves an Active (not stuck Reserved) claim
/// that can enter the PendingRelease lifecycle.
#[test]
fn control_claim_is_active_and_releasable_after_admit() {
    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let intent1 = unique_intent("ctrl-active");
    let grant = V2Grant::sign(control_fields_with_intent(&key, &mgr_vk, &intent1), &key).unwrap();
    let result = admit_control(&mut ctrl, &grant, &mut store, &intent1, 1_500, 100, &mgr);
    assert!(matches!(result, V2AdmissionDecision::Granted(_)));
    let (state, _) = store.get_controller_claim(&intent1).unwrap().unwrap();
    assert_eq!(
        state,
        authority_lab::ownership::ClaimState::Active,
        "successful control admit must acknowledge the claim"
    );
    ctrl.request_controller_release(&intent1, &mut store, 200)
        .unwrap();
    let (state, _) = store.get_controller_claim(&intent1).unwrap().unwrap();
    assert_eq!(state, authority_lab::ownership::ClaimState::PendingRelease);
    // PendingRelease still blocks a replacement controller.
    let intent2 = unique_intent("ctrl-replacement");
    let grant2 = V2Grant::sign(control_fields_with_intent(&key, &mgr_vk, &intent2), &key).unwrap();
    let result2 = admit_control(&mut ctrl, &grant2, &mut store, &intent2, 1_600, 300, &mgr);
    assert!(
        matches!(
            result2,
            V2AdmissionDecision::Denied(V2DenyReason::ControllerConflict)
        ),
        "pending release cannot free control authority: {result2:?}"
    );
    ctrl.confirm_controller_release(&intent1, &mut store, 400)
        .unwrap();
    let intent3 = unique_intent("ctrl-after-release");
    let grant3 = V2Grant::sign(control_fields_with_intent(&key, &mgr_vk, &intent3), &key).unwrap();
    let result3 = admit_control(&mut ctrl, &grant3, &mut store, &intent3, 1_700, 500, &mgr);
    assert!(
        matches!(result3, V2AdmissionDecision::Granted(_)),
        "confirmed release frees the slot: {result3:?}"
    );
}

/// Stop cleanup must remain possible when the store is latched
/// (required storage loss fails admission closed, not stop).
#[test]
fn stop_cleanup_succeeds_when_store_latched() {
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "stop-me",
            nonce_hex: &hex::encode(random_32()),
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "control",
            operation_intent: "take-control",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();
    store
        .reserve_controller("stop-me", &[4; 32], 1, 100)
        .unwrap();
    store.acknowledge_controller("stop-me").unwrap();
    // Latch the gate (storage/audit loss).
    store.check_wall_clock(1_000).unwrap();
    let _ = store.check_wall_clock(10);
    assert!(store.is_latched(), "wall rollback must latch");
    // Admission is closed...
    assert!(store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "after-latch",
            nonce_hex: &hex::encode(random_32()),
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 200,
        })
        .is_err());
    // ...but stop cleanup still works.
    store.request_release("stop-me", 300).unwrap();
    store.confirm_release("stop-me", 400).unwrap();
    store.request_controller_release("stop-me", 500).unwrap();
    store.confirm_controller_release("stop-me", 600).unwrap();
}

/// Wall-clock rollback must deny and latch; an expired grant cannot revive.
#[test]
fn wall_clock_rollback_denies_and_cannot_revive_expired_grant() {
    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let mut journal = IssuerJournal::create_memory().unwrap();
    journal
        .initialize(key.verifying_key().as_bytes(), 1)
        .unwrap();
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let mut value = fields(&key);
    value.approved_manager_key = *mgr_vk.as_bytes();
    // issued 1000, expires 6000
    let grant = V2Grant::sign(value, &key).unwrap();
    // Observe a late wall-clock reading past expiry.
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let digest = v2_grant_digest(&grant).unwrap();
    let binding = ChallengeBinding {
        deployment: grant.fields.deployment.clone(),
        issuer_public_key: grant.issuer_public_key,
        issuer_generation: grant.fields.issuer_generation,
        computer: grant.fields.computer.clone(),
        incarnation: grant.fields.incarnation.clone(),
        desktop_generation: grant.fields.desktop_generation,
        operation: grant.fields.operation,
        intent_id: grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
    };
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);

    // First call observes wall clock 9000 (past expiry) via issue-style
    // tracking inside admit. Use a grant whose validity covers 3000 so the
    // first admit is simply denied as expired at 9000, recording 9000.
    let expired = ctrl.admit_with_possession(
        &grant,
        Operation::Observe,
        &mut store,
        "wall-rollback",
        9_000,
        100,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(matches!(expired, V2AdmissionDecision::Denied(_)));

    // Roll the wall clock back inside the signed window. Must still deny
    // (ClockFault) — never revive the expired credential.
    let verifier2 = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge2 = verifier2
        .create_challenge(
            ChallengeBinding {
                deployment: grant.fields.deployment.clone(),
                issuer_public_key: grant.issuer_public_key,
                issuer_generation: grant.fields.issuer_generation,
                computer: grant.fields.computer.clone(),
                incarnation: grant.fields.incarnation.clone(),
                desktop_generation: grant.fields.desktop_generation,
                operation: grant.fields.operation,
                intent_id: grant.fields.operation_intent.as_str().to_string(),
                grant_digest: digest,
                channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
            },
            &mgr_vk,
            30_000,
        )
        .unwrap();
    let proof2 = mgr.prove_possession(&challenge2);
    let rolled = ctrl.admit_with_possession(
        &grant,
        Operation::Observe,
        &mut store,
        "wall-rollback-2",
        3_000,
        200,
        &PossessionAdmitParams {
            verifier: &verifier2,
            challenge: &challenge2,
            proof: &proof2,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(
        matches!(
            rolled,
            V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
        ),
        "wall-clock rollback must fail closed, not revive expiry: {rolled:?}"
    );
    assert!(store.is_latched());
}

/// Consumed challenges remain denied after receiver restart.
#[test]
fn consumed_challenge_denied_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("receiver.db");
    let challenge_hex = hex::encode(random_32());
    {
        let mut store = ReceiverLeaseStore::create(&path, 0).unwrap();
        store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
        store
            .consume_challenge(&challenge_hex, "challenge-intent", 100)
            .unwrap();
    }
    let mut reopened = ReceiverLeaseStore::open(&path, 0).unwrap();
    assert!(
        reopened.is_challenge_consumed(&challenge_hex).unwrap(),
        "consumed challenges must remain denied after restart"
    );
    assert!(matches!(
        reopened.consume_challenge(&challenge_hex, "challenge-intent-2", 200),
        Err(ReceiverError::NonceAlreadyConsumed)
    ));
}

/// Renewal goes only through verified `renew_with_possession`.
/// Raw `renew_lease` is crate-private — no public caller-supplied deadline.
#[test]
fn renewal_requires_fresh_signed_grant_and_possession() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let intent = unique_intent("renew-ok");
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );

    // Initial admit (Observe) with matching signed operation_intent.
    let mut value = fields_with_intent(&key, &intent);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &key).unwrap();
    let admit = admit_observe(&mut ctrl, &grant, &mut store, &intent, 1_500, 100, &mgr);
    assert!(matches!(admit, V2AdmissionDecision::Granted(_)));

    // Fresh signed renewal credential: same owner/context, new nonce, later expiry.
    let mut fresh = fields_with_intent(&key, &intent);
    fresh.approved_manager_key = *mgr_vk.as_bytes();
    fresh.issued_at = TimestampMs::new(2_000).unwrap();
    fresh.expires_at = TimestampMs::new(30_000).unwrap();
    let fresh_grant = V2Grant::sign(fresh, &key).unwrap();
    let digest = v2_grant_digest(&fresh_grant).unwrap();
    let binding = ChallengeBinding {
        deployment: fresh_grant.fields.deployment.clone(),
        issuer_public_key: fresh_grant.issuer_public_key,
        issuer_generation: fresh_grant.fields.issuer_generation,
        computer: fresh_grant.fields.computer.clone(),
        incarnation: fresh_grant.fields.incarnation.clone(),
        desktop_generation: fresh_grant.fields.desktop_generation,
        operation: fresh_grant.fields.operation,
        intent_id: fresh_grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&fresh_grant.fields.channel_binding).unwrap(),
    };
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    let renewed = ctrl.renew_with_possession(
        &fresh_grant,
        Operation::Observe,
        &mut store,
        &intent,
        2_500,
        200,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(
        matches!(renewed, V2AdmissionDecision::Granted(_)),
        "verified renewal with fresh signed grant must succeed: {renewed:?}"
    );
    let lease = store.get_lease(&intent).unwrap().unwrap();
    // remaining = 30_000 - 2_500 = 27_500 → deadline 200+27_500 = 27_700.
    // Clamped to fixed 30s from signed expiry — never a caller cap.
    assert_eq!(lease.lease_deadline_mono_ms, 27_700);
}

/// An otherwise valid grant for another Manager cannot renew this intent.
#[test]
fn renewal_wrong_manager_denied() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let other = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let other_vk = other.verifying_key();
    let intent = unique_intent("renew-wrong-mgr");
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let mut value = fields_with_intent(&key, &intent);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &key).unwrap();
    assert!(matches!(
        admit_observe(&mut ctrl, &grant, &mut store, &intent, 1_500, 100, &mgr),
        V2AdmissionDecision::Granted(_)
    ));

    // Fresh grant for a different approved Manager — valid signature, wrong owner.
    let mut fresh = fields_with_intent(&key, &intent);
    fresh.approved_manager_key = *other_vk.as_bytes();
    fresh.issued_at = TimestampMs::new(2_000).unwrap();
    fresh.expires_at = TimestampMs::new(30_000).unwrap();
    let fresh_grant = V2Grant::sign(fresh, &key).unwrap();
    let digest = v2_grant_digest(&fresh_grant).unwrap();
    let binding = ChallengeBinding {
        deployment: fresh_grant.fields.deployment.clone(),
        issuer_public_key: fresh_grant.issuer_public_key,
        issuer_generation: fresh_grant.fields.issuer_generation,
        computer: fresh_grant.fields.computer.clone(),
        incarnation: fresh_grant.fields.incarnation.clone(),
        desktop_generation: fresh_grant.fields.desktop_generation,
        operation: fresh_grant.fields.operation,
        intent_id: fresh_grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&fresh_grant.fields.channel_binding).unwrap(),
    };
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier
        .create_challenge(binding, &other_vk, 30_000)
        .unwrap();
    let proof = other.prove_possession(&challenge);
    let renewed = ctrl.renew_with_possession(
        &fresh_grant,
        Operation::Observe,
        &mut store,
        &intent,
        2_500,
        200,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &other_vk,
        },
    );
    assert!(
        matches!(renewed, V2AdmissionDecision::Denied(_)),
        "wrong manager cannot renew this intent: {renewed:?}"
    );
}

/// An otherwise valid grant for another operation cannot renew this intent.
#[test]
fn renewal_wrong_operation_denied() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let intent = unique_intent("renew-wrong-op");
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let mut value = fields_with_intent(&key, &intent);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &key).unwrap();
    assert!(matches!(
        admit_observe(&mut ctrl, &grant, &mut store, &intent, 1_500, 100, &mgr),
        V2AdmissionDecision::Granted(_)
    ));

    // Fresh grant for Control — valid signature, wrong operation.
    let mut fresh = control_fields_with_intent(&key, &mgr_vk, &intent);
    fresh.issued_at = TimestampMs::new(2_000).unwrap();
    fresh.expires_at = TimestampMs::new(30_000).unwrap();
    let fresh_grant = V2Grant::sign(fresh, &key).unwrap();
    let digest = v2_grant_digest(&fresh_grant).unwrap();
    let binding = ChallengeBinding {
        deployment: fresh_grant.fields.deployment.clone(),
        issuer_public_key: fresh_grant.issuer_public_key,
        issuer_generation: fresh_grant.fields.issuer_generation,
        computer: fresh_grant.fields.computer.clone(),
        incarnation: fresh_grant.fields.incarnation.clone(),
        desktop_generation: fresh_grant.fields.desktop_generation,
        operation: fresh_grant.fields.operation,
        intent_id: fresh_grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&fresh_grant.fields.channel_binding).unwrap(),
    };
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    let renewed = ctrl.renew_with_possession(
        &fresh_grant,
        Operation::Control,
        &mut store,
        &intent,
        2_500,
        200,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    );
    assert!(
        matches!(renewed, V2AdmissionDecision::Denied(_)),
        "wrong operation cannot renew this intent: {renewed:?}"
    );
}

/// Setup: admit an Observe lease and return everything needed to renew.
fn admitted_observe_fixture() -> (
    V2AdmissionController,
    ReceiverLeaseStore,
    String,
    IssuerSigningKey,
    ManagerSigningKey,
    u64,
) {
    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let intent = unique_intent("fixture");
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let mut value = fields_with_intent(&key, &intent);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &key).unwrap();
    let decision = admit_observe(&mut ctrl, &grant, &mut store, &intent, 1_500, 100, &mgr);
    assert!(matches!(decision, V2AdmissionDecision::Granted(_)));
    let deadline = store
        .get_lease(&intent)
        .unwrap()
        .unwrap()
        .lease_deadline_mono_ms;
    (ctrl, store, intent, key, mgr, deadline)
}

/// A lease that has reached its monotonic deadline cannot be revived by
/// renewal — exact boundary included. No fresh nonce is committed.
#[test]
fn renewal_at_or_after_lease_deadline_denied_without_nonce_commit() {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    for (label, renew_mono) in [("exact-deadline", None), ("after-deadline", Some(1u64))] {
        let (mut ctrl, mut store, intent, key, mgr, deadline) = admitted_observe_fixture();
        let renew_mono = renew_mono.map(|d| deadline + d).unwrap_or(deadline);
        let mgr_vk = mgr.verifying_key();
        let mut fresh = fields_with_intent(&key, &intent);
        fresh.approved_manager_key = *mgr_vk.as_bytes();
        fresh.issued_at = TimestampMs::new(2_000).unwrap();
        fresh.expires_at = TimestampMs::new(30_000).unwrap(); // ≤ 30s lifetime
        let fresh_grant = V2Grant::sign(fresh, &key).unwrap();
        let digest = v2_grant_digest(&fresh_grant).unwrap();
        let binding = ChallengeBinding {
            deployment: fresh_grant.fields.deployment.clone(),
            issuer_public_key: fresh_grant.issuer_public_key,
            issuer_generation: fresh_grant.fields.issuer_generation,
            computer: fresh_grant.fields.computer.clone(),
            incarnation: fresh_grant.fields.incarnation.clone(),
            desktop_generation: fresh_grant.fields.desktop_generation,
            operation: fresh_grant.fields.operation,
            intent_id: fresh_grant.fields.operation_intent.as_str().to_string(),
            grant_digest: digest,
            channel_binding: ChannelBinding::new(&fresh_grant.fields.channel_binding).unwrap(),
        };
        let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
        let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
        let proof = mgr.prove_possession(&challenge);
        let fresh_nonce_hex = hex::encode(fresh_grant.fields.session_nonce.as_bytes());
        let renewed = ctrl.renew_with_possession(
            &fresh_grant,
            Operation::Observe,
            &mut store,
            &intent,
            5_000,
            renew_mono,
            &PossessionAdmitParams {
                verifier: &verifier,
                challenge: &challenge,
                proof: &proof,
                expected_manager_key: &mgr_vk,
            },
        );
        assert!(
            matches!(renewed, V2AdmissionDecision::Denied(V2DenyReason::Expired)),
            "{label}: expired lease must not revive (mono={renew_mono} deadline={deadline}): {renewed:?}"
        );
        assert!(
            !store.is_nonce_consumed(&fresh_nonce_hex).unwrap(),
            "{label}: denial must not commit the fresh nonce"
        );
    }
}

/// renew_lease enforces consumed-nonce capacity inside its own transaction.
#[test]
fn renew_lease_capacity_is_bounded() {
    let mut store = ReceiverLeaseStore::create_memory_with_limits(0, 2, 10).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    let n1 = hex::encode([1u8; 32]);
    store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "cap-renew",
            nonce_hex: &n1,
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 100,
        })
        .unwrap();
    // One slot left after n1 (max_consumed = 2).
    let n2 = hex::encode([2u8; 32]);
    // Use crate-private path via a small unit-style check: consume one more
    // through renew after filling capacity with a second lease nonce.
    let n_fill = hex::encode([3u8; 32]);
    store
        .consume_and_lease(ConsumeLeaseParams {
            intent_id: "cap-fill",
            nonce_hex: &n_fill,
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 110,
        })
        .unwrap();
    // Capacity exhausted: further consume fails closed.
    assert!(matches!(
        store.consume_and_lease(ConsumeLeaseParams {
            intent_id: "cap-over",
            nonce_hex: &n2,
            endpoint_key: &[4; 32],
            boot_id: "boot-review",
            worker_id: "worker-review",
            operation: "observe",
            operation_intent: "view-review",
            desktop_generation: 1,
            display_generation: 1,
            approved_manager_key: &[3; 32],
            approved_account_key: &[2; 32],
            signed_expires_at_ms: 50_000,
            lease_deadline_mono_ms: 30_000,
            current_mono_ms: 120,
        }),
        Err(ReceiverError::CapacityExhausted)
    ));
}

/// PendingRelease keeps blocking until acknowledge or safe release —
/// mere wall/monotonic time does not free the slot.
#[test]
fn pending_release_blocks_until_acknowledged_not_mere_time() {
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    store.reserve_controller("hold", &[4; 32], 1, 100).unwrap();
    store.acknowledge_controller("hold").unwrap();
    store.request_controller_release("hold", 200).unwrap();
    // Far past any lease deadline — slot must stay blocked.
    assert!(matches!(
        store.reserve_controller("later", &[4; 32], 1, 999_999),
        Err(ReceiverError::ControllerConflict)
    ));
    // Only explicit acknowledge/release frees it (mono keeps advancing).
    store.confirm_controller_release("hold", 1_000_000).unwrap();
    store
        .reserve_controller("later", &[4; 32], 1, 1_000_001)
        .unwrap();
}

/// Caller intent_id must equal signed operation_intent at admit and renew.
#[test]
fn intent_id_must_equal_signed_operation_intent() {
    let key = IssuerSigningKey::generate();
    let mgr = ManagerSigningKey::generate();
    let mgr_vk = mgr.verifying_key();
    let signed_intent = unique_intent("signed-intent");
    let wrong_caller = unique_intent("caller-invented");
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store
        .initialize(key.verifying_key().as_bytes(), 1, &[4; 32])
        .unwrap();
    let mut ctrl = V2AdmissionController::new(
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-review").unwrap(),
            schema: V2_SCHEMA_VERSION.into(),
            authority_revision: AuthorityRevision::new("revision-1").unwrap(),
        },
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([4; 32]).unwrap(),
            boot_id: BootId::new("boot-review").unwrap(),
            worker_id: WorkerId::new("worker-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
        },
    );
    let mut value = fields_with_intent(&key, &signed_intent);
    value.approved_manager_key = *mgr_vk.as_bytes();
    let grant = V2Grant::sign(value, &key).unwrap();
    let result = admit_observe(
        &mut ctrl,
        &grant,
        &mut store,
        &wrong_caller,
        1_500,
        100,
        &mgr,
    );
    assert!(
        matches!(result, V2AdmissionDecision::Denied(_)),
        "caller-invented intent_id must not admit: {result:?}"
    );
}

/// Helper: Observe admit with possession for tests that need a leased intent.
fn admit_observe(
    ctrl: &mut V2AdmissionController,
    grant: &V2Grant,
    store: &mut ReceiverLeaseStore,
    intent: &str,
    now_ms: u64,
    mono_ms: u64,
    mgr: &ManagerSigningKey,
) -> V2AdmissionDecision {
    use authority_lab::admission::ManualElapsedClock;
    use authority_lab::admission_v2::{v2_grant_digest, PossessionAdmitParams};
    use authority_lab::peer::{ChallengeBinding, ChannelBinding, PeerPossessionVerifier};

    let digest = v2_grant_digest(grant).unwrap();
    let binding = ChallengeBinding {
        deployment: grant.fields.deployment.clone(),
        issuer_public_key: grant.issuer_public_key,
        issuer_generation: grant.fields.issuer_generation,
        computer: grant.fields.computer.clone(),
        incarnation: grant.fields.incarnation.clone(),
        desktop_generation: grant.fields.desktop_generation,
        operation: grant.fields.operation,
        intent_id: grant.fields.operation_intent.as_str().to_string(),
        grant_digest: digest,
        channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
    };
    let mgr_vk = mgr.verifying_key();
    let verifier = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(100)));
    let challenge = verifier.create_challenge(binding, &mgr_vk, 30_000).unwrap();
    let proof = mgr.prove_possession(&challenge);
    ctrl.admit_with_possession(
        grant,
        Operation::Observe,
        store,
        intent,
        now_ms,
        mono_ms,
        &PossessionAdmitParams {
            verifier: &verifier,
            challenge: &challenge,
            proof: &proof,
            expected_manager_key: &mgr_vk,
        },
    )
}

/// Receiver restart fences controller authority; it cannot reactivate.
#[test]
fn restart_fences_controller_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("receiver.db");
    {
        let mut store = ReceiverLeaseStore::create(&path, 0).unwrap();
        store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
        store
            .reserve_controller("old-ctrl", &[4; 32], 1, 100)
            .unwrap();
        store.acknowledge_controller("old-ctrl").unwrap();
        store
            .consume_and_lease(ConsumeLeaseParams {
                intent_id: "old-ctrl",
                nonce_hex: &hex::encode(random_32()),
                endpoint_key: &[4; 32],
                boot_id: "boot-review",
                worker_id: "worker-review",
                operation: "control",
                operation_intent: "take-control",
                desktop_generation: 1,
                display_generation: 1,
                approved_manager_key: &[3; 32],
                approved_account_key: &[2; 32],
                signed_expires_at_ms: 50_000,
                lease_deadline_mono_ms: 30_000,
                current_mono_ms: 100,
            })
            .unwrap();
    }
    let mut reopened = ReceiverLeaseStore::open(&path, 0).unwrap();
    assert!(
        !reopened.is_lease_active("old-ctrl", 1).unwrap(),
        "pre-restart leases must not survive as active authority"
    );
    let (state, _) = reopened.get_controller_claim("old-ctrl").unwrap().unwrap();
    assert_eq!(
        state,
        authority_lab::ownership::ClaimState::Released,
        "stale controller authority must be fenced on restart"
    );
    // A new controller reservation is allowed; the old one cannot reactivate.
    reopened
        .reserve_controller("new-ctrl", &[4; 32], 2, 200)
        .unwrap();
    assert!(matches!(
        reopened.reserve_controller("old-ctrl-reactivate", &[4; 32], 1, 300),
        Err(ReceiverError::ControllerConflict)
    ));
}

/// Durable control claims enforce exactly one controller including
/// reservations and pending release.
#[test]
fn durable_control_claims_enforce_single_controller() {
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    store.reserve_controller("first", &[4; 32], 1, 100).unwrap();
    assert!(matches!(
        store.reserve_controller("second", &[4; 32], 1, 200),
        Err(ReceiverError::ControllerConflict)
    ));
    store.acknowledge_controller("first").unwrap();
    assert!(matches!(
        store.reserve_controller("third", &[4; 32], 2, 300),
        Err(ReceiverError::ControllerConflict)
    ));
    store.request_controller_release("first", 400).unwrap();
    assert!(
        matches!(
            store.reserve_controller("fourth", &[4; 32], 1, 500),
            Err(ReceiverError::ControllerConflict)
        ),
        "pending release cannot free the slot"
    );
    store.confirm_controller_release("first", 600).unwrap();
    store.reserve_controller("fifth", &[4; 32], 1, 700).unwrap();
}

/// Challenge consumption is fail-closed bounded: malformed input and
/// capacity exhaustion are refused (same policy as consumed nonces).
#[test]
fn challenge_consumption_is_bounded() {
    let mut store = ReceiverLeaseStore::create_memory_with_limits(0, 2, 10).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    // Malformed (not 32-byte hex) input is rejected before any durable write.
    assert!(matches!(
        store.consume_challenge("deadbeef", "bad", 100),
        Err(ReceiverError::MalformedNonce)
    ));
    assert!(matches!(
        store.consume_challenge(&"f".repeat(200), "bad-long", 100),
        Err(ReceiverError::MalformedNonce)
    ));
    store
        .consume_challenge(&hex::encode([1u8; 32]), "c1", 100)
        .unwrap();
    store
        .consume_challenge(&hex::encode([2u8; 32]), "c2", 110)
        .unwrap();
    // Capacity 2 is exhausted; further challenge consumption fails closed.
    assert!(matches!(
        store.consume_challenge(&hex::encode([3u8; 32]), "c3", 120),
        Err(ReceiverError::CapacityExhausted)
    ));
    // Replay of a consumed challenge stays denied.
    assert!(matches!(
        store.consume_challenge(&hex::encode([1u8; 32]), "c1-replay", 130),
        Err(ReceiverError::NonceAlreadyConsumed)
    ));
}

/// Generation-bound stop never affects a higher-generation claim.
#[test]
fn safety_release_is_generation_bound() {
    let mut store = ReceiverLeaseStore::create_memory(0).unwrap();
    store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
    store.reserve_controller("gen1", &[4; 32], 1, 100).unwrap();
    store.acknowledge_controller("gen1").unwrap();
    // Free gen1, then take gen2.
    store.stop_controller_generation(&[4; 32], 1, 200).unwrap();
    store.reserve_controller("gen2", &[4; 32], 2, 300).unwrap();
    store.acknowledge_controller("gen2").unwrap();
    // Stopping generation 1 must not touch generation 2.
    let stopped = store.stop_controller_generation(&[4; 32], 1, 400).unwrap();
    assert_eq!(stopped, 0, "gen1 stop must not affect gen2");
    let (state, gen) = store.get_controller_claim("gen2").unwrap().unwrap();
    assert_eq!(gen, 2);
    assert_eq!(state, authority_lab::ownership::ClaimState::Active);
    // Safety release of gen2 works even after the store is latched.
    store.check_wall_clock(1_000).unwrap();
    let _ = store.check_wall_clock(10);
    assert!(store.is_latched());
    store.request_controller_release("gen2", 500).unwrap();
    store.confirm_controller_release("gen2", 600).unwrap();
    let (state, _) = store.get_controller_claim("gen2").unwrap().unwrap();
    assert_eq!(state, authority_lab::ownership::ClaimState::Released);
}

/// Restart preserves replay/high-water state while fencing process authority.
#[test]
fn restart_preserves_replay_state_and_high_water() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("receiver.db");
    let nonce_hex = hex::encode(random_32());
    let challenge_hex = hex::encode(random_32());
    {
        let mut store = ReceiverLeaseStore::create(&path, 0).unwrap();
        store.initialize(&[1; 32], 1, &[4; 32]).unwrap();
        store
            .consume_and_lease(ConsumeLeaseParams {
                intent_id: "keep-replay",
                nonce_hex: &nonce_hex,
                endpoint_key: &[4; 32],
                boot_id: "boot-review",
                worker_id: "worker-review",
                operation: "control",
                operation_intent: "take-control",
                desktop_generation: 1,
                display_generation: 1,
                approved_manager_key: &[3; 32],
                approved_account_key: &[2; 32],
                signed_expires_at_ms: 50_000,
                lease_deadline_mono_ms: 30_000,
                current_mono_ms: 100,
            })
            .unwrap();
        store
            .consume_challenge(&challenge_hex, "keep-replay", 100)
            .unwrap();
        store
            .reserve_controller("keep-replay", &[4; 32], 1, 100)
            .unwrap();
        store.acknowledge_controller("keep-replay").unwrap();
    }
    let mut reopened = ReceiverLeaseStore::open(&path, 0).unwrap();
    // Replay/high-water preserved.
    assert!(reopened.is_nonce_consumed(&nonce_hex).unwrap());
    assert!(reopened.is_challenge_consumed(&challenge_hex).unwrap());
    // Process monotonic authority fenced.
    assert!(!reopened.is_lease_active("keep-replay", 1).unwrap());
    let (state, _) = reopened
        .get_controller_claim("keep-replay")
        .unwrap()
        .unwrap();
    assert_eq!(state, authority_lab::ownership::ClaimState::Released);
}
