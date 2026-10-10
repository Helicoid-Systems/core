//! Coordinator regressions for verifier ownership and monotonic deadlines.
use authority_lab::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct ReviewClock(Arc<AtomicU64>);
impl ElapsedClock for ReviewClock {
    fn elapsed_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn binding() -> ChallengeBinding {
    ChallengeBinding {
        deployment: DeploymentId::new("deploy-review").unwrap(),
        issuer_public_key: *IssuerSigningKey::generate().verifying_key().as_bytes(),
        issuer_generation: 1,
        computer: ComputerId::new("computer-review").unwrap(),
        incarnation: IncarnationId::new("incarnation-review").unwrap(),
        desktop_generation: DesktopGeneration::new(1).unwrap(),
        operation: Operation::Observe,
        intent_id: "intent-review".into(),
        grant_digest: GrantDigest::new([7; 32]).unwrap(),
        channel_binding: ChannelBinding::new(b"channel-review").unwrap(),
    }
}
#[test]
fn challenge_cannot_move_to_a_different_verifier_clock() {
    let key = ManagerSigningKey::generate();
    let time = Arc::new(AtomicU64::new(1000));
    let origin = PeerPossessionVerifier::new(Box::new(ReviewClock(time.clone())));
    let challenge = origin
        .create_challenge(binding(), &key.verifying_key(), 100)
        .unwrap();
    let proof = key.prove_possession(&challenge);
    time.store(1100, Ordering::SeqCst);
    assert!(origin.verify_possession(&challenge, &proof).is_err());
    let replacement = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(1000)));
    assert!(
        replacement.verify_possession(&challenge, &proof).is_err(),
        "another verifier must not rewind a challenge deadline"
    );
}
#[test]
fn backward_elapsed_time_cannot_accept_a_challenge() {
    let key = ManagerSigningKey::generate();
    let time = Arc::new(AtomicU64::new(1000));
    let verifier = PeerPossessionVerifier::new(Box::new(ReviewClock(time.clone())));
    let challenge = verifier
        .create_challenge(binding(), &key.verifying_key(), 100)
        .unwrap();
    let proof = key.prove_possession(&challenge);
    time.store(999, Ordering::SeqCst);
    assert!(
        verifier.verify_possession(&challenge, &proof).is_err(),
        "clock rollback must fail closed"
    );
}

#[test]
fn exact_grant_digest_binds_signature_and_issuer_key() {
    let issuer = IssuerSigningKey::generate();
    let grant = Grant {
        fields: CanonicalFields {
            schema: SCHEMA_VERSION.into(),
            deployment: DeploymentId::new("deploy-review").unwrap(),
            issuer_generation: 1,
            authority_revision: AuthorityRevision::new("rev-review").unwrap(),
            computer: ComputerId::new("computer-review").unwrap(),
            incarnation: IncarnationId::new("incarnation-review").unwrap(),
            account: AccountId::new("account-review").unwrap(),
            manager: ManagerId::new("manager-review").unwrap(),
            action_scope: ActionScope::observe_only(),
            desktop_generation: DesktopGeneration::new(1).unwrap(),
            session_nonce: Nonce::new([5; 32]).unwrap(),
            issued_at: TimestampMs::new(1000).unwrap(),
            expires_at: TimestampMs::new(2000).unwrap(),
        },
        signature: [6; 64],
        issuer_public_key: *issuer.verifying_key().as_bytes(),
    };
    let original = GrantDigest::of_grant(&grant).unwrap();
    let mut changed = grant.clone();
    changed.signature[0] ^= 1;
    assert_ne!(
        original,
        GrantDigest::of_grant(&changed).unwrap(),
        "exact grant digest must bind signature bytes"
    );
    changed = grant;
    changed.issuer_public_key = *IssuerSigningKey::generate().verifying_key().as_bytes();
    assert_ne!(
        original,
        GrantDigest::of_grant(&changed).unwrap(),
        "exact grant digest must bind issuer key bytes"
    );
}

struct AdvancingClock(Arc<AtomicU64>);
impl ElapsedClock for AdvancingClock {
    fn elapsed_ms(&self) -> u64 {
        match self.0.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => 1000,
            _ => 1100,
        }
    }
}
#[test]
fn proof_expiring_during_verification_is_refused() {
    let key = ManagerSigningKey::generate();
    let reads = Arc::new(AtomicU64::new(0));
    let verifier = PeerPossessionVerifier::new(Box::new(AdvancingClock(reads.clone())));
    let challenge = verifier
        .create_challenge(binding(), &key.verifying_key(), 100)
        .unwrap();
    let proof = key.prove_possession(&challenge);
    reads.store(1, Ordering::SeqCst);
    assert!(
        verifier.verify_possession(&challenge, &proof).is_err(),
        "check expiry again after signature verification"
    );
}

#[test]
fn expired_challenge_cannot_revive_after_clock_rollback() {
    let key = ManagerSigningKey::generate();
    let time = Arc::new(AtomicU64::new(1000));
    let verifier = PeerPossessionVerifier::new(Box::new(ReviewClock(time.clone())));
    let challenge = verifier
        .create_challenge(binding(), &key.verifying_key(), 100)
        .unwrap();
    let proof = key.prove_possession(&challenge);
    time.store(1100, Ordering::SeqCst);
    assert!(verifier.verify_possession(&challenge, &proof).is_err());
    time.store(1001, Ordering::SeqCst);
    assert!(verifier.verify_possession(&challenge, &proof).is_err(), "expired challenge must remain terminal even if the supplied clock rolls back within its original interval");
}

#[test]
fn backward_elapsed_time_inside_lifetime_is_terminal() {
    let key = ManagerSigningKey::generate();
    let wrong_key = ManagerSigningKey::generate();
    let time = Arc::new(AtomicU64::new(1000));
    let verifier = PeerPossessionVerifier::new(Box::new(ReviewClock(time.clone())));
    let challenge = verifier
        .create_challenge(binding(), &key.verifying_key(), 100)
        .unwrap();
    time.store(1050, Ordering::SeqCst);
    assert!(verifier
        .verify_possession(&challenge, &wrong_key.prove_possession(&challenge))
        .is_err());
    time.store(1040, Ordering::SeqCst);
    let proof = key.prove_possession(&challenge);
    assert!(
        verifier.verify_possession(&challenge, &proof).is_err(),
        "elapsed time must not rewind even within the original lifetime"
    );
    time.store(1060, Ordering::SeqCst);
    assert!(
        verifier.verify_possession(&challenge, &proof).is_err(),
        "observed clock fault must not heal this challenge"
    );
}
