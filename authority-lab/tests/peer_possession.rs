//! Public peer-possession boundary proofs.
//!
//! Drives `PeerPossessionVerifier` and independent `ManagerSigningKey`
//! signing only. Channel binding is fixture input — no transport proof.

use authority_lab::*;

fn issuer_key() -> IssuerSigningKey {
    IssuerSigningKey::generate()
}

fn manager_key() -> ManagerSigningKey {
    ManagerSigningKey::generate()
}

fn binding_with(issuer_pk: [u8; 32]) -> ChallengeBinding {
    ChallengeBinding {
        deployment: DeploymentId::new("deploy-1").unwrap(),
        issuer_public_key: issuer_pk,
        issuer_generation: 1,
        computer: ComputerId::new("room7-a03").unwrap(),
        incarnation: IncarnationId::new("inc-abc").unwrap(),
        desktop_generation: DesktopGeneration::new(3).unwrap(),
        operation: Operation::Observe,
        intent_id: format!("intent-{}", hex::encode(random_32())),
        grant_digest: GrantDigest::new([7u8; 32]).unwrap(),
        channel_binding: ChannelBinding::new(b"channel-fixture-1").unwrap(),
    }
}

fn binding() -> ChallengeBinding {
    binding_with(*issuer_key().verifying_key().as_bytes())
}

fn verifier(start_ms: u64) -> (PeerPossessionVerifier, std::rc::Rc<ManualElapsedClock>) {
    let clock = std::rc::Rc::new(ManualElapsedClock::new(start_ms));
    let v = PeerPossessionVerifier::new(Box::new(CloneClock(clock.clone())));
    (v, clock)
}

/// Thin adapter so the verifier can own a clock while tests keep an Rc handle.
struct CloneClock(std::rc::Rc<ManualElapsedClock>);

impl ElapsedClock for CloneClock {
    fn elapsed_ms(&self) -> u64 {
        self.0.elapsed_ms()
    }
}

fn create_ok(
    v: &PeerPossessionVerifier,
    key: &ManagerVerifyingKey,
    lifetime_ms: u64,
) -> PeerChallenge {
    v.create_challenge(binding(), key, lifetime_ms)
        .expect("challenge")
}

/// Sign a transcript for the same challenge nonce/times but a mutated binding.
fn proof_over_binding(
    mgr: &ManagerSigningKey,
    challenge: &PeerChallenge,
    mutated: &ChallengeBinding,
) -> PossessionProof {
    let bytes = possession_signing_bytes(
        mutated,
        challenge.nonce(),
        challenge.expected_manager_key(),
        challenge.created_elapsed_ms(),
        challenge.lifetime_ms(),
    )
    .expect("mutated transcript");
    PossessionProof {
        signature: mgr.sign(&bytes),
        manager_public_key: *mgr.verifying_key().as_bytes(),
    }
}

#[test]
fn possession_roundtrip_with_independent_manager_secret() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let proof = mgr.prove_possession(&challenge);
    let verified = v.verify_possession(&challenge, &proof).expect("verify");
    assert_eq!(
        verified.manager_public_key(),
        mgr.verifying_key().as_bytes()
    );
    assert_eq!(verified.challenge_nonce(), challenge.nonce());
    assert_eq!(verified.binding(), challenge.binding());
    assert!(challenge.is_accepted());
}

#[test]
fn one_proof_succeeds_once_replay_fails() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let proof = mgr.prove_possession(&challenge);
    assert!(v.verify_possession(&challenge, &proof).is_ok());
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::AlreadyAccepted)
    );
    let other = PossessionProof {
        signature: proof.signature,
        manager_public_key: proof.manager_public_key,
    };
    assert_eq!(
        v.verify_possession(&challenge, &other),
        Err(PeerProofError::AlreadyAccepted)
    );
}

#[test]
fn failed_proof_does_not_consume_challenge() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let wrong = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let bad = wrong.prove_possession(&challenge);
    assert_eq!(
        v.verify_possession(&challenge, &bad),
        Err(PeerProofError::ManagerKeyMismatch)
    );
    assert!(!challenge.is_accepted());
    let good = mgr.prove_possession(&challenge);
    assert!(v.verify_possession(&challenge, &good).is_ok());
}

#[test]
fn wrong_manager_key_rejected() {
    let (v, _clock) = verifier(1_000);
    let expected = manager_key();
    let other = manager_key();
    let challenge = create_ok(&v, &expected.verifying_key(), 5_000);
    let proof = other.prove_possession(&challenge);
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::ManagerKeyMismatch)
    );
}

#[test]
fn signature_from_other_manager_secret_rejected() {
    let (v, _clock) = verifier(1_000);
    let expected = manager_key();
    let other = manager_key();
    let challenge = create_ok(&v, &expected.verifying_key(), 5_000);
    // Claim the expected key but sign with the other secret.
    let proof = PossessionProof {
        signature: other.sign(challenge.signing_bytes()),
        manager_public_key: *expected.verifying_key().as_bytes(),
    };
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::SignatureInvalid)
    );
}

#[test]
fn cross_role_issuer_grant_signature_is_not_possession() {
    let (v, clock) = verifier(10_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);

    // Build a real signed admission grant through the public issue seam.
    let issuer = issuer_key();
    let mut store = DurableStore::create_memory().unwrap();
    store
        .initialize_trust(&TrustBinding {
            issuer_public_key: *issuer.verifying_key().as_bytes(),
            issuer_generation: 1,
            authority_revision: "rev-1".to_string(),
            deployment: "deploy-1".to_string(),
            schema: SCHEMA_VERSION.to_string(),
        })
        .unwrap();
    let ctrl = AdmissionController::try_new(
        TrustBinding {
            issuer_public_key: *issuer.verifying_key().as_bytes(),
            issuer_generation: 1,
            authority_revision: "rev-1".to_string(),
            deployment: "deploy-1".to_string(),
            schema: SCHEMA_VERSION.to_string(),
        },
        Box::new(ManualEpochClock::new(10_000)),
    )
    .unwrap();
    let issued = ctrl
        .issue(
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
                issued_at: TimestampMs::new(10_000).unwrap(),
                expires_at: TimestampMs::new(15_000).unwrap(),
            },
            &issuer,
            &mut store,
            &format!("intent-{}", hex::encode(random_32())),
        )
        .expect("issue");

    // Issuer credential signature (admission domain) must not prove possession.
    let proof = PossessionProof {
        signature: issued.grant.signature,
        manager_public_key: *mgr.verifying_key().as_bytes(),
    };
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::SignatureInvalid)
    );
    let _ = clock;
}

#[test]
fn domain_separated_from_admission_tag() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);

    // Sign a message that uses the admission domain instead of the peer domain.
    let mut wrong_domain = b"HAL-AUTH-ADMISSION".to_vec();
    wrong_domain.push(0x00);
    wrong_domain.extend_from_slice(&challenge.signing_bytes()[PEER_DOMAIN_TAG.len() + 1..]);
    let proof = PossessionProof {
        signature: mgr.sign(&wrong_domain),
        manager_public_key: *mgr.verifying_key().as_bytes(),
    };
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::SignatureInvalid)
    );
}

#[test]
fn each_bound_field_mutation_fails_verification() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let base = challenge.binding().clone();

    let mutations: Vec<ChallengeBinding> = vec![
        ChallengeBinding {
            deployment: DeploymentId::new("deploy-2").unwrap(),
            ..base.clone()
        },
        ChallengeBinding {
            issuer_public_key: [9u8; 32],
            ..base.clone()
        },
        ChallengeBinding {
            issuer_generation: 2,
            ..base.clone()
        },
        ChallengeBinding {
            computer: ComputerId::new("room7-a04").unwrap(),
            ..base.clone()
        },
        ChallengeBinding {
            incarnation: IncarnationId::new("inc-xyz").unwrap(),
            ..base.clone()
        },
        ChallengeBinding {
            desktop_generation: DesktopGeneration::new(4).unwrap(),
            ..base.clone()
        },
        ChallengeBinding {
            operation: Operation::Control,
            ..base.clone()
        },
        ChallengeBinding {
            intent_id: format!("intent-{}", hex::encode(random_32())),
            ..base.clone()
        },
        ChallengeBinding {
            grant_digest: GrantDigest::new([8u8; 32]).unwrap(),
            ..base.clone()
        },
        ChallengeBinding {
            channel_binding: ChannelBinding::new(b"channel-fixture-2").unwrap(),
            ..base.clone()
        },
    ];

    for mutated in &mutations {
        let proof = proof_over_binding(&mgr, &challenge, mutated);
        assert_eq!(
            v.verify_possession(&challenge, &proof),
            Err(PeerProofError::SignatureInvalid),
            "mutated binding must not verify"
        );
    }
    assert!(!challenge.is_accepted());

    // Untouched transcript still verifies.
    let good = mgr.prove_possession(&challenge);
    assert!(v.verify_possession(&challenge, &good).is_ok());
}

#[test]
fn wrong_channel_binding_signature_rejected() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let mut mutated = challenge.binding().clone();
    mutated.channel_binding = ChannelBinding::new(b"other-channel").unwrap();
    let proof = proof_over_binding(&mgr, &challenge, &mutated);
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::SignatureInvalid)
    );
}

#[test]
fn substituted_grant_digest_rejected() {
    let (v, _clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    let mut mutated = challenge.binding().clone();
    mutated.grant_digest = GrantDigest::new([0xAAu8; 32]).unwrap();
    let proof = proof_over_binding(&mgr, &challenge, &mutated);
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::SignatureInvalid)
    );
}

#[test]
fn deadline_exact_bound_expires_on_deadline() {
    // Valid one millisecond before the deadline.
    let (v, clock) = verifier(1_000);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 5_000);
    clock.advance(4_999).unwrap();
    let before = mgr.prove_possession(&challenge);
    assert!(v.verify_possession(&challenge, &before).is_ok());

    // Fresh challenge: elapsed == created + lifetime is expired.
    let (v2, clock2) = verifier(1_000);
    let challenge2 = create_ok(&v2, &mgr.verifying_key(), 5_000);
    let proof2 = mgr.prove_possession(&challenge2);
    clock2.advance(5_000).unwrap();
    assert_eq!(
        v2.verify_possession(&challenge2, &proof2),
        Err(PeerProofError::Expired)
    );
    assert!(!challenge2.is_accepted());
}

#[test]
fn deadline_expires_after_bound_without_acceptance() {
    let (v, clock) = verifier(0);
    let mgr = manager_key();
    let challenge = create_ok(&v, &mgr.verifying_key(), 30_000);
    let proof = mgr.prove_possession(&challenge);
    clock.advance(30_000).unwrap();
    assert_eq!(
        v.verify_possession(&challenge, &proof),
        Err(PeerProofError::Expired)
    );
}

#[test]
fn lifetime_exact_30s_allowed_over_rejected() {
    let (v, _clock) = verifier(1_000);
    let key = manager_key().verifying_key();
    assert!(v
        .create_challenge(binding(), &key, MAX_CHALLENGE_LIFETIME_MS)
        .is_ok());
    assert!(matches!(
        v.create_challenge(binding(), &key, MAX_CHALLENGE_LIFETIME_MS + 1),
        Err(PeerChallengeError::LifetimeExceedsBound)
    ));
    assert!(matches!(
        v.create_challenge(binding(), &key, 0),
        Err(PeerChallengeError::NonPositiveLifetime)
    ));
}

#[test]
fn invalid_and_zero_fields_rejected_at_binding_or_transcript() {
    let (v, clock) = verifier(1_000);
    let key = manager_key().verifying_key();

    assert!(ChannelBinding::new(b"").is_err());
    assert!(ChannelBinding::new(&[0u8; 4]).is_err());
    assert!(GrantDigest::new([0u8; 32]).is_err());
    assert!(DesktopGeneration::new(0).is_err());
    assert!(Nonce::new([0u8; 32]).is_err());

    let mut zero_gen = binding();
    zero_gen.issuer_generation = 0;
    assert!(matches!(
        v.create_challenge(zero_gen, &key, 1_000),
        Err(PeerChallengeError::MalformedBinding)
    ));

    let mut empty_intent = binding();
    empty_intent.intent_id = String::new();
    assert!(matches!(
        v.create_challenge(empty_intent, &key, 1_000),
        Err(PeerChallengeError::MalformedBinding)
    ));

    let mut bad_issuer = binding();
    bad_issuer.issuer_public_key = [0u8; 32];
    assert!(matches!(
        v.create_challenge(bad_issuer, &key, 1_000),
        Err(PeerChallengeError::MalformedBinding)
    ));

    let mut zero_key = binding();
    let bytes = possession_signing_bytes(
        &zero_key,
        &Nonce::new([1u8; 32]).unwrap(),
        &[0u8; 32],
        clock.elapsed_ms(),
        1_000,
    );
    assert!(matches!(bytes, Err(PeerChallengeError::InvalidManagerKey)));
    zero_key.intent_id = "ok-intent".to_string();
    let _ = zero_key;
}

#[test]
fn challenges_have_fresh_nonces() {
    let (v, _clock) = verifier(1_000);
    let key = manager_key().verifying_key();
    let a = create_ok(&v, &key, 5_000);
    let b = create_ok(&v, &key, 5_000);
    assert_ne!(a.nonce(), b.nonce());
    assert_ne!(a.signing_bytes(), b.signing_bytes());
}

#[test]
fn exact_grant_digest_binds_signature_and_issuer_key() {
    let issuer = issuer_key();
    let mut store = DurableStore::create_memory().unwrap();
    store
        .initialize_trust(&TrustBinding {
            issuer_public_key: *issuer.verifying_key().as_bytes(),
            issuer_generation: 1,
            authority_revision: "rev-1".to_string(),
            deployment: "deploy-1".to_string(),
            schema: SCHEMA_VERSION.to_string(),
        })
        .unwrap();
    let ctrl = AdmissionController::try_new(
        TrustBinding {
            issuer_public_key: *issuer.verifying_key().as_bytes(),
            issuer_generation: 1,
            authority_revision: "rev-1".to_string(),
            deployment: "deploy-1".to_string(),
            schema: SCHEMA_VERSION.to_string(),
        },
        Box::new(ManualEpochClock::new(10_000)),
    )
    .unwrap();
    let issued = ctrl
        .issue(
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
                issued_at: TimestampMs::new(10_000).unwrap(),
                expires_at: TimestampMs::new(15_000).unwrap(),
            },
            &issuer,
            &mut store,
            &format!("intent-{}", hex::encode(random_32())),
        )
        .expect("issue");
    let original = GrantDigest::of_grant(&issued.grant).expect("digest");
    let mut changed = issued.grant.clone();
    changed.signature[0] ^= 1;
    assert_ne!(
        original,
        GrantDigest::of_grant(&changed).unwrap(),
        "exact grant digest must bind signature bytes"
    );
    changed = issued.grant.clone();
    changed.issuer_public_key = *issuer_key().verifying_key().as_bytes();
    assert_ne!(
        original,
        GrantDigest::of_grant(&changed).unwrap(),
        "exact grant digest must bind issuer key bytes"
    );
}

#[test]
fn foreign_verifier_and_rewound_clock_fail_closed() {
    let mgr = manager_key();
    let origin = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(1_000)));
    let challenge = create_ok(&origin, &mgr.verifying_key(), 5_000);
    let proof = mgr.prove_possession(&challenge);

    // A different verifier must not take over the challenge.
    let foreign = PeerPossessionVerifier::new(Box::new(ManualElapsedClock::new(1_100)));
    assert_eq!(
        foreign.verify_possession(&challenge, &proof),
        Err(PeerProofError::ForeignChallenge)
    );

    // Same-verifier rewind and terminal expiry are covered by `peer_review`.
    assert!(!challenge.is_accepted());
}
