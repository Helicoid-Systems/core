//! Peer manager-key possession against a receiver-issued challenge.
//!
//! This is a **possession primitive only** — not distributed admission.
//! A receiver creates a one-shot challenge bound to the exact fixture
//! context; the manager proves possession of a separate Ed25519 key by
//! signing the domain-separated canonical transcript.
//!
//! ## Scope and limits
//!
//! - Challenge objects are constructed only by `PeerPossessionVerifier`.
//!   Their acceptance state is private and cannot be rewound.
//! - Deadlines use monotonic elapsed time (`ElapsedClock`), never wall time.
//! - Channel binding is an independently supplied fixture input. It is
//!   **not** proof of trusted transport (no TLS or channel cryptography).
//! - No network, storage, user keys, OS claims, or production authority.

use crate::admission::{ElapsedClock, MAX_CANDIDATE_LIFETIME_MS};
use crate::canonical::CanonicalError;
use crate::grant::Grant;
use crate::keys::{IssuerVerifyingKey, KeyError};
use crate::types::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Domain separation for peer possession proofs (never the admission domain).
pub const PEER_DOMAIN_TAG: &[u8] = b"HAL-AUTH-PEER-PROOF";

/// Hard maximum challenge lifetime. Same 30s development bound as candidate
/// credentials. The exact bound is allowed.
pub const MAX_CHALLENGE_LIFETIME_MS: u64 = MAX_CANDIDATE_LIFETIME_MS;

/// Maximum length of an opaque channel-binding value.
pub const MAX_CHANNEL_BINDING_LEN: usize = 128;

/// Hard bound on the peer possession canonical body.
pub const MAX_PEER_CANONICAL_BODY: usize = 4096;

/// Opaque channel binding. Independently supplied fixture input — this is
/// **not** a cryptographic proof of a trusted transport channel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelBinding(Vec<u8>);

impl ChannelBinding {
    /// Non-empty, length-bounded, not all-zero.
    pub fn new(bytes: &[u8]) -> Result<Self, TypeError> {
        if bytes.is_empty() {
            return Err(TypeError::Empty);
        }
        if bytes.len() > MAX_CHANNEL_BINDING_LEN {
            return Err(TypeError::TooLong(bytes.len()));
        }
        if bytes.iter().all(|&b| b == 0) {
            return Err(TypeError::ZeroChannelBinding);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Exact grant digest (SHA-256 over canonical body, signature and issuer key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantDigest([u8; 32]);

impl GrantDigest {
    /// Non-zero digest.
    pub fn new(bytes: [u8; 32]) -> Result<Self, TypeError> {
        if bytes == [0u8; 32] {
            return Err(TypeError::ZeroGrantDigest);
        }
        Ok(Self(bytes))
    }

    /// Exact grant digest: SHA-256 over canonical signed body || signature
    /// || issuer public key. Substituted signature or issuer key changes it.
    pub fn of_grant(grant: &Grant) -> Result<Self, GrantDigestError> {
        use sha2::{Digest, Sha256};
        let body = crate::canonical::canonical_signing_bytes(&grant.fields)
            .map_err(|_| GrantDigestError::GrantBody)?;
        let mut hasher = Sha256::new();
        hasher.update(&body);
        hasher.update(grant.signature);
        hasher.update(grant.issuer_public_key);
        let hash: [u8; 32] = hasher.finalize().into();
        Self::new(hash).map_err(|_| GrantDigestError::ZeroDigest)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failure computing a grant digest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantDigestError {
    #[error("grant canonical body unavailable")]
    GrantBody,
    #[error("grant digest is zero")]
    ZeroDigest,
}

/// Manager (peer) signing key. Separate from the issuer credential signer.
/// Private key material never implements Debug or serde.
pub struct ManagerSigningKey {
    signing: SigningKey,
}

// Explicitly no Debug impl for ManagerSigningKey — private key must not leak.

impl ManagerSigningKey {
    /// Generate a new manager key from OS RNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self {
            signing: SigningKey::from_bytes(&secret),
        }
    }

    /// Load from raw 32 bytes (test/fixtures only).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// Manager verifying (public) key.
    pub fn verifying_key(&self) -> ManagerVerifyingKey {
        ManagerVerifyingKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign a message with this manager key (possession proofs, fixtures).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Produce a possession proof over a verifier-issued challenge.
    pub fn prove_possession(&self, challenge: &PeerChallenge) -> PossessionProof {
        PossessionProof {
            signature: self.sign(challenge.signing_bytes()),
            manager_public_key: *self.verifying_key().as_bytes(),
        }
    }
}

/// Manager verifying key. Safe to Debug and serialize.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagerVerifyingKey {
    verifying: VerifyingKey,
}

impl std::fmt::Debug for ManagerVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerVerifyingKey")
            .field("bytes", &hex::encode(self.verifying.as_bytes()))
            .finish()
    }
}

impl ManagerVerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let verifying = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self { verifying })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying.as_bytes()
    }

    /// Strict detached-signature verification.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), KeyError> {
        use ed25519_dalek::Signature;
        let sig = Signature::from_bytes(signature);
        self.verifying
            .verify_strict(message, &sig)
            .map_err(|_| KeyError::VerifyFailed)
    }
}

/// Exact fixture context bound into the possession transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeBinding {
    pub deployment: DeploymentId,
    /// Issuer binding: pinned issuer public key for this deployment.
    pub issuer_public_key: [u8; 32],
    pub issuer_generation: u64,
    pub computer: ComputerId,
    pub incarnation: IncarnationId,
    pub desktop_generation: DesktopGeneration,
    pub operation: Operation,
    pub intent_id: String,
    pub grant_digest: GrantDigest,
    pub channel_binding: ChannelBinding,
}

impl ChallengeBinding {
    /// Structural checks applied before any transcript is built.
    pub fn validate(&self) -> Result<(), PeerChallengeError> {
        checked_issuer_generation(self.issuer_generation)
            .map_err(|_| PeerChallengeError::MalformedBinding)?;
        crate::types::validate_id(&self.intent_id)
            .map_err(|_| PeerChallengeError::MalformedBinding)?;
        if *self.grant_digest.as_bytes() == [0u8; 32] {
            return Err(PeerChallengeError::MalformedBinding);
        }
        if self.channel_binding.as_bytes().is_empty()
            || self.channel_binding.as_bytes().iter().all(|&b| b == 0)
        {
            return Err(PeerChallengeError::MalformedBinding);
        }
        if self.issuer_public_key == [0u8; 32] {
            return Err(PeerChallengeError::MalformedBinding);
        }
        IssuerVerifyingKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| PeerChallengeError::MalformedBinding)?;
        Ok(())
    }
}

/// Canonical possession-transcript error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerChallengeError {
    #[error("malformed challenge binding")]
    MalformedBinding,
    #[error("non-positive challenge lifetime")]
    NonPositiveLifetime,
    #[error("challenge lifetime exceeds bound")]
    LifetimeExceedsBound,
    #[error("deadline would overflow monotonic clock")]
    DeadlineOverflow,
    #[error("canonical encoding error: {0}")]
    Canonical(String),
    #[error("invalid manager key")]
    InvalidManagerKey,
    #[error("fresh challenge nonce unavailable")]
    NonceUnavailable,
}

/// Possession-proof verification error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerProofError {
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("manager key mismatch")]
    ManagerKeyMismatch,
    #[error("challenge expired")]
    Expired,
    #[error("monotonic clock fault (elapsed time rewound)")]
    ClockFault,
    #[error("challenge was not issued by this verifier")]
    ForeignChallenge,
    #[error("challenge already accepted")]
    AlreadyAccepted,
}

/// Detached manager possession proof. Fields are public so fixtures can
/// substitute wrong keys/signatures; verification never trusts them blindly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossessionProof {
    pub signature: [u8; 64],
    pub manager_public_key: [u8; 32],
}

/// Typed result of a single successful possession proof.
///
/// Callers cannot manufacture this result or change the verified binding.
///
/// ```compile_fail
/// use authority_lab::{ChallengeBinding, Nonce, VerifiedPossession};
/// fn forge(binding: ChallengeBinding, challenge_nonce: Nonce) -> VerifiedPossession {
///     VerifiedPossession { manager_public_key: [0; 32], challenge_nonce, binding }
/// }
/// ```
///
/// ```compile_fail
/// use authority_lab::{Operation, VerifiedPossession};
/// fn escalate(result: &mut VerifiedPossession) {
///     result.binding.operation = Operation::Control;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPossession {
    manager_public_key: [u8; 32],
    challenge_nonce: Nonce,
    binding: ChallengeBinding,
}

impl VerifiedPossession {
    pub fn manager_public_key(&self) -> &[u8; 32] {
        &self.manager_public_key
    }

    pub fn challenge_nonce(&self) -> &Nonce {
        &self.challenge_nonce
    }

    pub fn binding(&self) -> &ChallengeBinding {
        &self.binding
    }
}

/// Build the domain-separated canonical possession transcript.
///
/// Layout:
///   PEER_DOMAIN_TAG || 0x00 ||
///   deployment (LP) || issuer_public_key (32) || issuer_generation (u64) ||
///   computer (LP) || incarnation (LP) || desktop_generation (u64) ||
///   operation (1) || intent_id (LP) || grant_digest (32) ||
///   channel_binding (LP) || challenge_nonce (32) ||
///   expected_manager_key (32) || created_elapsed_ms (u64) || lifetime_ms (u64)
pub fn possession_signing_bytes(
    binding: &ChallengeBinding,
    challenge_nonce: &Nonce,
    expected_manager_key: &[u8; 32],
    created_elapsed_ms: u64,
    lifetime_ms: u64,
) -> Result<Vec<u8>, PeerChallengeError> {
    binding.validate()?;
    if lifetime_ms == 0 {
        return Err(PeerChallengeError::NonPositiveLifetime);
    }
    if lifetime_ms > MAX_CHALLENGE_LIFETIME_MS {
        return Err(PeerChallengeError::LifetimeExceedsBound);
    }
    if *challenge_nonce.as_bytes() == [0u8; 32] {
        return Err(PeerChallengeError::MalformedBinding);
    }
    if *expected_manager_key == [0u8; 32] {
        return Err(PeerChallengeError::InvalidManagerKey);
    }
    created_elapsed_ms
        .checked_add(lifetime_ms)
        .ok_or(PeerChallengeError::DeadlineOverflow)?;

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(PEER_DOMAIN_TAG);
    out.push(0x00);

    push_lp(&mut out, binding.deployment.as_bytes(), "deployment")?;
    out.extend_from_slice(&binding.issuer_public_key);
    out.extend_from_slice(&binding.issuer_generation.to_be_bytes());
    push_lp(&mut out, binding.computer.as_bytes(), "computer")?;
    push_lp(&mut out, binding.incarnation.as_bytes(), "incarnation")?;
    out.extend_from_slice(&binding.desktop_generation.as_u64().to_be_bytes());
    out.push(binding.operation.opcode());
    push_lp(&mut out, binding.intent_id.as_bytes(), "intent_id")?;
    out.extend_from_slice(binding.grant_digest.as_bytes());
    push_lp(
        &mut out,
        binding.channel_binding.as_bytes(),
        "channel_binding",
    )?;
    out.extend_from_slice(challenge_nonce.as_bytes());
    out.extend_from_slice(expected_manager_key);
    out.extend_from_slice(&created_elapsed_ms.to_be_bytes());
    out.extend_from_slice(&lifetime_ms.to_be_bytes());

    if out.len() > MAX_PEER_CANONICAL_BODY {
        return Err(PeerChallengeError::Canonical(
            CanonicalError::BodyTooLarge(out.len()).to_string(),
        ));
    }
    Ok(out)
}

fn push_lp(out: &mut Vec<u8>, data: &[u8], field: &'static str) -> Result<(), PeerChallengeError> {
    if data.is_empty() {
        return Err(PeerChallengeError::Canonical(
            CanonicalError::EmptyField(field).to_string(),
        ));
    }
    if data.len() > u32::MAX as usize {
        return Err(PeerChallengeError::Canonical(
            CanonicalError::FieldTooLong(field).to_string(),
        ));
    }
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// Receiver-issued possession challenge. Constructed only by
/// `PeerPossessionVerifier`; all state is private and acceptance is one-shot.
/// Observed expiry or a monotonic rewind latches terminal — never heals.
pub struct PeerChallenge {
    nonce: Nonce,
    expected_manager_key: [u8; 32],
    binding: ChallengeBinding,
    created_elapsed_ms: u64,
    lifetime_ms: u64,
    signing_bytes: Vec<u8>,
    /// Private verifier identity. Prevents accepting a challenge under
    /// another verifier's (possibly rewound) clock.
    verifier_id: Arc<()>,
    accepted: AtomicBool,
    expired: AtomicBool,
    clock_fault: AtomicBool,
    last_seen_ms: AtomicU64,
}

impl PeerChallenge {
    /// Challenge nonce (fresh, non-zero).
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Exact manager key this challenge pins.
    pub fn expected_manager_key(&self) -> &[u8; 32] {
        &self.expected_manager_key
    }

    /// Bound fixture context.
    pub fn binding(&self) -> &ChallengeBinding {
        &self.binding
    }

    pub fn created_elapsed_ms(&self) -> u64 {
        self.created_elapsed_ms
    }

    pub fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }

    /// Canonical bytes the manager must sign. Read-only.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// True after a proof has succeeded once.
    pub fn is_accepted(&self) -> bool {
        self.accepted.load(Ordering::SeqCst)
    }

    /// True after the challenge deadline has been observed as reached.
    pub fn is_expired(&self) -> bool {
        self.expired.load(Ordering::SeqCst)
    }

    /// True after a monotonic rewind was observed; never heals.
    pub fn is_clock_faulted(&self) -> bool {
        self.clock_fault.load(Ordering::SeqCst)
    }
}

/// Peer possession verifier. The only public constructor of `PeerChallenge`.
pub struct PeerPossessionVerifier {
    clock: Box<dyn ElapsedClock>,
    verifier_id: Arc<()>,
}

impl PeerPossessionVerifier {
    pub fn new(clock: Box<dyn ElapsedClock>) -> Self {
        Self {
            clock,
            verifier_id: Arc::new(()),
        }
    }

    /// Create a one-shot challenge with a fresh random nonce.
    pub fn create_challenge(
        &self,
        binding: ChallengeBinding,
        expected_manager_key: &ManagerVerifyingKey,
        lifetime_ms: u64,
    ) -> Result<PeerChallenge, PeerChallengeError> {
        binding.validate()?;
        if lifetime_ms == 0 {
            return Err(PeerChallengeError::NonPositiveLifetime);
        }
        if lifetime_ms > MAX_CHALLENGE_LIFETIME_MS {
            return Err(PeerChallengeError::LifetimeExceedsBound);
        }

        let created_elapsed_ms = self.clock.elapsed_ms();
        created_elapsed_ms
            .checked_add(lifetime_ms)
            .ok_or(PeerChallengeError::DeadlineOverflow)?;

        let nonce = fresh_challenge_nonce()?;
        let expected_manager_key = *expected_manager_key.as_bytes();
        let signing_bytes = possession_signing_bytes(
            &binding,
            &nonce,
            &expected_manager_key,
            created_elapsed_ms,
            lifetime_ms,
        )?;

        Ok(PeerChallenge {
            nonce,
            expected_manager_key,
            binding,
            created_elapsed_ms,
            lifetime_ms,
            signing_bytes,
            verifier_id: Arc::clone(&self.verifier_id),
            accepted: AtomicBool::new(false),
            expired: AtomicBool::new(false),
            clock_fault: AtomicBool::new(false),
            last_seen_ms: AtomicU64::new(created_elapsed_ms),
        })
    }

    /// Verify a manager possession proof. At most one proof succeeds per
    /// challenge. Wrong key, mutated transcript, foreign verifier, rewound
    /// clock, expired deadline, or replay after acceptance all fail.
    pub fn verify_possession(
        &self,
        challenge: &PeerChallenge,
        proof: &PossessionProof,
    ) -> Result<VerifiedPossession, PeerProofError> {
        if !Arc::ptr_eq(&challenge.verifier_id, &self.verifier_id) {
            return Err(PeerProofError::ForeignChallenge);
        }
        if challenge.is_accepted() {
            return Err(PeerProofError::AlreadyAccepted);
        }
        if challenge.is_clock_faulted() {
            return Err(PeerProofError::ClockFault);
        }
        // Expiry is terminal: a rewound clock must not revive the challenge.
        if challenge.is_expired() {
            return Err(PeerProofError::Expired);
        }

        let deadline = challenge
            .created_elapsed_ms
            .checked_add(challenge.lifetime_ms)
            .ok_or(PeerProofError::Expired)?;

        check_deadline(challenge, deadline, self.clock.elapsed_ms())?;

        if proof.manager_public_key != challenge.expected_manager_key {
            return Err(PeerProofError::ManagerKeyMismatch);
        }

        let key = ManagerVerifyingKey::from_bytes(&challenge.expected_manager_key)
            .map_err(|_| PeerProofError::ManagerKeyMismatch)?;
        key.verify_strict(challenge.signing_bytes(), &proof.signature)
            .map_err(|_| PeerProofError::SignatureInvalid)?;

        // Re-check the deadline after signature verification: that work takes
        // time and a proof must not be accepted if it expired mid-check.
        check_deadline(challenge, deadline, self.clock.elapsed_ms())?;

        if challenge
            .accepted
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(PeerProofError::AlreadyAccepted);
        }

        Ok(VerifiedPossession {
            manager_public_key: challenge.expected_manager_key,
            challenge_nonce: challenge.nonce.clone(),
            binding: challenge.binding.clone(),
        })
    }
}

/// Fail closed on monotonic rewind (terminal clock fault) and latch expiry
/// as terminal so neither heals if the supplied clock later moves back.
fn check_deadline(
    challenge: &PeerChallenge,
    deadline: u64,
    now: u64,
) -> Result<(), PeerProofError> {
    if challenge.is_clock_faulted() {
        return Err(PeerProofError::ClockFault);
    }
    let last = challenge.last_seen_ms.load(Ordering::SeqCst);
    if now < challenge.created_elapsed_ms || now < last {
        challenge.clock_fault.store(true, Ordering::SeqCst);
        return Err(PeerProofError::ClockFault);
    }
    challenge.last_seen_ms.fetch_max(now, Ordering::SeqCst);
    if now >= deadline {
        challenge.expired.store(true, Ordering::SeqCst);
        return Err(PeerProofError::Expired);
    }
    Ok(())
}

fn fresh_challenge_nonce() -> Result<Nonce, PeerChallengeError> {
    for _ in 0..8 {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| PeerChallengeError::NonceUnavailable)?;
        if let Ok(nonce) = Nonce::new(bytes) {
            return Ok(nonce);
        }
    }
    Err(PeerChallengeError::NonceUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::ManualElapsedClock;
    use crate::keys::IssuerSigningKey;

    fn sample_binding() -> ChallengeBinding {
        ChallengeBinding {
            deployment: DeploymentId::new("deploy-1").unwrap(),
            issuer_public_key: IssuerSigningKey::generate()
                .verifying_key()
                .as_bytes()
                .to_owned(),
            issuer_generation: 1,
            computer: ComputerId::new("room7-a03").unwrap(),
            incarnation: IncarnationId::new("inc-abc").unwrap(),
            desktop_generation: DesktopGeneration::new(3).unwrap(),
            operation: Operation::Observe,
            intent_id: format!("intent-{}", hex::encode(crate::keys::random_32())),
            grant_digest: GrantDigest::new([2u8; 32]).unwrap(),
            channel_binding: ChannelBinding::new(b"channel-1").unwrap(),
        }
    }

    #[test]
    fn channel_binding_rejects_empty_and_zero() {
        assert!(ChannelBinding::new(b"").is_err());
        assert!(ChannelBinding::new(&[0u8; 8]).is_err());
        assert!(ChannelBinding::new(b"ch").is_ok());
    }

    #[test]
    fn grant_digest_rejects_zero() {
        assert!(GrantDigest::new([0u8; 32]).is_err());
        assert!(GrantDigest::new([1u8; 32]).is_ok());
    }

    #[test]
    fn lifetime_bounds_match_candidate() {
        let clock = ManualElapsedClock::new(10);
        let v = PeerPossessionVerifier::new(Box::new(clock));
        let key = ManagerSigningKey::generate().verifying_key();
        assert!(matches!(
            v.create_challenge(sample_binding(), &key, 0),
            Err(PeerChallengeError::NonPositiveLifetime)
        ));
        assert!(matches!(
            v.create_challenge(sample_binding(), &key, MAX_CHALLENGE_LIFETIME_MS + 1),
            Err(PeerChallengeError::LifetimeExceedsBound)
        ));
        assert!(v
            .create_challenge(sample_binding(), &key, MAX_CHALLENGE_LIFETIME_MS)
            .is_ok());
    }
}
