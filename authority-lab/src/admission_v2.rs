//! V2 distributed admission controller.
//!
//! This is the v2 admission contract for distributed signed admission.
//! It uses separate `IssuerJournal` and `ReceiverLeaseStore` instead of
//! the shared `DurableStore`. The receiver never opens the issuer DB.
//!
//! ## Scope
//!
//! - V2 canonical signed grants with full endpoint binding
//! - Cryptographic verification against pinned trusted context
//! - Separate issuer journal and receiver lease store
//! - Monotonic lease with bounded lifetime
//! - Transport/OS context explicitly unproved until adapter integration
//!
//! ## Not in scope
//!
//! - Real authenticated channel (channel binding is fixture input)
//! - Production callers (B03 not passed)
//! - Media, file, or UI automatic scope expansion

use crate::canonical_v2::{canonical_v2_signing_bytes, CanonicalV2Error, CanonicalV2Fields};
use crate::issuer_store::{IssuerError, IssuerJournal, JournalEntry};
use crate::keys::{IssuerSigningKey, IssuerVerifyingKey};
use crate::ownership::{ClaimRole, OwnershipManager};
use crate::peer::{
    GrantDigest, GrantDigestError, ManagerVerifyingKey, PeerPossessionVerifier, PeerProofError,
    PossessionProof,
};
use crate::receiver_store::{
    ConsumeLeaseParams, ReceiverError, ReceiverLeaseStore, RenewLeaseParams,
};
use crate::types::*;
use sha2::{Digest, Sha256};

/// Hard maximum v2 credential lifetime (30 seconds).
pub const V2_MAX_CANDIDATE_LIFETIME_MS: u64 = 30_000;

/// V2 signed admission grant.
#[derive(Debug, Clone)]
pub struct V2Grant {
    /// Signed canonical v2 fields.
    pub fields: CanonicalV2Fields,
    /// Detached Ed25519 signature over the v2 canonical bytes.
    pub signature: [u8; 64],
    /// Issuer public key that produced this signature.
    pub issuer_public_key: [u8; 32],
}

impl V2Grant {
    /// SHA-256 over the exact canonical v2 signed bytes.
    pub fn body_hash(&self) -> Result<[u8; 32], V2GrantError> {
        let bytes = canonical_v2_signing_bytes(&self.fields)?;
        Ok(Sha256::digest(&bytes).into())
    }

    /// Sign canonical v2 fields. Creates a complete V2Grant.
    pub fn sign(fields: CanonicalV2Fields, key: &IssuerSigningKey) -> Result<Self, V2GrantError> {
        fields.validate_structure()?;
        let bytes = canonical_v2_signing_bytes(&fields)?;
        let signature = key.sign(&bytes);
        let pk = *key.verifying_key().as_bytes();
        Ok(Self {
            fields,
            signature,
            issuer_public_key: pk,
        })
    }

    /// Verify the grant against independent expected authority and
    /// receiver context. Never uses credential claims as their own
    /// expected values.
    pub fn verify(
        &self,
        expected: &V2ExpectedAuthority,
        receiver: &V2ReceiverContext,
        now_ms: u64,
        max_lifetime_ms: u64,
    ) -> Result<(), V2GrantError> {
        self.fields.validate_structure()?;
        let bytes = canonical_v2_signing_bytes(&self.fields)?;

        // Strict signature verification
        let sig_key = IssuerVerifyingKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| V2GrantError::SignatureInvalid)?;
        sig_key
            .verify_strict(&bytes, &self.signature)
            .map_err(|_| V2GrantError::SignatureInvalid)?;

        // Issuer binding
        if self.issuer_public_key != expected.issuer_public_key {
            return Err(V2GrantError::IssuerKeyMismatch);
        }
        if self.fields.issuer_generation != expected.issuer_generation {
            return Err(V2GrantError::IssuerGenerationMismatch);
        }
        if self.fields.deployment != expected.deployment {
            return Err(V2GrantError::DeploymentMismatch);
        }
        if self.fields.schema != expected.schema {
            return Err(V2GrantError::SchemaMismatch);
        }
        if self.fields.authority_revision != expected.authority_revision {
            return Err(V2GrantError::AuthorityRevisionMismatch);
        }

        // Receiver context — all identity fields must match independently
        if self.fields.endpoint_key != receiver.endpoint_key {
            return Err(V2GrantError::EndpointMismatch);
        }
        if self.fields.boot_id != receiver.boot_id {
            return Err(V2GrantError::BootIdMismatch);
        }
        if self.fields.worker_id != receiver.worker_id {
            return Err(V2GrantError::WorkerIdMismatch);
        }
        if self.fields.computer != receiver.computer {
            return Err(V2GrantError::TargetMismatch);
        }
        if self.fields.incarnation != receiver.incarnation {
            return Err(V2GrantError::TargetMismatch);
        }
        if self.fields.desktop_generation != receiver.desktop_generation {
            return Err(V2GrantError::DesktopGenerationMismatch);
        }

        // Time
        if now_ms >= self.fields.expires_at.as_u64() {
            return Err(V2GrantError::Expired);
        }
        if now_ms < self.fields.issued_at.as_u64() {
            return Err(V2GrantError::NotYetValid);
        }
        let lifetime = checked_duration_ms(self.fields.issued_at, self.fields.expires_at)
            .map_err(|_| V2GrantError::NonPositiveDuration)?;
        if lifetime > max_lifetime_ms {
            return Err(V2GrantError::DurationExceedsBound);
        }

        Ok(())
    }

    /// Check if this grant permits the given operation.
    pub fn permits(&self, op: Operation) -> bool {
        self.fields.operation == op
    }
}

/// Compute the exact grant digest for a v2 grant: SHA-256 over canonical
/// v2 body || signature || issuer_public_key. This binds the signature
/// and issuer key into the possession challenge transcript.
pub fn v2_grant_digest(grant: &V2Grant) -> Result<GrantDigest, GrantDigestError> {
    use sha2::{Digest, Sha256};
    let body =
        canonical_v2_signing_bytes(&grant.fields).map_err(|_| GrantDigestError::GrantBody)?;
    let mut hasher = Sha256::new();
    hasher.update(&body);
    hasher.update(grant.signature);
    hasher.update(grant.issuer_public_key);
    let hash: [u8; 32] = hasher.finalize().into();
    GrantDigest::new(hash).map_err(|_| GrantDigestError::ZeroDigest)
}

/// Sealed result of a verified v2 admission.
///
/// Callers cannot manufacture this result or change the verified binding.
/// Fields are private and immutable. Every field was independently verified
/// against the grant signature and the pinned receiver context — none of
/// these are caller claims.
///
/// ```compile_fail
/// use authority_lab::admission_v2::VerifiedAdmission;
/// fn forge() -> VerifiedAdmission {
///     VerifiedAdmission { intent_id: "x".into(), manager_public_key: [0; 32],
///         granted_at_mono_ms: 0, lease_deadline_mono_ms: 0, operation_intent: "x".into(),
///         endpoint_key: [0; 32], desktop_generation: 0, operation: authority_lab::Operation::Observe,
///         display_generation: 0, grant_digest: [0; 32], channel_binding: vec![] }
/// }
/// ```
///
/// ```compile_fail
/// use authority_lab::admission_v2::VerifiedAdmission;
/// fn mutate(admission: &mut VerifiedAdmission) {
///     admission.intent_id = "y".into();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmission {
    intent_id: String,
    manager_public_key: [u8; 32],
    granted_at_mono_ms: u64,
    lease_deadline_mono_ms: u64,
    operation_intent: String,
    endpoint_key: [u8; 32],
    desktop_generation: u64,
    operation: Operation,
    display_generation: u64,
    grant_digest: [u8; 32],
    channel_binding: Vec<u8>,
}

impl VerifiedAdmission {
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }
    pub fn manager_public_key(&self) -> &[u8; 32] {
        &self.manager_public_key
    }
    pub fn granted_at_mono_ms(&self) -> u64 {
        self.granted_at_mono_ms
    }
    pub fn lease_deadline_mono_ms(&self) -> u64 {
        self.lease_deadline_mono_ms
    }
    pub fn operation_intent(&self) -> &str {
        &self.operation_intent
    }
    pub fn endpoint_key(&self) -> &[u8; 32] {
        &self.endpoint_key
    }
    pub fn desktop_generation(&self) -> u64 {
        self.desktop_generation
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn display_generation(&self) -> u64 {
        self.display_generation
    }
    pub fn grant_digest(&self) -> &[u8; 32] {
        &self.grant_digest
    }
    pub fn channel_binding(&self) -> &[u8] {
        &self.channel_binding
    }
}

/// V2 grant error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum V2GrantError {
    #[error("canonical v2 encoding error: {0}")]
    Canonical(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("issuer key mismatch")]
    IssuerKeyMismatch,
    #[error("issuer generation mismatch")]
    IssuerGenerationMismatch,
    #[error("deployment mismatch")]
    DeploymentMismatch,
    #[error("schema mismatch")]
    SchemaMismatch,
    #[error("authority revision mismatch")]
    AuthorityRevisionMismatch,
    #[error("endpoint key mismatch")]
    EndpointMismatch,
    #[error("boot ID mismatch")]
    BootIdMismatch,
    #[error("worker ID mismatch")]
    WorkerIdMismatch,
    #[error("target identity mismatch")]
    TargetMismatch,
    #[error("desktop generation mismatch")]
    DesktopGenerationMismatch,
    #[error("credential expired")]
    Expired,
    #[error("credential not yet valid")]
    NotYetValid,
    #[error("duration exceeds bound")]
    DurationExceedsBound,
    #[error("non-positive duration")]
    NonPositiveDuration,
    #[error("structural field rejection")]
    Structural,
}

impl From<CanonicalV2Error> for V2GrantError {
    fn from(e: CanonicalV2Error) -> Self {
        V2GrantError::Canonical(e.to_string())
    }
}

/// V2 admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2AdmissionDecision {
    /// Credential accepted with verified Manager possession. Lease created.
    /// The sealed admission carries immutable verified bindings.
    Granted(Box<VerifiedAdmission>),
    /// Credential rejected.
    Denied(V2DenyReason),
}

/// V2 denial reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2DenyReason {
    SignatureInvalid,
    IssuerMismatch,
    SchemaMismatch,
    DeploymentMismatch,
    EndpointMismatch,
    BootIdMismatch,
    WorkerIdMismatch,
    TargetMismatch,
    DesktopGenerationMismatch,
    Expired,
    NotYetValid,
    IssuerGenerationMismatch,
    AuthorityRevisionMismatch,
    ReplayDetected,
    OperationNotPermitted,
    DurationExceedsBound,
    NonPositiveDuration,
    MalformedCredential,
    ClockFault,
    StorageFault,
    TrustStateCorrupt,
    CapacityExhausted,
    GateLatched,
    ControllerConflict,
    /// Manager possession proof required but not provided.
    PossessionRequired,
    /// Manager possession proof signature invalid.
    PossessionSignatureInvalid,
    /// Manager key in proof does not match expected.
    PossessionManagerKeyMismatch,
    /// Manager possession challenge expired.
    PossessionExpired,
    /// Challenge was not issued by this verifier.
    PossessionForeignChallenge,
}

/// V2 expected authority binding.
#[derive(Debug, Clone)]
pub struct V2ExpectedAuthority {
    pub issuer_public_key: [u8; 32],
    pub issuer_generation: u64,
    pub deployment: DeploymentId,
    pub schema: String,
    pub authority_revision: AuthorityRevision,
}

/// V2 receiver context for verification.
#[derive(Debug, Clone)]
pub struct V2ReceiverContext {
    pub endpoint_key: EndpointKey,
    pub boot_id: BootId,
    pub worker_id: WorkerId,
    pub computer: ComputerId,
    pub incarnation: IncarnationId,
    pub desktop_generation: DesktopGeneration,
}

/// Parameters for `admit_with_possession` to avoid too many arguments.
pub struct PossessionAdmitParams<'a> {
    pub verifier: &'a PeerPossessionVerifier,
    pub challenge: &'a crate::peer::PeerChallenge,
    pub proof: &'a PossessionProof,
    pub expected_manager_key: &'a ManagerVerifyingKey,
}

/// V2 distributed admission controller.
pub struct V2AdmissionController {
    expected: V2ExpectedAuthority,
    receiver: V2ReceiverContext,
    ownership: OwnershipManager,
    /// Last observed wall-clock ms for signed validity. Backward movement
    /// fails closed and latches — never revives an expired grant.
    last_wall_ms: std::cell::Cell<Option<u64>>,
}

impl V2AdmissionController {
    pub fn new(expected: V2ExpectedAuthority, receiver: V2ReceiverContext) -> Self {
        Self {
            expected,
            receiver,
            ownership: OwnershipManager::new(),
            last_wall_ms: std::cell::Cell::new(None),
        }
    }

    /// Observe wall-clock for signed validity. Backward movement returns
    /// `ClockFault` and latches the receiver store. The grant must not be
    /// admitted after a rollback.
    fn observe_wall_clock(
        &self,
        now_ms: u64,
        receiver_store: Option<&mut ReceiverLeaseStore>,
    ) -> Result<(), V2DenyReason> {
        if let Some(last) = self.last_wall_ms.get() {
            if now_ms < last {
                if let Some(store) = receiver_store {
                    let _ = store.check_wall_clock(now_ms);
                }
                return Err(V2DenyReason::ClockFault);
            }
        }
        if let Some(store) = receiver_store {
            if store.check_wall_clock(now_ms).is_err() {
                return Err(V2DenyReason::ClockFault);
            }
        }
        self.last_wall_ms.set(Some(now_ms));
        Ok(())
    }

    /// Issue a v2 grant: sign the fields and record in the issuer journal.
    /// Returns the signed grant only after a durable journal commit.
    pub fn issue(
        &self,
        fields: CanonicalV2Fields,
        signing_key: &IssuerSigningKey,
        journal: &mut IssuerJournal,
        intent_id: &str,
        now_ms: u64,
    ) -> Result<V2Grant, V2IssueError> {
        if journal.is_latched() {
            return Err(V2IssueError::GateLatched);
        }
        validate_id(intent_id).map_err(|_| V2IssueError::Malformed)?;
        self.observe_wall_clock(now_ms, None)
            .map_err(|_| V2IssueError::ClockFault)?;

        fields
            .validate_structure()
            .map_err(|_| V2IssueError::Malformed)?;

        // Authority checks before signing
        if fields.schema != self.expected.schema {
            return Err(V2IssueError::Malformed);
        }
        if fields.deployment != self.expected.deployment {
            return Err(V2IssueError::Malformed);
        }
        if fields.issuer_generation != self.expected.issuer_generation {
            return Err(V2IssueError::Malformed);
        }
        if fields.authority_revision != self.expected.authority_revision {
            return Err(V2IssueError::Malformed);
        }
        if *signing_key.verifying_key().as_bytes() != self.expected.issuer_public_key {
            return Err(V2IssueError::SigningKeyMismatch);
        }

        // Time checks
        if now_ms >= fields.expires_at.as_u64() {
            return Err(V2IssueError::Malformed);
        }
        if now_ms < fields.issued_at.as_u64() {
            return Err(V2IssueError::Malformed);
        }
        let lifetime = checked_duration_ms(fields.issued_at, fields.expires_at)
            .map_err(|_| V2IssueError::Malformed)?;
        if lifetime == 0 || lifetime > V2_MAX_CANDIDATE_LIFETIME_MS {
            return Err(V2IssueError::DurationExceedsBound);
        }

        let grant = V2Grant::sign(fields, signing_key)?;
        let body_hash_hex = hex::encode(grant.body_hash()?);

        let entry = JournalEntry {
            intent_id: intent_id.to_string(),
            nonce_hex: hex::encode(grant.fields.session_nonce.as_bytes()),
            body_hash_hex: body_hash_hex.clone(),
            deployment: grant.fields.deployment.as_str().to_string(),
            issuer_generation: grant.fields.issuer_generation,
            issuer_public_key: grant.issuer_public_key,
            approved_account_key: grant.fields.approved_account_key,
            approved_manager_key: grant.fields.approved_manager_key,
            endpoint_key: *grant.fields.endpoint_key.as_bytes(),
            endpoint_incarnation: grant.fields.endpoint_incarnation.as_str().to_string(),
            boot_id: grant.fields.boot_id.as_str().to_string(),
            worker_id: grant.fields.worker_id.as_str().to_string(),
            computer_id: grant.fields.computer.as_str().to_string(),
            incarnation_id: grant.fields.incarnation.as_str().to_string(),
            desktop_generation: grant.fields.desktop_generation.as_u64(),
            display_generation: grant.fields.display_generation,
            operation: grant.fields.operation.to_string(),
            operation_intent: grant.fields.operation_intent.as_str().to_string(),
            interaction_generation: grant.fields.interaction_generation.as_u64(),
            policy_revision: grant.fields.policy_revision.as_str().to_string(),
            authority_revision: grant.fields.authority_revision.as_str().to_string(),
            channel_binding: grant.fields.channel_binding.clone(),
            issued_at_ms: grant.fields.issued_at.as_u64(),
            expires_at_ms: grant.fields.expires_at.as_u64(),
            schema_version: grant.fields.schema.clone(),
        };
        journal.record_issuance(&entry)?;

        Ok(grant)
    }

    /// Admit without Manager possession proof. Always denies.
    /// Use `admit_with_possession` for verified admission.
    pub fn admit(
        &mut self,
        _grant: &V2Grant,
        _operation: Operation,
        _receiver_store: &mut ReceiverLeaseStore,
        _intent_id: &str,
        _now_ms: u64,
        _current_mono_ms: u64,
    ) -> V2AdmissionDecision {
        V2AdmissionDecision::Denied(V2DenyReason::PossessionRequired)
    }

    /// Admit a v2 grant with verified Manager possession proof.
    ///
    /// The receiver never opens the issuer DB. Admission requires:
    /// 1. Grant cryptographic verification against pinned context
    /// 2. Verified Manager possession proof (challenge bound to grant digest)
    /// 3. Monotonic lease deadline from bounded signed validity
    /// 4. Atomic nonce consumption before permit creation
    ///
    /// The `verifier` must have been used to create the `challenge`.
    /// The `proof` is the Manager's signed response to the challenge.
    /// The `challenge` carries the grant digest binding.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_possession(
        &mut self,
        grant: &V2Grant,
        operation: Operation,
        receiver_store: &mut ReceiverLeaseStore,
        intent_id: &str,
        now_ms: u64,
        current_mono_ms: u64,
        possession: &PossessionAdmitParams<'_>,
    ) -> V2AdmissionDecision {
        if receiver_store.is_latched() {
            return V2AdmissionDecision::Denied(V2DenyReason::GateLatched);
        }
        if validate_id(intent_id).is_err() {
            return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential);
        }
        // Wall-clock rollback fails closed before any credential acceptance.
        if self
            .observe_wall_clock(now_ms, Some(receiver_store))
            .is_err()
        {
            return V2AdmissionDecision::Denied(V2DenyReason::ClockFault);
        }

        // 1. Cryptographic verification against independent pinned context.
        //    Expected values are never taken from the grant.
        if let Err(err) = grant.verify(
            &self.expected,
            &self.receiver,
            now_ms,
            V2_MAX_CANDIDATE_LIFETIME_MS,
        ) {
            return V2AdmissionDecision::Denied(map_grant_error(err));
        }

        // 2. Operation permission
        if !grant.permits(operation) {
            return V2AdmissionDecision::Denied(V2DenyReason::OperationNotPermitted);
        }

        // 2b. Caller intent_id must equal the signed operation_intent.
        //     A caller cannot invent a lease identity different from the
        //     signed credential.
        if intent_id != grant.fields.operation_intent.as_str() {
            return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential);
        }

        // 3. Manager possession proof verification
        let verified_possession = match possession
            .verifier
            .verify_possession(possession.challenge, possession.proof)
        {
            Ok(v) => v,
            Err(PeerProofError::SignatureInvalid) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionSignatureInvalid)
            }
            Err(PeerProofError::ManagerKeyMismatch) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch)
            }
            Err(PeerProofError::Expired) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionExpired)
            }
            Err(PeerProofError::ClockFault) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
            }
            Err(PeerProofError::ForeignChallenge) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge)
            }
            Err(PeerProofError::AlreadyAccepted) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
        };

        // Verify the expected manager key matches
        if verified_possession.manager_public_key() != possession.expected_manager_key.as_bytes() {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch);
        }

        // Verify the challenge's expected manager key matches the grant's
        // approved_manager_key. A challenge created for a different manager
        // cannot be used to admit this grant.
        if *possession.challenge.expected_manager_key() != grant.fields.approved_manager_key {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch);
        }

        // Verify the challenge binding matches the grant being admitted.
        // A challenge created for a different grant (different digest,
        // deployment, issuer, computer, operation, etc.) cannot be used.
        let cb = possession.challenge.binding();
        if cb.deployment != grant.fields.deployment
            || cb.issuer_public_key != grant.issuer_public_key
            || cb.issuer_generation != grant.fields.issuer_generation
            || cb.computer != grant.fields.computer
            || cb.incarnation != grant.fields.incarnation
            || cb.desktop_generation != grant.fields.desktop_generation
            || cb.operation != grant.fields.operation
            || cb.intent_id != grant.fields.operation_intent.as_str()
        {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge);
        }
        match v2_grant_digest(grant) {
            Ok(actual_digest) if cb.grant_digest == actual_digest => {}
            _ => return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge),
        }

        // 4. Durable one-shot challenge consumption. Survives restart;
        //    a consumed challenge remains denied.
        let challenge_nonce_hex = hex::encode(possession.challenge.nonce().as_bytes());
        match receiver_store.consume_challenge(&challenge_nonce_hex, intent_id, current_mono_ms) {
            Ok(()) => {}
            Err(ReceiverError::NonceAlreadyConsumed) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
            Err(ReceiverError::ClockFault(_)) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
            }
            Err(ReceiverError::GateLatched(_)) => {
                return V2AdmissionDecision::Denied(V2DenyReason::GateLatched)
            }
            Err(_) => return V2AdmissionDecision::Denied(V2DenyReason::StorageFault),
        }

        // 5. Compute lease deadline (bounded, monotonic, no late extension)
        let deadline = match receiver_store.compute_lease_deadline(
            grant.fields.expires_at.as_u64(),
            current_mono_ms,
            V2_MAX_CANDIDATE_LIFETIME_MS,
            now_ms,
        ) {
            Ok(d) => d,
            Err(ReceiverError::GrantExpired) => {
                return V2AdmissionDecision::Denied(V2DenyReason::Expired);
            }
            Err(ReceiverError::TimestampOverflow) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ClockFault);
            }
            Err(_) => {
                return V2AdmissionDecision::Denied(V2DenyReason::StorageFault);
            }
        };

        // 6. Durable controller reservation for Control operations.
        //    Reserved/Active/PendingRelease block a second controller.
        //    On lease failure the reservation is abandoned so a denied
        //    admit cannot permanently block the endpoint.
        let is_control = grant.fields.operation == Operation::Control;
        if is_control {
            let ep = *grant.fields.endpoint_key.as_bytes();
            let gen = grant.fields.desktop_generation.as_u64();
            if let Err(err) =
                receiver_store.reserve_controller(intent_id, &ep, gen, current_mono_ms)
            {
                return V2AdmissionDecision::Denied(match err {
                    ReceiverError::ControllerConflict => V2DenyReason::ControllerConflict,
                    ReceiverError::ClockFault(_) => V2DenyReason::ClockFault,
                    ReceiverError::GateLatched(_) => V2DenyReason::GateLatched,
                    _ => V2DenyReason::StorageFault,
                });
            }
            // Mirror into the in-process state machine.
            if self
                .ownership
                .reserve(ep, gen, ClaimRole::Controller, intent_id, current_mono_ms)
                .is_err()
            {
                let _ = receiver_store.abandon_controller(intent_id);
                return V2AdmissionDecision::Denied(V2DenyReason::ControllerConflict);
            }
        }

        // 7. Compute the sealed result binding BEFORE any permit is created.
        //    A failure here must not leave a committed lease behind.
        let grant_digest = match v2_grant_digest(grant) {
            Ok(d) => *d.as_bytes(),
            Err(_) => {
                if is_control {
                    let _ = receiver_store.abandon_controller(intent_id);
                    if let Some(idx) = self.ownership.find_by_intent(intent_id) {
                        let _ = self.ownership.force_release(idx);
                    }
                }
                return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential);
            }
        };

        // 8. Atomic nonce consumption + lease creation.
        //    Nonce must be persisted BEFORE the sealed result is returned.
        let nonce_hex = hex::encode(grant.fields.session_nonce.as_bytes());
        match receiver_store.consume_and_lease(ConsumeLeaseParams {
            intent_id,
            nonce_hex: &nonce_hex,
            endpoint_key: grant.fields.endpoint_key.as_bytes(),
            boot_id: grant.fields.boot_id.as_str(),
            worker_id: grant.fields.worker_id.as_str(),
            operation: &operation.to_string(),
            operation_intent: grant.fields.operation_intent.as_str(),
            desktop_generation: grant.fields.desktop_generation.as_u64(),
            display_generation: grant.fields.display_generation,
            approved_manager_key: &grant.fields.approved_manager_key,
            approved_account_key: &grant.fields.approved_account_key,
            signed_expires_at_ms: grant.fields.expires_at.as_u64(),
            lease_deadline_mono_ms: deadline,
            current_mono_ms,
        }) {
            Ok(()) => {
                if is_control {
                    // A failed durable acknowledgment must not issue a
                    // usable permit: deny, latch-facing cleanup, and free
                    // process-owned reservation state.
                    if receiver_store.acknowledge_controller(intent_id).is_err() {
                        let _ = receiver_store.request_release(intent_id, current_mono_ms);
                        let _ = receiver_store.confirm_release(intent_id, current_mono_ms);
                        let _ = receiver_store.abandon_controller(intent_id);
                        if let Some(idx) = self.ownership.find_by_intent(intent_id) {
                            let _ = self.ownership.force_release(idx);
                        }
                        return V2AdmissionDecision::Denied(V2DenyReason::StorageFault);
                    }
                    if let Some(idx) = self.ownership.find_by_intent(intent_id) {
                        let _ = self.ownership.acknowledge(idx);
                    }
                }
                V2AdmissionDecision::Granted(Box::new(VerifiedAdmission {
                    intent_id: intent_id.to_string(),
                    manager_public_key: *verified_possession.manager_public_key(),
                    granted_at_mono_ms: current_mono_ms,
                    lease_deadline_mono_ms: deadline,
                    operation_intent: grant.fields.operation_intent.as_str().to_string(),
                    endpoint_key: *grant.fields.endpoint_key.as_bytes(),
                    desktop_generation: grant.fields.desktop_generation.as_u64(),
                    operation,
                    display_generation: grant.fields.display_generation,
                    grant_digest,
                    channel_binding: grant.fields.channel_binding.clone(),
                }))
            }
            Err(ReceiverError::NonceAlreadyConsumed) => {
                if is_control {
                    let _ = receiver_store.abandon_controller(intent_id);
                    if let Some(idx) = self.ownership.find_by_intent(intent_id) {
                        let _ = self.ownership.force_release(idx);
                    }
                }
                V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
            Err(err) => {
                if is_control {
                    let _ = receiver_store.abandon_controller(intent_id);
                    if let Some(idx) = self.ownership.find_by_intent(intent_id) {
                        let _ = self.ownership.force_release(idx);
                    }
                }
                match err {
                    ReceiverError::CapacityExhausted => {
                        V2AdmissionDecision::Denied(V2DenyReason::CapacityExhausted)
                    }
                    ReceiverError::GateLatched(_) => {
                        V2AdmissionDecision::Denied(V2DenyReason::GateLatched)
                    }
                    ReceiverError::ClockFault(_) => {
                        V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
                    }
                    _ => V2AdmissionDecision::Denied(V2DenyReason::StorageFault),
                }
            }
        }
    }

    /// Request release of a controller claim (PendingRelease).
    /// Stop cleanup remains possible without audit persistence.
    pub fn request_controller_release(
        &mut self,
        intent_id: &str,
        receiver_store: &mut ReceiverLeaseStore,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        receiver_store.request_controller_release(intent_id, current_mono_ms)?;
        if let Some(idx) = self.ownership.find_by_intent(intent_id) {
            let _ = self.ownership.request_release(idx);
        }
        Ok(())
    }

    /// Confirm controller release. Frees the controller slot.
    /// Stop cleanup remains possible without audit persistence.
    pub fn confirm_controller_release(
        &mut self,
        intent_id: &str,
        receiver_store: &mut ReceiverLeaseStore,
        current_mono_ms: u64,
    ) -> Result<(), ReceiverError> {
        receiver_store.confirm_controller_release(intent_id, current_mono_ms)?;
        if let Some(idx) = self.ownership.find_by_intent(intent_id) {
            let _ = self.ownership.confirm_release(idx);
        }
        Ok(())
    }

    /// Generation-bound stop. Higher-generation claims are unaffected.
    /// Stop cleanup remains possible without audit persistence.
    pub fn stop_controller_generation(
        &mut self,
        endpoint_key: &[u8; 32],
        generation: u64,
        receiver_store: &mut ReceiverLeaseStore,
        current_mono_ms: u64,
    ) -> Result<usize, ReceiverError> {
        let stopped =
            receiver_store.stop_controller_generation(endpoint_key, generation, current_mono_ms)?;
        let _ = self.ownership.stop_generation(endpoint_key, generation);
        Ok(stopped)
    }

    /// Renew an active lease with a fresh signed credential and Manager
    /// possession proof.
    ///
    /// Validates the same independent expected/receiver context, operation
    /// binding, and possession as admission. The new lease deadline is
    /// computed from the fresh credential's signed expiry — never from a
    /// caller-supplied deadline. A duplicate fresh nonce cannot extend.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_with_possession(
        &mut self,
        fresh_grant: &V2Grant,
        operation: Operation,
        receiver_store: &mut ReceiverLeaseStore,
        intent_id: &str,
        now_ms: u64,
        current_mono_ms: u64,
        possession: &PossessionAdmitParams<'_>,
    ) -> V2AdmissionDecision {
        if receiver_store.is_latched() {
            return V2AdmissionDecision::Denied(V2DenyReason::GateLatched);
        }
        if validate_id(intent_id).is_err() {
            return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential);
        }
        if self
            .observe_wall_clock(now_ms, Some(receiver_store))
            .is_err()
        {
            return V2AdmissionDecision::Denied(V2DenyReason::ClockFault);
        }

        // Same independent verification as admit — expected is never
        // copied from the grant.
        if let Err(err) = fresh_grant.verify(
            &self.expected,
            &self.receiver,
            now_ms,
            V2_MAX_CANDIDATE_LIFETIME_MS,
        ) {
            return V2AdmissionDecision::Denied(map_grant_error(err));
        }
        if !fresh_grant.permits(operation) {
            return V2AdmissionDecision::Denied(V2DenyReason::OperationNotPermitted);
        }
        // Caller intent_id must equal the signed operation_intent.
        if intent_id != fresh_grant.fields.operation_intent.as_str() {
            return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential);
        }

        // Compare the existing lease owner and exact bound context BEFORE
        // any nonce commit. A valid grant for another manager, operation,
        // intent, endpoint, or generation cannot renew this intent.
        let existing_lease = match receiver_store.get_lease(intent_id) {
            Ok(Some(l)) => l,
            Ok(None) => return V2AdmissionDecision::Denied(V2DenyReason::Expired),
            Err(_) => return V2AdmissionDecision::Denied(V2DenyReason::StorageFault),
        };
        if existing_lease.state != crate::receiver_store::LeaseState::Active {
            return V2AdmissionDecision::Denied(V2DenyReason::Expired);
        }
        // An expired lease (including exact deadline) cannot be revived by
        // renewal. A new explicit intent/admission is required after safe
        // cleanup. The store re-checks this inside its transaction.
        if current_mono_ms >= existing_lease.lease_deadline_mono_ms {
            return V2AdmissionDecision::Denied(V2DenyReason::Expired);
        }
        if existing_lease.approved_manager_key != fresh_grant.fields.approved_manager_key
            || existing_lease.approved_account_key != fresh_grant.fields.approved_account_key
            || existing_lease.operation != operation.to_string()
            || existing_lease.operation_intent != fresh_grant.fields.operation_intent.as_str()
            || existing_lease.endpoint_key != *fresh_grant.fields.endpoint_key.as_bytes()
            || existing_lease.boot_id != fresh_grant.fields.boot_id.as_str()
            || existing_lease.worker_id != fresh_grant.fields.worker_id.as_str()
            || existing_lease.desktop_generation != fresh_grant.fields.desktop_generation.as_u64()
            || existing_lease.display_generation != fresh_grant.fields.display_generation
        {
            return V2AdmissionDecision::Denied(V2DenyReason::TargetMismatch);
        }

        // Manager possession for this fresh grant.
        let verified_possession = match possession
            .verifier
            .verify_possession(possession.challenge, possession.proof)
        {
            Ok(v) => v,
            Err(PeerProofError::SignatureInvalid) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionSignatureInvalid)
            }
            Err(PeerProofError::ManagerKeyMismatch) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch)
            }
            Err(PeerProofError::Expired) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionExpired)
            }
            Err(PeerProofError::ClockFault) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
            }
            Err(PeerProofError::ForeignChallenge) => {
                return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge)
            }
            Err(PeerProofError::AlreadyAccepted) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
        };
        if verified_possession.manager_public_key() != possession.expected_manager_key.as_bytes() {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch);
        }
        if *possession.challenge.expected_manager_key() != fresh_grant.fields.approved_manager_key {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch);
        }
        let cb = possession.challenge.binding();
        if cb.deployment != fresh_grant.fields.deployment
            || cb.issuer_public_key != fresh_grant.issuer_public_key
            || cb.issuer_generation != fresh_grant.fields.issuer_generation
            || cb.computer != fresh_grant.fields.computer
            || cb.incarnation != fresh_grant.fields.incarnation
            || cb.desktop_generation != fresh_grant.fields.desktop_generation
            || cb.operation != fresh_grant.fields.operation
            || cb.intent_id != fresh_grant.fields.operation_intent.as_str()
        {
            return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge);
        }
        match v2_grant_digest(fresh_grant) {
            Ok(actual_digest) if cb.grant_digest == actual_digest => {}
            _ => return V2AdmissionDecision::Denied(V2DenyReason::PossessionForeignChallenge),
        }

        // Durable one-shot challenge consumption for the renewal proof.
        let challenge_nonce_hex = hex::encode(possession.challenge.nonce().as_bytes());
        match receiver_store.consume_challenge(&challenge_nonce_hex, intent_id, current_mono_ms) {
            Ok(()) => {}
            Err(ReceiverError::NonceAlreadyConsumed) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
            Err(ReceiverError::ClockFault(_)) => {
                return V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
            }
            Err(ReceiverError::GateLatched(_)) => {
                return V2AdmissionDecision::Denied(V2DenyReason::GateLatched)
            }
            Err(_) => return V2AdmissionDecision::Denied(V2DenyReason::StorageFault),
        }

        let fresh_nonce_hex = hex::encode(fresh_grant.fields.session_nonce.as_bytes());
        match receiver_store.renew_lease(RenewLeaseParams {
            intent_id,
            fresh_nonce_hex: &fresh_nonce_hex,
            fresh_signed_expires_at_ms: fresh_grant.fields.expires_at.as_u64(),
            now_wall_ms: now_ms,
            current_mono_ms,
        }) {
            Ok(()) => {
                let grant_digest = match v2_grant_digest(fresh_grant) {
                    Ok(d) => *d.as_bytes(),
                    Err(_) => {
                        return V2AdmissionDecision::Denied(V2DenyReason::MalformedCredential)
                    }
                };
                let lease = receiver_store.get_lease(intent_id).ok().flatten();
                let deadline = lease
                    .map(|l| l.lease_deadline_mono_ms)
                    .unwrap_or(current_mono_ms);
                V2AdmissionDecision::Granted(Box::new(VerifiedAdmission {
                    intent_id: intent_id.to_string(),
                    manager_public_key: *verified_possession.manager_public_key(),
                    granted_at_mono_ms: current_mono_ms,
                    lease_deadline_mono_ms: deadline,
                    operation_intent: fresh_grant.fields.operation_intent.as_str().to_string(),
                    endpoint_key: *fresh_grant.fields.endpoint_key.as_bytes(),
                    desktop_generation: fresh_grant.fields.desktop_generation.as_u64(),
                    operation,
                    display_generation: fresh_grant.fields.display_generation,
                    grant_digest,
                    channel_binding: fresh_grant.fields.channel_binding.clone(),
                }))
            }
            Err(ReceiverError::NonceAlreadyConsumed) => {
                V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
            }
            Err(ReceiverError::RenewalNoExtension)
            | Err(ReceiverError::GrantExpired)
            | Err(ReceiverError::LeaseExpired) => {
                V2AdmissionDecision::Denied(V2DenyReason::Expired)
            }
            Err(ReceiverError::CapacityExhausted) => {
                V2AdmissionDecision::Denied(V2DenyReason::CapacityExhausted)
            }
            Err(ReceiverError::LeaseNotActive) | Err(ReceiverError::LeaseNotFound) => {
                V2AdmissionDecision::Denied(V2DenyReason::Expired)
            }
            Err(ReceiverError::ClockFault(_)) => {
                V2AdmissionDecision::Denied(V2DenyReason::ClockFault)
            }
            Err(ReceiverError::GateLatched(_)) => {
                V2AdmissionDecision::Denied(V2DenyReason::GateLatched)
            }
            Err(_) => V2AdmissionDecision::Denied(V2DenyReason::StorageFault),
        }
    }

    pub fn ownership(&self) -> &OwnershipManager {
        &self.ownership
    }
}

fn map_grant_error(err: V2GrantError) -> V2DenyReason {
    match err {
        V2GrantError::SignatureInvalid => V2DenyReason::SignatureInvalid,
        V2GrantError::IssuerKeyMismatch => V2DenyReason::IssuerMismatch,
        V2GrantError::SchemaMismatch => V2DenyReason::SchemaMismatch,
        V2GrantError::DeploymentMismatch => V2DenyReason::DeploymentMismatch,
        V2GrantError::EndpointMismatch => V2DenyReason::EndpointMismatch,
        V2GrantError::BootIdMismatch => V2DenyReason::BootIdMismatch,
        V2GrantError::WorkerIdMismatch => V2DenyReason::WorkerIdMismatch,
        V2GrantError::TargetMismatch => V2DenyReason::TargetMismatch,
        V2GrantError::DesktopGenerationMismatch => V2DenyReason::DesktopGenerationMismatch,
        V2GrantError::IssuerGenerationMismatch => V2DenyReason::IssuerGenerationMismatch,
        V2GrantError::AuthorityRevisionMismatch => V2DenyReason::AuthorityRevisionMismatch,
        V2GrantError::Expired => V2DenyReason::Expired,
        V2GrantError::NotYetValid => V2DenyReason::NotYetValid,
        V2GrantError::DurationExceedsBound => V2DenyReason::DurationExceedsBound,
        V2GrantError::NonPositiveDuration => V2DenyReason::NonPositiveDuration,
        V2GrantError::Structural | V2GrantError::Canonical(_) => V2DenyReason::MalformedCredential,
    }
}

/// V2 issue error.
#[derive(Debug, thiserror::Error)]
pub enum V2IssueError {
    #[error("journal error: {0}")]
    Journal(IssuerError),
    #[error("grant error: {0}")]
    Grant(V2GrantError),
    #[error("malformed credential fields")]
    Malformed,
    #[error("duration exceeds development bound")]
    DurationExceedsBound,
    #[error("signing key does not match pinned authority")]
    SigningKeyMismatch,
    #[error("gate latched closed")]
    GateLatched,
    #[error("clock fault")]
    ClockFault,
}

impl From<IssuerError> for V2IssueError {
    fn from(e: IssuerError) -> Self {
        match e {
            IssuerError::GateLatched(_) => V2IssueError::GateLatched,
            other => V2IssueError::Journal(other),
        }
    }
}

impl From<V2GrantError> for V2IssueError {
    fn from(e: V2GrantError) -> Self {
        V2IssueError::Grant(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::ElapsedClock;
    use crate::canonical_v2::V2_SCHEMA_VERSION;
    use crate::peer::{ChallengeBinding, ChannelBinding, ManagerSigningKey};
    use crate::random_32;
    use std::rc::Rc;

    /// Generate a deterministic test manager signing key.
    fn test_manager_key() -> ManagerSigningKey {
        ManagerSigningKey::from_bytes(&[0xCCu8; 32])
    }

    fn v2_fields(
        key: &IssuerSigningKey,
        now: u64,
        mgr_vk: &ManagerVerifyingKey,
        intent: &str,
    ) -> CanonicalV2Fields {
        let issued = TimestampMs::new(now.saturating_sub(500).max(1)).unwrap();
        let expires = TimestampMs::new(
            now.saturating_add(5_000)
                .min(issued.as_u64() + V2_MAX_CANDIDATE_LIFETIME_MS),
        )
        .unwrap();
        CanonicalV2Fields {
            schema: V2_SCHEMA_VERSION.to_string(),
            deployment: DeploymentId::new("deploy-1").unwrap(),
            issuer_generation: 1,
            issuer_public_key: *key.verifying_key().as_bytes(),
            approved_account_key: [0xBBu8; 32],
            approved_manager_key: *mgr_vk.as_bytes(),
            endpoint_key: EndpointKey::new([0xDDu8; 32]).unwrap(),
            endpoint_incarnation: EndpointIncarnation::new("ep-inc-1").unwrap(),
            boot_id: BootId::new("boot-1").unwrap(),
            worker_id: WorkerId::new("worker-1").unwrap(),
            computer: ComputerId::new("room7-a03").unwrap(),
            incarnation: IncarnationId::new("inc-abc").unwrap(),
            desktop_generation: DesktopGeneration::new(3).unwrap(),
            display_generation: 2,
            operation: Operation::Observe,
            // Caller intent_id must equal this signed operation_intent.
            operation_intent: OperationIntent::new(intent).unwrap(),
            interaction_generation: InteractionGeneration::new(1).unwrap(),
            policy_revision: PolicyRevision::new("policy-2026").unwrap(),
            authority_revision: AuthorityRevision::new("rev-1").unwrap(),
            channel_binding: b"channel-v2-binding".to_vec(),
            session_nonce: Nonce::new(random_32()).unwrap(),
            issued_at: issued,
            expires_at: expires,
        }
    }

    fn v2_expected(key: &IssuerSigningKey) -> V2ExpectedAuthority {
        V2ExpectedAuthority {
            issuer_public_key: *key.verifying_key().as_bytes(),
            issuer_generation: 1,
            deployment: DeploymentId::new("deploy-1").unwrap(),
            schema: V2_SCHEMA_VERSION.to_string(),
            authority_revision: AuthorityRevision::new("rev-1").unwrap(),
        }
    }

    fn v2_receiver() -> V2ReceiverContext {
        V2ReceiverContext {
            endpoint_key: EndpointKey::new([0xDDu8; 32]).unwrap(),
            boot_id: BootId::new("boot-1").unwrap(),
            worker_id: WorkerId::new("worker-1").unwrap(),
            computer: ComputerId::new("room7-a03").unwrap(),
            incarnation: IncarnationId::new("inc-abc").unwrap(),
            desktop_generation: DesktopGeneration::new(3).unwrap(),
        }
    }

    fn unique_intent(tag: &str) -> String {
        format!("{tag}-{}", hex::encode(random_32()))
    }

    /// Test helper: wrapper for ManualElapsedClock that can be shared via Rc.
    struct CloneClock(Rc<crate::admission::ManualElapsedClock>);
    impl ElapsedClock for CloneClock {
        fn elapsed_ms(&self) -> u64 {
            self.0.elapsed_ms()
        }
    }

    /// Create a valid possession proof for a grant using the given manager
    /// signing key (whose verifying key must match the grant's
    /// `approved_manager_key`). Returns (verifier, challenge, proof,
    /// manager_verifying_key, clock).
    fn create_valid_possession(
        grant: &V2Grant,
        issuer_pk: &[u8; 32],
        start_ms: u64,
        mgr_key: &ManagerSigningKey,
    ) -> (
        PeerPossessionVerifier,
        crate::peer::PeerChallenge,
        PossessionProof,
        ManagerVerifyingKey,
        Rc<crate::admission::ManualElapsedClock>,
    ) {
        let digest = v2_grant_digest(grant).expect("grant digest");
        let binding = ChallengeBinding {
            deployment: grant.fields.deployment.clone(),
            issuer_public_key: *issuer_pk,
            issuer_generation: grant.fields.issuer_generation,
            computer: grant.fields.computer.clone(),
            incarnation: grant.fields.incarnation.clone(),
            desktop_generation: grant.fields.desktop_generation,
            operation: grant.fields.operation,
            intent_id: grant.fields.operation_intent.as_str().to_string(),
            grant_digest: digest,
            channel_binding: ChannelBinding::new(&grant.fields.channel_binding).unwrap(),
        };
        let clock = Rc::new(crate::admission::ManualElapsedClock::new(start_ms));
        let verifier = PeerPossessionVerifier::new(Box::new(CloneClock(clock.clone())));
        let challenge = verifier
            .create_challenge(binding, &mgr_key.verifying_key(), 30_000)
            .expect("challenge");
        let proof = mgr_key.prove_possession(&challenge);
        (verifier, challenge, proof, mgr_key.verifying_key(), clock)
    }

    #[test]
    fn v2_admit_without_possession_always_denies() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("no-poss");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let result = ctrl.admit(&grant, Operation::Observe, &mut recv, &intent, 1500, 100);
        assert_eq!(
            result,
            V2AdmissionDecision::Denied(V2DenyReason::PossessionRequired)
        );
    }

    #[test]
    fn v2_issue_and_admit_with_possession_roundtrip() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("roundtrip");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let (verifier, challenge, proof, mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        let decision = ctrl.admit_with_possession(
            &grant,
            Operation::Observe,
            &mut recv,
            &intent,
            1500,
            100,
            &PossessionAdmitParams {
                verifier: &verifier,
                challenge: &challenge,
                proof: &proof,
                expected_manager_key: &mgr_vk,
            },
        );
        assert!(matches!(decision, V2AdmissionDecision::Granted(_)));
    }

    #[test]
    fn v2_replay_rejected_with_possession() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("replay");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let (verifier, challenge, proof, mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        assert!(matches!(
            ctrl.admit_with_possession(
                &grant,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk
                },
            ),
            V2AdmissionDecision::Granted(_)
        ));
        // Replay with same grant (nonce already consumed)
        assert_eq!(
            ctrl.admit_with_possession(
                &grant,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                200,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk
                },
            ),
            V2AdmissionDecision::Denied(V2DenyReason::ReplayDetected)
        );
    }

    #[test]
    fn v2_wrong_issuer_key_rejected_at_issue() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let wrong_key = IssuerSigningKey::generate();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("w");
        assert!(matches!(
            ctrl.issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &wrong_key,
                &mut journal,
                &intent,
                1500
            ),
            Err(V2IssueError::SigningKeyMismatch)
        ));
    }

    #[test]
    fn v2_wrong_receiver_context_rejected() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("wrong-ctx");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let wrong_recv = V2ReceiverContext {
            boot_id: BootId::new("boot-other").unwrap(),
            ..v2_receiver()
        };
        let mut ctrl2 = V2AdmissionController::new(v2_expected(&key), wrong_recv);
        let (verifier, challenge, proof, mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        assert_eq!(
            ctrl2.admit_with_possession(
                &grant,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk
                },
            ),
            V2AdmissionDecision::Denied(V2DenyReason::BootIdMismatch)
        );
    }

    #[test]
    fn v2_signature_mutation_rejected() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("sig-mut");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let mut bad_sig = grant.clone();
        bad_sig.signature[0] ^= 0xFF;
        let (verifier, challenge, proof, mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        assert_eq!(
            ctrl.admit_with_possession(
                &bad_sig,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk
                },
            ),
            V2AdmissionDecision::Denied(V2DenyReason::SignatureInvalid)
        );
    }

    #[test]
    fn v2_operation_not_permitted() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("scope");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let (verifier, challenge, proof, mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        // Grant is for Observe, trying Control
        assert_eq!(
            ctrl.admit_with_possession(
                &grant,
                Operation::Control,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk
                },
            ),
            V2AdmissionDecision::Denied(V2DenyReason::OperationNotPermitted)
        );
    }

    #[test]
    fn v2_wrong_manager_key_rejected() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let mut journal = IssuerJournal::create_memory().unwrap();
        journal
            .initialize(key.verifying_key().as_bytes(), 1)
            .unwrap();
        let mut recv = ReceiverLeaseStore::create_memory(0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
        let intent = unique_intent("wrong-mgr");
        let grant = ctrl
            .issue(
                v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                &key,
                &mut journal,
                &intent,
                1500,
            )
            .unwrap();
        let (verifier, challenge, _proof, _mgr_vk, _clock) =
            create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
        // Create proof with wrong manager key
        let wrong_mgr = ManagerSigningKey::generate();
        let wrong_proof = wrong_mgr.prove_possession(&challenge);
        assert_eq!(
            ctrl.admit_with_possession(
                &grant,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &wrong_proof,
                    expected_manager_key: &wrong_mgr.verifying_key()
                },
            ),
            V2AdmissionDecision::Denied(V2DenyReason::PossessionManagerKeyMismatch)
        );
    }

    #[test]
    fn v2_receiver_reopen_fences_old_leases() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recv-integ.db");
        {
            let mut recv = ReceiverLeaseStore::create(&path, 0).unwrap();
            recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
                .unwrap();
            let mut journal = IssuerJournal::create_memory().unwrap();
            journal
                .initialize(key.verifying_key().as_bytes(), 1)
                .unwrap();
            let mut ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
            let intent = unique_intent("reopen");
            let grant = ctrl
                .issue(
                    v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                    &key,
                    &mut journal,
                    &intent,
                    1500,
                )
                .unwrap();
            let (verifier, challenge, proof, mgr_vk, _clock) =
                create_valid_possession(&grant, key.verifying_key().as_bytes(), 100, &mgr);
            let decision = ctrl.admit_with_possession(
                &grant,
                Operation::Observe,
                &mut recv,
                &intent,
                1500,
                100,
                &PossessionAdmitParams {
                    verifier: &verifier,
                    challenge: &challenge,
                    proof: &proof,
                    expected_manager_key: &mgr_vk,
                },
            );
            assert!(matches!(decision, V2AdmissionDecision::Granted(_)));
        }
        // Reopen: old leases must be fenced, store not latched
        let recv2 = ReceiverLeaseStore::open(&path, 0).unwrap();
        assert!(!recv2.is_latched());
    }

    #[test]
    fn v2_issuer_journal_separate_from_receiver() {
        let key = IssuerSigningKey::generate();
        let mgr = test_manager_key();
        let dir = tempfile::tempdir().unwrap();
        let issuer_path = dir.path().join("issuer.db");
        let recv_path = dir.path().join("receiver.db");
        {
            let mut journal = IssuerJournal::create(&issuer_path).unwrap();
            journal
                .initialize(key.verifying_key().as_bytes(), 1)
                .unwrap();
            let ctrl = V2AdmissionController::new(v2_expected(&key), v2_receiver());
            let intent = unique_intent("sep");
            let _grant = ctrl
                .issue(
                    v2_fields(&key, 1500, &mgr.verifying_key(), &intent),
                    &key,
                    &mut journal,
                    &intent,
                    1500,
                )
                .unwrap();
        }
        let mut recv = ReceiverLeaseStore::create(&recv_path, 0).unwrap();
        recv.initialize(key.verifying_key().as_bytes(), 1, &[0xDDu8; 32])
            .unwrap();
        assert!(!recv.is_latched());
    }
}
