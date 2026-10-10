//! Admission controller: the public gate for credential issuance and
//! peer admission.
//!
//! Every decision uses independent trusted receiver context and the
//! persisted authority binding. Credential claims are never their own
//! expected values. Issuance returns signed bytes only after a concrete
//! durable commit of the full credential binding.
//!
//! Bounded development proof limits apply. Not production E06 budgets.

use crate::canonical::CanonicalFields;
use crate::grant::{ExpectedAuthority, Grant, GrantError};
use crate::keys::IssuerSigningKey;
use crate::store::{DurableStore, IssuedCredential, StoreError, TrustBinding};
use crate::types::*;

/// Hard maximum candidate credential lifetime (30 seconds in ms).
/// Values greater than this are rejected on public issue and admit.
/// The exact bound is allowed. This is not a measured latency guarantee.
pub const MAX_CANDIDATE_LIFETIME_MS: u64 = 30_000;

/// Clock fault. Propagates as deny; backward wall movement also latches.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClockError {
    #[error("wall clock before Unix epoch")]
    PreEpoch,
    #[error("counter exhausted")]
    CounterExhausted,
    #[error("backward wall movement: last={last} now={now}")]
    BackwardMovement { last: u64, now: u64 },
}

/// Signed-epoch validity clock (wall/scheduled time used for credential
/// issued/expires bounds). Distinct from local monotonic lease time.
pub trait ValidityClock {
    fn now_ms(&self) -> Result<u64, ClockError>;
}

/// System wall clock for signed-epoch validity. Fails closed on pre-epoch
/// and on backward movement relative to the last reading.
pub struct SystemEpochClock {
    last_ms: std::cell::Cell<Option<u64>>,
}

impl SystemEpochClock {
    pub fn new() -> Self {
        Self {
            last_ms: std::cell::Cell::new(None),
        }
    }
}

impl Default for SystemEpochClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidityClock for SystemEpochClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::PreEpoch)?;
        let now = u64::try_from(dur.as_millis()).map_err(|_| ClockError::CounterExhausted)?;
        if let Some(last) = self.last_ms.get() {
            if now < last {
                return Err(ClockError::BackwardMovement { last, now });
            }
        }
        self.last_ms.set(Some(now));
        Ok(now)
    }
}

/// Manual validity clock for deterministic tests. Checked advance; counter
/// never wraps.
pub struct ManualEpochClock {
    ms: std::cell::Cell<u64>,
    last_ms: std::cell::Cell<Option<u64>>,
}

impl ManualEpochClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            ms: std::cell::Cell::new(start_ms),
            last_ms: std::cell::Cell::new(None),
        }
    }

    /// Checked advance. Overflow is a clock fault, not a wrap.
    pub fn advance(&self, delta_ms: u64) -> Result<(), ClockError> {
        let cur = self.ms.get();
        let next = cur
            .checked_add(delta_ms)
            .ok_or(ClockError::CounterExhausted)?;
        self.ms.set(next);
        Ok(())
    }

    /// Set an absolute time. Backward sets are permitted here only for
    /// tests that *intend* to simulate rollback; `now_ms` then reports
    /// `BackwardMovement` against the last observed reading.
    pub fn set(&self, ms: u64) {
        self.ms.set(ms);
    }
}

impl ValidityClock for ManualEpochClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        let now = self.ms.get();
        if let Some(last) = self.last_ms.get() {
            if now < last {
                return Err(ClockError::BackwardMovement { last, now });
            }
        }
        self.last_ms.set(Some(now));
        Ok(now)
    }
}

/// Local monotonic lease/checkpoint source. Separate from signed-epoch
/// validity: `Instant` cannot go backwards, so leases never extend on
/// wall-clock rollback.
pub struct MonotonicLeaseClock {
    start: std::time::Instant,
}

impl MonotonicLeaseClock {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Elapsed milliseconds since this lease clock was created.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

impl Default for MonotonicLeaseClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Monotonic elapsed-time source for bounded challenge deadlines.
/// Distinct from `ValidityClock`: this never supplies signed wall time.
pub trait ElapsedClock {
    fn elapsed_ms(&self) -> u64;
}

impl ElapsedClock for MonotonicLeaseClock {
    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

/// Manual monotonic clock for deterministic challenge-deadline tests.
pub struct ManualElapsedClock {
    ms: std::cell::Cell<u64>,
}

impl ManualElapsedClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            ms: std::cell::Cell::new(start_ms),
        }
    }

    /// Checked advance. Overflow is a clock fault, not a wrap.
    pub fn advance(&self, delta_ms: u64) -> Result<(), ClockError> {
        let cur = self.ms.get();
        let next = cur
            .checked_add(delta_ms)
            .ok_or(ClockError::CounterExhausted)?;
        self.ms.set(next);
        Ok(())
    }
}

impl ElapsedClock for ManualElapsedClock {
    fn elapsed_ms(&self) -> u64 {
        self.ms.get()
    }
}

/// Admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Credential accepted for this operation.
    Granted,
    /// Credential rejected.
    Denied(DenyReason),
}

/// Reason for denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Signature or key verification failed.
    SignatureInvalid,
    /// Issuer key does not match pinned active authority.
    IssuerMismatch,
    /// Schema version mismatch.
    SchemaMismatch,
    /// Deployment ID mismatch.
    DeploymentMismatch,
    /// Target computer/incarnation/account/manager mismatch.
    TargetMismatch,
    /// Desktop generation is not current.
    DesktopGenerationStale,
    /// Credential expired (now >= expires_at).
    Expired,
    /// Credential not yet valid.
    NotYetValid,
    /// Issuer generation mismatch (copied/restored server).
    IssuerGenerationMismatch,
    /// Authority revision mismatch.
    AuthorityRevisionMismatch,
    /// Nonce already claimed (replay).
    ReplayDetected,
    /// Operation not permitted by action scope.
    OperationNotPermitted,
    /// Epoch closed.
    EpochClosed,
    /// Duration exceeds development proof bound.
    DurationExceedsBound,
    /// Duration is not strictly positive.
    NonPositiveDuration,
    /// Structural field rejection (zero generation/desktop, bad times).
    MalformedCredential,
    /// Clock fault (pre-epoch, counter exhaustion, rollback).
    ClockFault,
    /// Storage fault; gate latched.
    StorageFault,
    /// Trust binding missing or corrupt.
    TrustStateCorrupt,
    /// Persisted trust binding disagrees with this controller.
    TrustBindingMismatch,
    /// Hard capacity exhausted; fail closed.
    CapacityExhausted,
    /// Gate latched closed after a required IO fault.
    GateLatched,
}

/// Issue error (public issuance path).
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("store error: {0}")]
    Store(StoreError),
    #[error("grant error: {0}")]
    Grant(GrantError),
    #[error("clock fault: {0}")]
    Clock(ClockError),
    #[error("epoch closed")]
    EpochClosed,
    #[error("duration exceeds development bound")]
    DurationExceedsBound,
    #[error("malformed credential fields")]
    Malformed,
    #[error("trust state missing or corrupt")]
    TrustStateCorrupt,
    #[error("signing key does not match pinned authority")]
    SigningKeyMismatch,
    #[error("gate latched closed")]
    GateLatched,
}

impl From<StoreError> for IssueError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::EpochClosed => IssueError::EpochClosed,
            StoreError::GateLatched(_) => IssueError::GateLatched,
            StoreError::TrustNotInitialized | StoreError::TrustStateCorrupt => {
                IssueError::TrustStateCorrupt
            }
            other => IssueError::Store(other),
        }
    }
}

impl From<GrantError> for IssueError {
    fn from(e: GrantError) -> Self {
        IssueError::Grant(e)
    }
}

impl From<ClockError> for IssueError {
    fn from(e: ClockError) -> Self {
        IssueError::Clock(e)
    }
}

/// Issued grant: signed credential plus the durable record identity.
#[derive(Debug, Clone)]
pub struct IssuedGrant {
    pub grant: Grant,
    pub intent_id: String,
    pub body_hash_hex: String,
}

/// Admission controller. Transport-independent.
pub struct AdmissionController {
    expected: ExpectedAuthority,
    clock: Box<dyn ValidityClock>,
}

impl AdmissionController {
    /// Pin the expected authority binding for this controller.
    pub fn try_new(
        binding: TrustBinding,
        clock: Box<dyn ValidityClock>,
    ) -> Result<Self, TypeError> {
        Ok(Self {
            expected: ExpectedAuthority {
                issuer_public_key: binding.issuer_public_key,
                issuer_generation: binding.issuer_generation,
                authority_revision: AuthorityRevision::new(binding.authority_revision)?,
                deployment: DeploymentId::new(binding.deployment)?,
                schema: binding.schema,
            },
            clock,
        })
    }

    /// Public issuance. Returns signed bytes only after a concrete durable
    /// commit of the exact canonical body hash and full authority binding.
    /// Wrong signing key / authority / schema / generation / target / time
    /// is rejected before any store write.
    pub fn issue(
        &self,
        fields: CanonicalFields,
        signing_key: &IssuerSigningKey,
        store: &mut DurableStore,
        intent_id: &str,
    ) -> Result<IssuedGrant, IssueError> {
        if store.is_latched() {
            return Err(IssueError::GateLatched);
        }
        crate::types::validate_id(intent_id).map_err(|_| IssueError::Malformed)?;

        // Reject before store: authority, schema, generation, time, structure.
        fields
            .validate_structure()
            .map_err(|_| IssueError::Malformed)?;

        if fields.schema != self.expected.schema {
            return Err(IssueError::Malformed);
        }
        if fields.deployment != self.expected.deployment {
            return Err(IssueError::Malformed);
        }
        if fields.issuer_generation != self.expected.issuer_generation {
            return Err(IssueError::Malformed);
        }
        if fields.authority_revision != self.expected.authority_revision {
            return Err(IssueError::Malformed);
        }

        let now_ms = self.clock.now_ms()?;
        if now_ms >= fields.expires_at.as_u64() {
            return Err(IssueError::Malformed);
        }
        if now_ms < fields.issued_at.as_u64() {
            return Err(IssueError::Malformed);
        }
        let lifetime = checked_duration_ms(fields.issued_at, fields.expires_at)
            .map_err(|_| IssueError::Malformed)?;
        if lifetime == 0 || lifetime > MAX_CANDIDATE_LIFETIME_MS {
            return Err(IssueError::DurationExceedsBound);
        }

        // Signing key must match the pinned issuer key.
        if *signing_key.verifying_key().as_bytes() != self.expected.issuer_public_key {
            return Err(IssueError::SigningKeyMismatch);
        }

        let grant = Grant::sign_credential(fields, signing_key)?;
        let body_hash_hex = hex::encode(grant.body_hash()?);

        let cred = IssuedCredential {
            intent_id: intent_id.to_string(),
            nonce_hex: hex::encode(grant.fields.session_nonce.as_bytes()),
            body_hash_hex: body_hash_hex.clone(),
            computer_id: grant.fields.computer.as_str().to_string(),
            incarnation_id: grant.fields.incarnation.as_str().to_string(),
            account_id: grant.fields.account.as_str().to_string(),
            manager_id: grant.fields.manager.as_str().to_string(),
            desktop_generation: grant.fields.desktop_generation.as_u64(),
            scope_ops: scope_ops_string(&grant),
            issued_at_ms: grant.fields.issued_at.as_u64(),
            expires_at_ms: grant.fields.expires_at.as_u64(),
            issuer_public_key: grant.issuer_public_key,
            issuer_generation: grant.fields.issuer_generation,
            authority_revision: grant.fields.authority_revision.as_str().to_string(),
            deployment: grant.fields.deployment.as_str().to_string(),
            schema: grant.fields.schema.clone(),
        };

        // Trust/epoch/fault/capacity/binding checks + insert are atomic.
        store.commit_issuance(&cred)?;

        Ok(IssuedGrant {
            grant,
            intent_id: intent_id.to_string(),
            body_hash_hex,
        })
    }

    /// Public admission. Compares every signed field to independent trusted
    /// receiver context. On success the nonce is claimed exactly once.
    /// The claimed row is compared to the full expected issued credential
    /// (hash, nonce, intent, identity, authority) inside the claim IMMEDIATE
    /// transaction. Bad signature, target, or scope never consumes a nonce.
    ///
    /// This is a **same-store centralized** candidate proof. `intent_id` must
    /// match the issuance intent; it is not distributed endpoint admission.
    pub fn admit(
        &self,
        grant: &Grant,
        operation: Operation,
        receiver: &ReceiverContext,
        store: &mut DurableStore,
        intent_id: &str,
    ) -> AdmissionDecision {
        if store.refresh_fault_state().is_err() || store.is_latched() {
            return AdmissionDecision::Denied(DenyReason::GateLatched);
        }
        if crate::types::validate_id(intent_id).is_err() {
            return AdmissionDecision::Denied(DenyReason::MalformedCredential);
        }

        let now_ms = match self.clock.now_ms() {
            Ok(n) => n,
            Err(ClockError::BackwardMovement { .. }) => {
                // Backward wall movement: deny and latch; never extend lease.
                store.latch_fault("backward wall clock movement");
                return AdmissionDecision::Denied(DenyReason::ClockFault);
            }
            Err(_) => return AdmissionDecision::Denied(DenyReason::ClockFault),
        };

        if let Err(err) =
            grant.verify_admission(&self.expected, receiver, now_ms, MAX_CANDIDATE_LIFETIME_MS)
        {
            return AdmissionDecision::Denied(match err {
                GrantError::SignatureInvalid => DenyReason::SignatureInvalid,
                GrantError::IssuerKeyMismatch => DenyReason::IssuerMismatch,
                GrantError::SchemaMismatch => DenyReason::SchemaMismatch,
                GrantError::DeploymentMismatch => DenyReason::DeploymentMismatch,
                GrantError::TargetMismatch => DenyReason::TargetMismatch,
                GrantError::IssuerGenerationMismatch => DenyReason::IssuerGenerationMismatch,
                GrantError::AuthorityRevisionMismatch => DenyReason::AuthorityRevisionMismatch,
                GrantError::Expired => DenyReason::Expired,
                GrantError::NotYetValid => DenyReason::NotYetValid,
                GrantError::DurationExceedsBound => DenyReason::DurationExceedsBound,
                GrantError::NonPositiveDuration => DenyReason::NonPositiveDuration,
                GrantError::Structural | GrantError::Canonical(_) => {
                    DenyReason::MalformedCredential
                }
            });
        }

        // Scope is an authorization check and must not consume the nonce.
        if !grant.permits(operation) {
            return AdmissionDecision::Denied(DenyReason::OperationNotPermitted);
        }

        let body_hash_hex = match grant.body_hash() {
            Ok(h) => hex::encode(h),
            Err(_) => return AdmissionDecision::Denied(DenyReason::MalformedCredential),
        };
        let expected = IssuedCredential {
            intent_id: intent_id.to_string(),
            nonce_hex: hex::encode(grant.fields.session_nonce.as_bytes()),
            body_hash_hex,
            computer_id: grant.fields.computer.as_str().to_string(),
            incarnation_id: grant.fields.incarnation.as_str().to_string(),
            account_id: grant.fields.account.as_str().to_string(),
            manager_id: grant.fields.manager.as_str().to_string(),
            desktop_generation: grant.fields.desktop_generation.as_u64(),
            scope_ops: scope_ops_string(grant),
            issued_at_ms: grant.fields.issued_at.as_u64(),
            expires_at_ms: grant.fields.expires_at.as_u64(),
            issuer_public_key: grant.issuer_public_key,
            issuer_generation: grant.fields.issuer_generation,
            authority_revision: grant.fields.authority_revision.as_str().to_string(),
            deployment: grant.fields.deployment.as_str().to_string(),
            schema: grant.fields.schema.clone(),
        };

        // Atomic receiver consumption with full issued-row comparison.
        match store.claim_nonce(&expected, now_ms) {
            Ok(()) => AdmissionDecision::Granted,
            Err(StoreError::NonceReplayed) => AdmissionDecision::Denied(DenyReason::ReplayDetected),
            Err(StoreError::EpochClosed) => AdmissionDecision::Denied(DenyReason::EpochClosed),
            Err(StoreError::CapacityExhausted) => {
                AdmissionDecision::Denied(DenyReason::CapacityExhausted)
            }
            Err(StoreError::GateLatched(_)) => AdmissionDecision::Denied(DenyReason::GateLatched),
            Err(StoreError::TrustNotInitialized)
            | Err(StoreError::TrustStateCorrupt)
            | Err(StoreError::TrustBindingMismatch) => {
                AdmissionDecision::Denied(DenyReason::TrustStateCorrupt)
            }
            Err(StoreError::IssuedMismatch) | Err(StoreError::IntentMismatch) => {
                AdmissionDecision::Denied(DenyReason::MalformedCredential)
            }
            Err(_) => AdmissionDecision::Denied(DenyReason::StorageFault),
        }
    }
}

fn scope_ops_string(grant: &Grant) -> String {
    grant
        .fields
        .action_scope
        .operations()
        .iter()
        .map(|o| o.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
