//! Observation, control, and teardown lifecycle.
//!
//! D19: multiple authorized viewers coexist independently; one controller
//! owns a computer at a time. One operator's pause cannot stop other viewers.
//! D24: minimizing a remote-control window releases control and keeps
//! viewing; restoration requires explicit Take Control. Focus loss stops
//! forwarding and releases held input without ending the controller lease.
//! Desktop change, expiry, revocation, and process failure tear down access.
//!
//! Conservative pending release: an unacknowledged control release keeps the
//! controller slot occupied. Restore, refocus, or a late acknowledgment cannot
//! reactivate that claim. Take Control cannot start while the previous claim's
//! release is unresolved.

use crate::action::TimestampMs;
use crate::bounds::{
    DEFAULT_CONTROL_LEASE_MS, DEFAULT_OBSERVATION_LEASE_MS, DEFAULT_PENDING_RELEASE_TIMEOUT_MS,
    MAX_INTERACTION_CLAIMS_PER_COMPUTER, MAX_OBSERVERS_PER_COMPUTER, MAX_SHARE_RECEIVERS,
};
use crate::error::{Error, Result};
use crate::id::{
    AccountId, ComputerId, DesktopGeneration, InteractionGeneration, InteractionId, ManagerId,
    MonitoringId,
};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Interaction kinds with separate lifecycles and ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InteractionKind {
    /// Live view only. Never implies control.
    Observation,
    /// Exclusive remote input authority.
    Control,
    /// Outgoing share source distribution.
    ShareSource,
    /// Incoming share receiver presentation.
    ShareReceiver,
    /// Temporary managed restriction with a plain message.
    Attention,
}

/// Observation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationState {
    /// Requested; no pixels yet.
    Requested,
    /// Connecting under fresh current-desktop admission.
    Connecting,
    /// Admitted live stream.
    Live,
    /// Stream is stalled; receiver shows honest age.
    Stalled,
    /// Ending; authority is being torn down.
    Ending,
    /// Ended. Late frames cannot resurrect.
    Ended,
    /// Failed with a named reason.
    Failed,
}

/// Control lifecycle state. Pending Release is conservative and honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlState {
    /// Take Control requested.
    Requested,
    /// Waiting for endpoint acknowledgment of unique controller lease.
    Authorizing,
    /// Exclusive controller; input may be forwarded only while the remote
    /// canvas has explicit focus and no local UI surface is active.
    Controlling,
    /// Release requested/started; no new input is accepted.
    Stopping,
    /// Release acknowledged. View-only observation may continue separately.
    Stopped,
    /// Release not yet acknowledged; slot stays occupied, retake refused.
    PendingRelease,
    /// Failed with a named reason.
    Failed,
}

/// Shared interaction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interaction {
    /// Stable interaction identity.
    pub id: InteractionId,
    /// Kind.
    pub kind: InteractionKind,
    /// Owning account. Never a caller-supplied display name.
    pub owner_account_id: AccountId,
    /// Owning manager identity.
    pub owner_manager_id: ManagerId,
    /// Optional monitoring context.
    pub monitoring_id: Option<MonitoringId>,
    /// Target computer.
    pub computer_id: ComputerId,
    /// Desktop generation bound at admission.
    pub desktop_generation: DesktopGeneration,
    /// Fencing counter for late callbacks/frames.
    pub generation: InteractionGeneration,
    /// Expiry timestamp; renewal cannot extend an existing lease without a
    /// fresh authority.
    pub expires_at: TimestampMs,
    /// True while input forwarding is permitted (control only, and only while
    /// the remote canvas has explicit focus).
    pub input_forwarding: bool,
    /// Tracked injected keys/buttons currently held. Released on every exit.
    pub held_input_count: u32,
    /// Lifecycle state for the interaction kind.
    pub state: InteractionState,
    /// True once the interaction has ended and cannot be resurrected.
    pub ended: bool,
}

/// Unified lifecycle state covering observation and control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionState {
    /// Requested.
    Requested,
    /// Connecting / authorizing.
    Connecting,
    /// Live observation.
    Live,
    /// Controlling (control only).
    Controlling,
    /// Stalled observation.
    Stalled,
    /// Ending / stopping.
    Ending,
    /// Pending release (control only).
    PendingRelease,
    /// Ended.
    Ended,
    /// Failed.
    Failed,
}

/// Result of a D24 minimize on a control window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizeOutcome {
    /// Held input was released and forwarding stopped.
    pub released_input: bool,
    /// Fresh fencing generation for late events.
    ///
    /// `None` means the generation counter is exhausted: teardown still ran,
    /// but no new reusable generation exists. Callers must refuse new control
    /// authority rather than reuse the current generation.
    pub generation_fenced: Option<InteractionGeneration>,
    /// Control must be re-taken explicitly; restore never resumes it.
    pub control_disposition: ControlDisposition,
    /// Separately authorized observation stays active.
    pub observation_preserved: bool,
}

/// What the UI must do about control after a lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlDisposition {
    /// Show Viewing only; Take Control is explicit and required again.
    RequireExplicitRetake,
    /// Release is still unresolved; show Pending Release and refuse retake.
    PendingRelease,
}

/// Requested operation for the shared interaction conflict contract.
///
/// The identifier variant keeps interactions and machine actions distinct.
/// These values are domain inputs, not signed authority or a wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOperation {
    /// Start or reuse view-only observation.
    Observe(InteractionId),
    /// Request unique input control.
    TakeControl(InteractionId),
    /// Start or reuse an outgoing sharing source.
    ShareSource(InteractionId),
    /// Start or reuse an incoming sharing receiver.
    ShareReceiver(InteractionId),
    /// Apply or reuse a temporary attention interaction.
    Attention(InteractionId),
    /// Dispatch or retrieve the result of one typed machine action.
    MachineAction(crate::id::ActionId, crate::capability::MachineActionKind),
}

impl TransitionOperation {
    fn requested_kind(&self) -> RequestedKind {
        match self {
            Self::Observe(_) => RequestedKind::Observation,
            Self::TakeControl(_) => RequestedKind::Control,
            Self::ShareSource(_) => RequestedKind::ShareSource,
            Self::ShareReceiver(_) => RequestedKind::ShareReceiver,
            Self::Attention(_) => RequestedKind::Attention,
            Self::MachineAction(_, _) => RequestedKind::MachineAction,
        }
    }

    fn interaction_id(&self) -> Option<&InteractionId> {
        match self {
            Self::Observe(id)
            | Self::TakeControl(id)
            | Self::ShareSource(id)
            | Self::ShareReceiver(id)
            | Self::Attention(id) => Some(id),
            Self::MachineAction(_, _) => None,
        }
    }
}

/// Opaque digest of the canonical, fully validated operation payload.
///
/// Equality supports stable-ID replay checks. It is not authority or a grant
/// format; E03 must define the canonical payload encoding before network use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationFingerprint(pub [u8; 32]);

/// Current idempotency owner and typed operation for a reserved machine action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMachineAction {
    /// Stable action identity.
    pub id: crate::id::ActionId,
    /// Authenticated owning account.
    pub owner_account_id: AccountId,
    /// Authenticated owning manager.
    pub owner_manager_id: ManagerId,
    /// Typed operation already reserved for this identity.
    pub kind: crate::capability::MachineActionKind,
    /// Fingerprint of the full typed request payload.
    pub operation_fingerprint: OperationFingerprint,
}

/// The authenticated actor identity passed by the server after session checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionActor {
    /// Account identity.
    pub account_id: AccountId,
    /// Once-approved manager identity.
    pub manager_id: ManagerId,
}

/// Snapshot of one interaction claim on the requested computer.
///
/// Callers include claims that are Requested, Stopping, Releasing, or in
/// Pending Release. Only Ended and Failed claims have released their slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionClaim {
    /// Stable interaction identity.
    pub id: InteractionId,
    /// Fingerprint of the full typed operation payload.
    pub operation_fingerprint: OperationFingerprint,
    /// Claimed operation.
    pub kind: InteractionKind,
    /// Authenticated owning account.
    pub owner_account_id: AccountId,
    /// Authenticated owning manager.
    pub owner_manager_id: ManagerId,
    /// Computer whose operation slot is claimed.
    pub computer_id: ComputerId,
    /// Other computers affected by this claim, such as fixed share receivers.
    pub affected_computer_ids: Vec<ComputerId>,
    /// Current lifecycle state.
    pub state: InteractionState,
}

impl InteractionClaim {
    fn occupies_slot(&self) -> bool {
        !matches!(
            self.state,
            InteractionState::Ended | InteractionState::Failed
        )
    }

    fn is_releasing(&self) -> bool {
        matches!(
            self.state,
            InteractionState::Ending | InteractionState::PendingRelease
        )
    }
}

/// Input to the pure transition planner.
///
/// The caller supplies current server-derived permission facts and a revision
/// from the same interaction snapshot as the claims. The server must still
/// compare and reserve that revision atomically before ending claims or
/// dispatching an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRequest {
    /// Requested operation and its idempotency identity.
    pub operation: TransitionOperation,
    /// Fingerprint of the full typed operation payload.
    pub operation_fingerprint: OperationFingerprint,
    /// Authenticated actor from the current manager session.
    pub actor: TransitionActor,
    /// Computer whose interaction set is being planned.
    pub computer_id: ComputerId,
    /// Current authorization to start the requested operation.
    pub operation_permitted: bool,
    /// Scoped authority to stop another owner's interaction on this computer.
    pub scoped_it_stop: bool,
    /// Interaction revision shown to the operator or captured for dispatch.
    pub expected_revision: u64,
}

/// Effect that a consequence review presents for one existing interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionImpactEffect {
    /// The interaction remains active alongside the requested operation.
    Coexist,
    /// This exact interaction can be reused by the requested operation.
    Reuse,
    /// End this interaction only after explicit consequence review and
    /// acknowledged/fenced teardown.
    EndAfterReview,
    /// Teardown has started but is not reconciled; wait before replacing it.
    AwaitTeardown,
}

/// Exact owner and target details for one interaction shown in a review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionImpact {
    /// Interaction identity.
    pub id: InteractionId,
    /// Existing operation.
    pub kind: InteractionKind,
    /// Owning account.
    pub owner_account_id: AccountId,
    /// Owning manager.
    pub owner_manager_id: ManagerId,
    /// Target computer and any fixed recipients affected by ending the claim.
    pub affected_computer_ids: Vec<ComputerId>,
    /// State observed when the plan was computed.
    pub state: InteractionState,
    /// Planned consequence.
    pub effect: InteractionImpactEffect,
}

/// Result of planning one computer's interaction transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPlan {
    /// Operation being planned.
    pub operation: TransitionOperation,
    /// Fingerprint of the full typed operation payload.
    pub operation_fingerprint: OperationFingerprint,
    /// Computer whose interaction set was evaluated.
    pub computer_id: ComputerId,
    /// Revision that must still match when the server atomically reserves work.
    pub expected_revision: u64,
    /// Proceed, request review, reuse an exact operation, return an idempotent
    /// machine-action result, or refuse with a typed reason.
    pub disposition: TransitionDisposition,
    /// Exact claims and consequences. Empty on refusal so a denied request
    /// does not reveal interaction ownership or recipient details.
    pub impacts: Vec<InteractionImpact>,
}

/// Planned transition result. Review plans never authorize side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionDisposition {
    /// No conflicting claim needs teardown.
    Proceed,
    /// The exact owned interaction is already present.
    ReuseExisting,
    /// Show impacts, then recheck the revision and reconcile teardown.
    ReviewRequired,
    /// Show the pending teardown and wait for its acknowledgment or fencing.
    TeardownPending,
    /// The same pending machine action already exists; return its stored state.
    ReturnExistingAction,
    /// Refused before any side effect.
    Refused(ReasonCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedKind {
    Observation,
    Control,
    ShareSource,
    ShareReceiver,
    Attention,
    MachineAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictRelation {
    Coexist,
    ReuseOrReplace,
    ReuseOrRefuse,
    Replace,
    EndForMachineAction,
}

/// One source of truth for the draft E02/E03 conflict table in contracts.md.
fn conflict_relation(requested: RequestedKind, existing: InteractionKind) -> ConflictRelation {
    use ConflictRelation::{Coexist as C, EndForMachineAction as M, Replace as R};
    use InteractionKind::{
        Attention as A, Control as Ctl, Observation as O, ShareReceiver as Rcv, ShareSource as Src,
    };
    use RequestedKind::{
        Attention as QA, Control as QC, MachineAction as QM, Observation as QO,
        ShareReceiver as QRcv, ShareSource as QSrc,
    };

    match (requested, existing) {
        (QO, O | Ctl | Src | Rcv | A) => C,
        (QC, O | Src) => C,
        (QC, Ctl) => ConflictRelation::ReuseOrRefuse,
        (QC, Rcv | A) => R,
        (QSrc, O | Ctl) => C,
        (QSrc, Src) => ConflictRelation::ReuseOrReplace,
        (QSrc, Rcv | A) => R,
        (QRcv, O) => C,
        (QRcv, Ctl | Src | A) => R,
        (QRcv, Rcv) => ConflictRelation::ReuseOrReplace,
        (QA, O) => C,
        (QA, Ctl | Src | Rcv) => R,
        (QA, A) => ConflictRelation::ReuseOrReplace,
        (QM, O | Ctl | Src | Rcv | A) => M,
    }
}

/// Plan one interaction transition from a bounded server-owned snapshot.
///
/// This does not commit, reserve, authorize at the endpoint, or stop anything.
/// The service must enforce operation permission, compare the revision and
/// reserve claims in one durable transaction, then reconcile endpoint teardown
/// before issuing replacement authority.
pub fn plan_transition(
    request: TransitionRequest,
    current_revision: u64,
    claims: &[InteractionClaim],
    pending_machine_action: Option<&PendingMachineAction>,
) -> TransitionPlan {
    let refuse = |reason| TransitionPlan {
        operation: request.operation.clone(),
        operation_fingerprint: request.operation_fingerprint,
        computer_id: request.computer_id.clone(),
        expected_revision: request.expected_revision,
        disposition: TransitionDisposition::Refused(reason),
        impacts: Vec::new(),
    };

    if !request.operation_permitted {
        return refuse(ReasonCode::PermissionDenied);
    }
    if let Some(pending_id) = pending_machine_action {
        if let TransitionOperation::MachineAction(action_id, kind) = &request.operation {
            if action_id == &pending_id.id {
                if request.actor.account_id == pending_id.owner_account_id
                    && request.actor.manager_id == pending_id.owner_manager_id
                    && kind == &pending_id.kind
                    && request.operation_fingerprint == pending_id.operation_fingerprint
                {
                    return TransitionPlan {
                        operation: request.operation.clone(),
                        operation_fingerprint: request.operation_fingerprint,
                        computer_id: request.computer_id.clone(),
                        expected_revision: current_revision,
                        disposition: TransitionDisposition::ReturnExistingAction,
                        impacts: Vec::new(),
                    };
                }
                return refuse(ReasonCode::Replayed);
            }
        }
        return refuse(ReasonCode::MachineActionPending);
    }

    if request.expected_revision != current_revision {
        return refuse(ReasonCode::ConflictChanged);
    }
    if claims.len() > MAX_INTERACTION_CLAIMS_PER_COMPUTER {
        return refuse(ReasonCode::QuotaReached);
    }
    if claims
        .iter()
        .any(|claim| claim.computer_id != request.computer_id)
    {
        return refuse(ReasonCode::InvalidInput);
    }
    if claims
        .iter()
        .any(|claim| claim.affected_computer_ids.len() > MAX_SHARE_RECEIVERS)
    {
        return refuse(ReasonCode::QuotaReached);
    }
    let mut claim_ids = BTreeSet::new();
    if claims.iter().any(|claim| !claim_ids.insert(&claim.id)) {
        return refuse(ReasonCode::Replayed);
    }

    let requested_kind = request.operation.requested_kind();
    let mut reused = false;
    let mut requires_review = false;
    let mut teardown_pending = false;
    let mut impacts = Vec::new();

    for claim in claims
        .iter()
        .filter(|claim| claim.computer_id == request.computer_id)
    {
        let is_requested_id = request.operation.interaction_id() == Some(&claim.id);
        let is_owner = claim.owner_account_id == request.actor.account_id
            && claim.owner_manager_id == request.actor.manager_id;

        if is_requested_id {
            if !is_owner
                || Some(claim.kind) != requested_interaction_kind(requested_kind)
                || claim.operation_fingerprint != request.operation_fingerprint
                || !claim.occupies_slot()
            {
                return refuse(ReasonCode::Replayed);
            }
            if claim.is_releasing() {
                return refuse(ReasonCode::PendingRelease);
            }
            reused = true;
            impacts.push(interaction_impact(claim, InteractionImpactEffect::Reuse));
            continue;
        }

        if !claim.occupies_slot() {
            continue;
        }

        let effect = match conflict_relation(requested_kind, claim.kind) {
            ConflictRelation::Coexist => InteractionImpactEffect::Coexist,
            ConflictRelation::ReuseOrReplace | ConflictRelation::Replace => {
                if !is_owner && !request.scoped_it_stop {
                    return refuse(ReasonCode::StopAuthorityRequired);
                }
                requires_review = true;
                if claim.is_releasing() {
                    teardown_pending = true;
                    InteractionImpactEffect::AwaitTeardown
                } else {
                    InteractionImpactEffect::EndAfterReview
                }
            }
            ConflictRelation::ReuseOrRefuse => {
                return refuse(if claim.is_releasing() {
                    ReasonCode::PendingRelease
                } else if is_owner {
                    ReasonCode::InUse
                } else {
                    ReasonCode::InteractionOwnershipConflict
                });
            }
            ConflictRelation::EndForMachineAction => {
                if !is_owner && !request.scoped_it_stop {
                    return refuse(ReasonCode::StopAuthorityRequired);
                }
                requires_review = true;
                if claim.is_releasing() {
                    teardown_pending = true;
                    InteractionImpactEffect::AwaitTeardown
                } else {
                    InteractionImpactEffect::EndAfterReview
                }
            }
        };
        impacts.push(interaction_impact(claim, effect));
    }

    let disposition = if teardown_pending {
        TransitionDisposition::TeardownPending
    } else if requires_review {
        TransitionDisposition::ReviewRequired
    } else if reused {
        TransitionDisposition::ReuseExisting
    } else {
        TransitionDisposition::Proceed
    };

    TransitionPlan {
        operation: request.operation,
        operation_fingerprint: request.operation_fingerprint,
        computer_id: request.computer_id,
        expected_revision: request.expected_revision,
        disposition,
        impacts,
    }
}

fn requested_interaction_kind(requested: RequestedKind) -> Option<InteractionKind> {
    match requested {
        RequestedKind::Observation => Some(InteractionKind::Observation),
        RequestedKind::Control => Some(InteractionKind::Control),
        RequestedKind::ShareSource => Some(InteractionKind::ShareSource),
        RequestedKind::ShareReceiver => Some(InteractionKind::ShareReceiver),
        RequestedKind::Attention => Some(InteractionKind::Attention),
        RequestedKind::MachineAction => None,
    }
}

fn interaction_impact(
    claim: &InteractionClaim,
    effect: InteractionImpactEffect,
) -> InteractionImpact {
    let mut affected_computer_ids = claim.affected_computer_ids.clone();
    if !affected_computer_ids.contains(&claim.computer_id) {
        affected_computer_ids.push(claim.computer_id.clone());
    }
    affected_computer_ids.sort();
    affected_computer_ids.dedup();
    InteractionImpact {
        id: claim.id.clone(),
        kind: claim.kind,
        owner_account_id: claim.owner_account_id.clone(),
        owner_manager_id: claim.owner_manager_id.clone(),
        affected_computer_ids,
        state: claim.state,
        effect,
    }
}

/// One computer's interaction registry.
///
/// Ownership is the authenticated account/manager binding, never a matching
/// display name or a caller-supplied owner field.
#[derive(Debug, Clone, Default)]
pub struct InteractionRegistry {
    interactions: BTreeMap<InteractionId, Interaction>,
    /// Unique controller per computer, if any (including Pending Release).
    controllers: BTreeMap<ComputerId, InteractionId>,
    /// Stable admission order for observer listing.
    observer_order: Vec<InteractionId>,
    /// When a control release entered Pending Release.
    pending_release_since: BTreeMap<InteractionId, TimestampMs>,
}

/// Parameters for admitting a new interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginInteraction {
    /// Stable interaction identity.
    pub id: InteractionId,
    /// Owning account. Never a caller-supplied display name.
    pub owner_account_id: AccountId,
    /// Owning manager identity.
    pub owner_manager_id: ManagerId,
    /// Optional monitoring context.
    pub monitoring_id: Option<MonitoringId>,
    /// Target computer.
    pub computer_id: ComputerId,
    /// Desktop generation bound at admission.
    pub desktop_generation: DesktopGeneration,
    /// Admission timestamp.
    pub now: TimestampMs,
    /// Lease length in milliseconds; defaults to the kind's frozen lease.
    pub lease_ms: Option<u64>,
    /// Optional starting interaction generation for recovery that must
    /// preserve fencing. Defaults to [`InteractionGeneration::INITIAL`].
    pub initial_generation: Option<InteractionGeneration>,
}

impl InteractionRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up an interaction.
    pub fn get(&self, id: &InteractionId) -> Option<&Interaction> {
        self.interactions.get(id)
    }

    /// True when `id` exists and has not ended.
    pub fn is_active(&self, id: &InteractionId) -> bool {
        self.interactions.get(id).map(|i| !i.ended).unwrap_or(false)
    }

    /// Admitted, non-ended observers on one computer.
    pub fn observers_on(&self, computer_id: &ComputerId) -> Vec<&Interaction> {
        self.observer_order
            .iter()
            .filter_map(|id| self.interactions.get(id))
            .filter(|i| i.computer_id == *computer_id && !i.ended)
            .collect()
    }

    /// Current controlling interaction on one computer, if any.
    ///
    /// A Pending Release claim is still returned so callers can refuse retake
    /// and show the honest state.
    pub fn controller_on(&self, computer_id: &ComputerId) -> Option<&Interaction> {
        let id = self.controllers.get(computer_id)?;
        self.interactions.get(id)
    }

    /// Begin view-only observation. Several observers coexist (D19).
    ///
    /// Refuses when the bound desktop generation is exhausted: an exhausted
    /// counter cannot fence later authority, so no new work may bind to it.
    pub fn begin_observation(&mut self, params: BeginInteraction) -> Result<()> {
        let BeginInteraction {
            id,
            owner_account_id,
            owner_manager_id,
            monitoring_id,
            computer_id,
            desktop_generation,
            now,
            lease_ms,
            initial_generation,
        } = params;
        if desktop_generation.is_exhausted() {
            return Err(Error::refused(ReasonCode::Expired));
        }
        if self.interactions.contains_key(&id) {
            return Err(Error::refused(ReasonCode::Replayed));
        }
        if self.observers_on(&computer_id).len() >= MAX_OBSERVERS_PER_COMPUTER {
            return Err(Error::QuotaReached {
                limit: "MAX_OBSERVERS_PER_COMPUTER",
            });
        }
        let lease = lease_ms.unwrap_or(DEFAULT_OBSERVATION_LEASE_MS);
        let interaction = Interaction {
            id: id.clone(),
            kind: InteractionKind::Observation,
            owner_account_id,
            owner_manager_id,
            monitoring_id,
            computer_id,
            desktop_generation,
            generation: initial_generation.unwrap_or(InteractionGeneration::INITIAL),
            expires_at: TimestampMs(now.0.saturating_add(lease)),
            input_forwarding: false,
            held_input_count: 0,
            state: InteractionState::Requested,
            ended: false,
        };
        self.observer_order.push(id.clone());
        self.interactions.insert(id, interaction);
        Ok(())
    }

    /// Request exclusive control.
    ///
    /// Refuses when another controller holds the computer, when any control
    /// claim (including this owner's Pending Release) is unresolved, or when
    /// the ID is already used. Operators cannot silently displace another
    /// operator's control (I06); stop the existing claim first.
    pub fn begin_control(&mut self, params: BeginInteraction) -> Result<()> {
        let BeginInteraction {
            id,
            owner_account_id,
            owner_manager_id,
            monitoring_id,
            computer_id,
            desktop_generation,
            now,
            lease_ms,
            initial_generation,
        } = params;
        if desktop_generation.is_exhausted() {
            return Err(Error::refused(ReasonCode::Expired));
        }
        if self.interactions.contains_key(&id) {
            return Err(Error::refused(ReasonCode::Replayed));
        }
        if let Some(existing) = self.controller_on(&computer_id) {
            let reason = if existing.state == InteractionState::PendingRelease {
                ReasonCode::PendingRelease
            } else {
                ReasonCode::InUse
            };
            return Err(Error::refused(reason));
        }
        let lease = lease_ms.unwrap_or(DEFAULT_CONTROL_LEASE_MS);
        let interaction = Interaction {
            id: id.clone(),
            kind: InteractionKind::Control,
            owner_account_id,
            owner_manager_id,
            monitoring_id,
            computer_id: computer_id.clone(),
            desktop_generation,
            generation: initial_generation.unwrap_or(InteractionGeneration::INITIAL),
            expires_at: TimestampMs(now.0.saturating_add(lease)),
            input_forwarding: false,
            held_input_count: 0,
            state: InteractionState::Requested,
            ended: false,
        };
        self.controllers.insert(computer_id, id.clone());
        self.interactions.insert(id, interaction);
        Ok(())
    }

    /// Advance a control interaction to `state`.
    ///
    /// `Stopping`/`PendingRelease` stop forwarding and release held input.
    /// `PendingRelease` keeps the controller slot occupied. `Stopped`/`Failed`
    /// clear the slot so a later explicit Take Control can proceed. A late
    /// acknowledgment cannot resurrect an ended claim.
    pub fn set_control_state(
        &mut self,
        id: &InteractionId,
        state: ControlState,
        now: TimestampMs,
    ) -> Result<()> {
        let computer_id;
        {
            let interaction = self
                .interactions
                .get_mut(id)
                .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
            if interaction.kind != InteractionKind::Control || interaction.ended {
                return Err(Error::refused(ReasonCode::LateGeneration));
            }
            match state {
                ControlState::Authorizing | ControlState::Controlling => {
                    if interaction.expires_at.0 < now.0 {
                        return Err(Error::refused(ReasonCode::Expired));
                    }
                    interaction.state = match state {
                        ControlState::Controlling => InteractionState::Controlling,
                        _ => InteractionState::Connecting,
                    };
                }
                ControlState::Requested => {
                    interaction.state = InteractionState::Requested;
                }
                ControlState::Stopping => {
                    interaction.input_forwarding = false;
                    interaction.held_input_count = 0;
                    interaction.state = InteractionState::Ending;
                }
                ControlState::PendingRelease => {
                    interaction.input_forwarding = false;
                    interaction.held_input_count = 0;
                    interaction.state = InteractionState::PendingRelease;
                }
                ControlState::Stopped => {
                    interaction.input_forwarding = false;
                    interaction.held_input_count = 0;
                    interaction.state = InteractionState::Ended;
                    interaction.ended = true;
                }
                ControlState::Failed => {
                    interaction.input_forwarding = false;
                    interaction.held_input_count = 0;
                    interaction.state = InteractionState::Failed;
                    interaction.ended = true;
                }
            }
            computer_id = interaction.computer_id.clone();
        }

        match state {
            ControlState::PendingRelease => {
                self.pending_release_since.insert(id.clone(), now);
            }
            ControlState::Stopped | ControlState::Failed => {
                self.pending_release_since.remove(id);
                if self.controllers.get(&computer_id) == Some(id) {
                    self.controllers.remove(&computer_id);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Observe that release was acknowledged after Pending Release.
    pub fn acknowledge_control_release(
        &mut self,
        id: &InteractionId,
        now: TimestampMs,
    ) -> Result<()> {
        self.set_control_state(id, ControlState::Stopped, now)
    }

    /// True when `id` has been in Pending Release longer than the frozen bound.
    pub fn pending_release_expired(&self, id: &InteractionId, now: TimestampMs) -> bool {
        let Some(started) = self.pending_release_since.get(id) else {
            return false;
        };
        now.0.saturating_sub(started.0) >= DEFAULT_PENDING_RELEASE_TIMEOUT_MS
    }

    /// Start or stop input forwarding for a controlling interaction.
    ///
    /// Forwarding is only permitted while the interaction is Controlling and
    /// `focused` is true. Focus loss must call this with `focused = false`,
    /// which also releases held input. Focus loss never ends the lease.
    pub fn set_input_forwarding(&mut self, id: &InteractionId, focused: bool) -> Result<()> {
        let interaction = self
            .interactions
            .get_mut(id)
            .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
        if interaction.kind != InteractionKind::Control || interaction.ended {
            return Err(Error::refused(ReasonCode::LateGeneration));
        }
        if focused {
            if interaction.state != InteractionState::Controlling {
                return Err(Error::refused(ReasonCode::PermissionDenied));
            }
            interaction.input_forwarding = true;
        } else {
            interaction.input_forwarding = false;
            interaction.held_input_count = 0;
        }
        Ok(())
    }

    /// Track an injected key/button down.
    pub fn note_injected_input_down(&mut self, id: &InteractionId) -> Result<()> {
        let interaction = self
            .interactions
            .get_mut(id)
            .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
        if !interaction.input_forwarding {
            return Err(Error::refused(ReasonCode::PermissionDenied));
        }
        interaction.held_input_count = interaction.held_input_count.saturating_add(1);
        Ok(())
    }

    /// Track an injected key/button up.
    pub fn note_injected_input_up(&mut self, id: &InteractionId) -> Result<()> {
        let interaction = self
            .interactions
            .get_mut(id)
            .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
        interaction.held_input_count = interaction.held_input_count.saturating_sub(1);
        Ok(())
    }

    /// D24 minimize: stop forwarding, release held input, cancel pending
    /// control admission or start release of active control. Observation is
    /// untouched. The claim enters Pending Release so restore cannot resume it.
    ///
    /// Generation exhaustion still performs this safety teardown. When the
    /// counter cannot advance, `generation_fenced` is `None` and no new
    /// control authority may be issued on this interaction.
    pub fn minimize_control_window(
        &mut self,
        id: &InteractionId,
        now: TimestampMs,
    ) -> Result<MinimizeOutcome> {
        let generation_fenced = {
            let interaction = self
                .interactions
                .get_mut(id)
                .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
            if interaction.kind != InteractionKind::Control || interaction.ended {
                return Err(Error::refused(ReasonCode::LateGeneration));
            }
            // Safety teardown never depends on generation availability.
            interaction.input_forwarding = false;
            interaction.held_input_count = 0;
            interaction.state = InteractionState::PendingRelease;
            match interaction.generation.next() {
                Some(next) => {
                    interaction.generation = next;
                    Some(next)
                }
                None => None,
            }
        };
        self.pending_release_since.insert(id.clone(), now);
        Ok(MinimizeOutcome {
            released_input: true,
            generation_fenced,
            control_disposition: ControlDisposition::PendingRelease,
            observation_preserved: true,
        })
    }

    /// End an interaction and clear any controller slot it held.
    ///
    /// Safe to call from teardown paths even when the engine is unavailable.
    /// Idempotent for an already-ended interaction.
    pub fn end_interaction(&mut self, id: &InteractionId) -> Result<()> {
        let computer_id = match self.interactions.get_mut(id) {
            Some(interaction) => {
                interaction.input_forwarding = false;
                interaction.held_input_count = 0;
                interaction.state = InteractionState::Ended;
                interaction.ended = true;
                interaction.computer_id.clone()
            }
            None => return Ok(()),
        };
        self.pending_release_since.remove(id);
        self.observer_order.retain(|x| x != id);
        if self.controllers.get(&computer_id) == Some(id) {
            self.controllers.remove(&computer_id);
        }
        Ok(())
    }

    /// End every interaction bound to a desktop generation that is no longer
    /// current. Used on desktop change, logout, lock, worker restart.
    ///
    /// Returns the ended interaction IDs so callers can clear frames and
    /// notify endpoints. Never requires engine health; teardown stays available.
    pub fn teardown_desktop(
        &mut self,
        desktop_generation: DesktopGeneration,
    ) -> Vec<InteractionId> {
        let stale: Vec<InteractionId> = self
            .interactions
            .values()
            .filter(|i| !i.ended && i.desktop_generation == desktop_generation)
            .map(|i| i.id.clone())
            .collect();
        for id in &stale {
            let _ = self.end_interaction(id);
        }
        stale
    }

    /// Expire interactions whose lease ended at `now`. Conservative: renewal
    /// cannot extend an existing lease without a fresh authority.
    pub fn expire_at(&mut self, now: TimestampMs) -> Vec<InteractionId> {
        let expired: Vec<InteractionId> = self
            .interactions
            .values()
            .filter(|i| !i.ended && i.expires_at.0 < now.0)
            .map(|i| i.id.clone())
            .collect();
        for id in &expired {
            let _ = self.end_interaction(id);
        }
        expired
    }

    /// True when any interaction still holds injected input on `computer_id`.
    pub fn has_held_input(&self, computer_id: &ComputerId) -> bool {
        self.interactions
            .values()
            .any(|i| i.computer_id == *computer_id && i.held_input_count > 0)
    }
}

/// Sharing distribution: one source, fixed receivers, independent branches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharingDistribution {
    /// Distribution identity (the share-source interaction id).
    pub id: InteractionId,
    /// Owner account.
    pub owner_account_id: AccountId,
    /// Owner manager.
    pub owner_manager_id: ManagerId,
    /// Source computer (or the operator console, when sharing locally).
    pub source_computer_id: Option<ComputerId>,
    /// Immutable receiver IDs frozen at Start Sharing.
    receiver_ids: Vec<ComputerId>,
    /// Branch state per receiver.
    branches: BTreeMap<ComputerId, ReceiverBranchState>,
    /// Source generation; a closed window does not silently become a display share.
    pub source_generation: InteractionGeneration,
}

/// One receiver branch state under the D30 stop-rights policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiverBranchState {
    /// Admitted; presentation may start.
    Preparing,
    /// Actually presenting on screen (not merely packets received).
    Receiving,
    /// Allowed minimize: not currently presenting; branch is not stopped.
    PresentationMinimized,
    /// Authorized teardown in progress.
    Releasing,
    /// Explicitly stopped by the sharing owner or scoped authorized IT.
    StoppedByOperatorOrIt,
    /// Source/authority/permission loss; automatic teardown applied.
    SourceLost,
    /// Recipient never admitted or became unavailable.
    Unavailable,
}

impl SharingDistribution {
    /// Freeze receivers at Start Sharing. Recursive source-to-self is refused.
    pub fn new(
        id: InteractionId,
        owner_account_id: AccountId,
        owner_manager_id: ManagerId,
        source_computer_id: Option<ComputerId>,
        receiver_ids: impl IntoIterator<Item = ComputerId>,
    ) -> Result<Self> {
        let mut receivers = Vec::new();
        for r in receiver_ids {
            if Some(&r) == source_computer_id.as_ref() {
                return Err(Error::refused(ReasonCode::InvalidInput));
            }
            if receivers.contains(&r) {
                continue;
            }
            if receivers.len() >= MAX_SHARE_RECEIVERS {
                return Err(Error::QuotaReached {
                    limit: "MAX_SHARE_RECEIVERS",
                });
            }
            receivers.push(r);
        }
        if receivers.is_empty() {
            return Err(Error::refused(ReasonCode::ZeroTargets));
        }
        let mut branches = BTreeMap::new();
        for r in &receivers {
            branches.insert(r.clone(), ReceiverBranchState::Preparing);
        }
        Ok(Self {
            id,
            owner_account_id,
            owner_manager_id,
            source_computer_id,
            receiver_ids: receivers,
            branches,
            source_generation: InteractionGeneration::INITIAL,
        })
    }

    /// Immutable receiver set.
    pub fn receiver_ids(&self) -> &[ComputerId] {
        &self.receiver_ids
    }

    /// Branch state for one receiver.
    pub fn branch_state(&self, receiver: &ComputerId) -> Option<ReceiverBranchState> {
        self.branches.get(receiver).copied()
    }

    /// True when the caller may explicitly stop this branch/distribution.
    ///
    /// Under D30 only the sharing owner or scoped authorized IT can stop a
    /// receiving presentation. The computer user has no product stop command.
    /// Automatic safety teardown is separate and always available.
    pub fn can_explicitly_stop(
        &self,
        actor_account_id: &AccountId,
        is_scoped_it_stop: bool,
    ) -> bool {
        &self.owner_account_id == actor_account_id || is_scoped_it_stop
    }

    /// Stop one branch. Clears only that receiver; other recipients continue.
    /// The branch remains ended in the original immutable target set.
    pub fn stop_branch(
        &mut self,
        receiver: &ComputerId,
        actor_account_id: &AccountId,
        is_scoped_it_stop: bool,
    ) -> Result<ReceiverBranchState> {
        if !self.can_explicitly_stop(actor_account_id, is_scoped_it_stop) {
            return Err(Error::refused(ReasonCode::StopAuthorityRequired));
        }
        let state = self
            .branches
            .get_mut(receiver)
            .ok_or_else(|| Error::refused(ReasonCode::LateGeneration))?;
        if matches!(
            state,
            ReceiverBranchState::StoppedByOperatorOrIt
                | ReceiverBranchState::SourceLost
                | ReceiverBranchState::Unavailable
        ) {
            return Err(Error::refused(ReasonCode::Replayed));
        }
        *state = ReceiverBranchState::StoppedByOperatorOrIt;
        Ok(ReceiverBranchState::StoppedByOperatorOrIt)
    }

    /// Stop the entire distribution. Review must name that larger consequence.
    pub fn stop_all(
        &mut self,
        actor_account_id: &AccountId,
        is_scoped_it_stop: bool,
    ) -> Result<()> {
        if !self.can_explicitly_stop(actor_account_id, is_scoped_it_stop) {
            return Err(Error::refused(ReasonCode::StopAuthorityRequired));
        }
        for state in self.branches.values_mut() {
            if !matches!(
                state,
                ReceiverBranchState::StoppedByOperatorOrIt | ReceiverBranchState::SourceLost
            ) {
                *state = ReceiverBranchState::StoppedByOperatorOrIt;
            }
        }
        Ok(())
    }

    /// A computer-user dismissal attempt (native close/menu/shortcut/API)
    /// cannot end an admitted branch (D30). This method is the single named
    /// place endpoints use to refuse user stop rights.
    pub fn user_stop_attempt(&mut self, _receiver: &ComputerId) -> Result<()> {
        Err(Error::refused(ReasonCode::PermissionDenied))
    }

    /// True when every receiver is terminal and source demand must end.
    pub fn all_branches_terminal(&self) -> bool {
        self.branches.values().all(|s| {
            matches!(
                s,
                ReceiverBranchState::StoppedByOperatorOrIt
                    | ReceiverBranchState::SourceLost
                    | ReceiverBranchState::Unavailable
            )
        })
    }

    /// Source generation bump when the captured source changes explicitly.
    ///
    /// Exhaustion refuses the bump: a saturated generation must never become
    /// reusable current authority. Existing teardown still applies.
    pub fn bump_source_generation(&mut self) -> Result<InteractionGeneration> {
        let next = self
            .source_generation
            .next()
            .ok_or_else(|| Error::refused(ReasonCode::Expired))?;
        self.source_generation = next;
        Ok(next)
    }
}

/// Local/remote input ownership decision for a remote-control window.
///
/// Forward input only when the admitted controlling window is foreground/key,
/// its remote canvas has explicit focus, no local menu/dialog/sheet/popover is
/// active, and the current interaction/desktop/display generations still match.
/// A toolbar click, native picker, confirmation, text field, menu shortcut, or
/// another application always receives local input. Local keyboard/mouse stay
/// enabled under D27; local input never grants product Stop Control authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InputRouting {
    /// Admitted control interaction is Controlling.
    pub control_active: bool,
    /// The remote canvas has explicit keyboard focus.
    pub canvas_focused: bool,
    /// A local menu, dialog, sheet, popover, or picker is open.
    pub local_ui_modal: bool,
    /// The control window is the foreground/key window.
    pub window_foreground: bool,
    /// Interaction/desktop/display generations still match admission.
    pub generations_match: bool,
}

impl InputRouting {
    /// True when remote input may be forwarded. Otherwise the event stays local
    /// and any tracked injected input must be released.
    pub const fn forwards_input(&self) -> bool {
        self.control_active
            && self.canvas_focused
            && !self.local_ui_modal
            && self.window_foreground
            && self.generations_match
    }
}

/// Remote-window lifecycle events that trigger teardown rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowEvent {
    /// User minimized the remote-control window (D24).
    Minimized,
    /// Window/canvas lost focus or another surface took focus (not minimize).
    FocusLost,
    /// A local menu/dialog/sheet/popover/picker opened.
    LocalUiOpened,
    /// Desktop generation changed (user switch, lock, replacement, worker restart).
    DesktopChanged,
    /// Authority lease expired or was revoked.
    AuthorityExpired,
    /// Engine cannot enforce admission; fail closed for new work.
    EngineUnavailable,
    /// Operator explicitly stopped control.
    StopControlRequested,
    /// Operator closed the remote window; ends its interactions.
    WindowClosed,
}

/// Pure teardown actions for a remote-window lifecycle event.
///
/// The host applies the returned actions. Deterministic and covered by tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeardownPlan {
    /// Stop local input forwarding immediately.
    pub stop_forwarding: bool,
    /// Release tracked injected keys/buttons through the control channel.
    pub release_held_input: bool,
    /// Discard pending text/IME composition and fence late events.
    pub discard_pending_text: bool,
    /// Cancel pending Take Control admission.
    pub cancel_pending_control: bool,
    /// Start release of active control (minimize / stop / close / expiry).
    pub release_active_control: bool,
    /// Keep separately authorized observation active.
    pub keep_observation: bool,
    /// Require explicit Take Control after release reconciliation.
    pub require_explicit_retake: bool,
    /// Clear exportable frame caches / pixel buffers.
    pub clear_frames: bool,
    /// End observation as well (desktop change / expiry / revocation).
    pub end_observation: bool,
}

/// Compute the D24/D27 teardown actions for a remote-window lifecycle event.
/// Pure decision function.
pub fn plan_teardown(event: WindowEvent, control_active: bool) -> TeardownPlan {
    match event {
        WindowEvent::Minimized => TeardownPlan {
            stop_forwarding: true,
            release_held_input: true,
            discard_pending_text: true,
            cancel_pending_control: true,
            release_active_control: true,
            keep_observation: true,
            require_explicit_retake: true,
            clear_frames: false,
            end_observation: false,
        },
        WindowEvent::FocusLost | WindowEvent::LocalUiOpened => TeardownPlan {
            stop_forwarding: true,
            release_held_input: true,
            discard_pending_text: true,
            cancel_pending_control: false,
            release_active_control: false,
            keep_observation: true,
            require_explicit_retake: false,
            clear_frames: false,
            end_observation: false,
        },
        WindowEvent::DesktopChanged | WindowEvent::AuthorityExpired | WindowEvent::WindowClosed => {
            TeardownPlan {
                stop_forwarding: true,
                release_held_input: true,
                discard_pending_text: true,
                cancel_pending_control: true,
                release_active_control: true,
                keep_observation: false,
                require_explicit_retake: true,
                clear_frames: true,
                end_observation: true,
            }
        }
        WindowEvent::EngineUnavailable => TeardownPlan {
            stop_forwarding: true,
            release_held_input: true,
            discard_pending_text: true,
            cancel_pending_control: true,
            release_active_control: control_active,
            keep_observation: false,
            require_explicit_retake: true,
            clear_frames: true,
            end_observation: true,
        },
        WindowEvent::StopControlRequested => TeardownPlan {
            stop_forwarding: true,
            release_held_input: true,
            discard_pending_text: true,
            cancel_pending_control: true,
            release_active_control: true,
            keep_observation: true,
            require_explicit_retake: true,
            clear_frames: false,
            end_observation: false,
        },
    }
}

/// Computer-user visibility of active observation/control (I16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoredUserVisibility {
    /// Display names of currently admitted observers.
    pub observers: Vec<String>,
    /// Display name of the unique controlling operator, if any.
    pub controller: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(n: &str) -> (AccountId, ManagerId, ComputerId, InteractionId) {
        (
            AccountId::new(format!("acc-{n}")).unwrap(),
            ManagerId::new(format!("mgr-{n}")).unwrap(),
            ComputerId::new(format!("c-{n}")).unwrap(),
            InteractionId::new(format!("ix-{n}")).unwrap(),
        )
    }

    fn begin_obs(
        reg: &mut InteractionRegistry,
        n: &str,
        computer_id: &ComputerId,
        gen: DesktopGeneration,
        now: TimestampMs,
    ) -> InteractionId {
        let (a, m, _, id) = parts(n);
        reg.begin_observation(BeginInteraction {
            id: id.clone(),
            owner_account_id: a,
            owner_manager_id: m,
            monitoring_id: None,
            computer_id: computer_id.clone(),
            desktop_generation: gen,
            now,
            lease_ms: None,
            initial_generation: None,
        })
        .unwrap();
        id
    }

    fn begin_ctl(
        reg: &mut InteractionRegistry,
        n: &str,
        computer_id: &ComputerId,
        gen: DesktopGeneration,
        now: TimestampMs,
    ) -> InteractionId {
        let (a, m, _, id) = parts(n);
        reg.begin_control(BeginInteraction {
            id: id.clone(),
            owner_account_id: a,
            owner_manager_id: m,
            monitoring_id: None,
            computer_id: computer_id.clone(),
            desktop_generation: gen,
            now,
            lease_ms: None,
            initial_generation: None,
        })
        .unwrap();
        id
    }

    fn transition_request(
        operation: TransitionOperation,
        actor_name: &str,
        computer_id: &ComputerId,
    ) -> TransitionRequest {
        let (account_id, manager_id, _, _) = parts(actor_name);
        TransitionRequest {
            operation,
            operation_fingerprint: OperationFingerprint([0; 32]),
            actor: TransitionActor {
                account_id,
                manager_id,
            },
            computer_id: computer_id.clone(),
            operation_permitted: true,
            scoped_it_stop: false,
            expected_revision: 7,
        }
    }

    fn claim(
        n: &str,
        kind: InteractionKind,
        computer_id: &ComputerId,
        state: InteractionState,
        affected_computer_ids: Vec<ComputerId>,
    ) -> InteractionClaim {
        let (owner_account_id, owner_manager_id, _, id) = parts(n);
        InteractionClaim {
            id,
            operation_fingerprint: OperationFingerprint([0; 32]),
            kind,
            owner_account_id,
            owner_manager_id,
            computer_id: computer_id.clone(),
            affected_computer_ids,
            state,
        }
    }

    #[test]
    fn conflict_relation_matches_every_contract_cell() {
        use ConflictRelation::{Coexist as C, EndForMachineAction as M, Replace as R};
        use InteractionKind::{
            Attention as A, Control as Ctl, Observation as O, ShareReceiver as Rcv,
            ShareSource as Src,
        };
        use RequestedKind::{
            Attention as QA, Control as QC, MachineAction as QM, Observation as QO,
            ShareReceiver as QRcv, ShareSource as QSrc,
        };

        let existing = [O, Ctl, Src, Rcv, A];
        let rows = [
            (QO, [C, C, C, C, C]),
            (QC, [C, ConflictRelation::ReuseOrRefuse, C, R, R]),
            (QSrc, [C, C, ConflictRelation::ReuseOrReplace, R, R]),
            (QRcv, [C, R, R, ConflictRelation::ReuseOrReplace, R]),
            (QA, [C, R, R, R, ConflictRelation::ReuseOrReplace]),
            (QM, [M, M, M, M, M]),
        ];
        for (requested, expected) in rows {
            for (existing, expected) in existing.into_iter().zip(expected) {
                assert_eq!(conflict_relation(requested, existing), expected);
            }
        }
    }

    #[test]
    fn transition_review_names_foreign_owner_and_fixed_share_recipients() {
        let target = ComputerId::new("computer-target").unwrap();
        let receiver = ComputerId::new("computer-receiver").unwrap();
        let existing = claim(
            "other",
            InteractionKind::ShareSource,
            &target,
            InteractionState::Live,
            vec![receiver.clone()],
        );
        let request = transition_request(
            TransitionOperation::Attention(InteractionId::new("attention-1").unwrap()),
            "actor",
            &target,
        );

        let denied = plan_transition(request.clone(), 7, std::slice::from_ref(&existing), None);
        assert_eq!(
            denied.disposition,
            TransitionDisposition::Refused(ReasonCode::StopAuthorityRequired)
        );
        assert!(
            denied.impacts.is_empty(),
            "refusal does not expose claim details"
        );

        let mut authorized = request;
        authorized.scoped_it_stop = true;
        let plan = plan_transition(authorized, 7, &[existing], None);
        assert_eq!(plan.disposition, TransitionDisposition::ReviewRequired);
        assert_eq!(plan.impacts.len(), 1);
        assert_eq!(plan.impacts[0].owner_account_id.as_str(), "acc-other");
        assert_eq!(
            plan.impacts[0].affected_computer_ids,
            vec![receiver, target]
        );
        assert_eq!(
            plan.impacts[0].effect,
            InteractionImpactEffect::EndAfterReview
        );
    }

    #[test]
    fn replacement_waits_when_a_conflicting_claim_is_still_releasing() {
        let target = ComputerId::new("computer-release").unwrap();
        let receiver = ComputerId::new("computer-release-recipient").unwrap();
        let releasing = claim(
            "actor",
            InteractionKind::ShareSource,
            &target,
            InteractionState::Ending,
            vec![receiver.clone()],
        );
        let request = transition_request(
            TransitionOperation::Attention(InteractionId::new("attention-release").unwrap()),
            "actor",
            &target,
        );

        let plan = plan_transition(request, 7, &[releasing], None);
        assert_eq!(plan.disposition, TransitionDisposition::TeardownPending);
        assert_eq!(plan.impacts[0].state, InteractionState::Ending);
        assert_eq!(
            plan.impacts[0].effect,
            InteractionImpactEffect::AwaitTeardown
        );
        assert_eq!(
            plan.impacts[0].affected_computer_ids,
            vec![target, receiver]
        );
    }

    #[test]
    fn control_reuse_is_exact_and_pending_release_still_blocks() {
        let target = ComputerId::new("computer-control").unwrap();
        let (account_id, manager_id, _, id) = parts("owner");
        let existing = InteractionClaim {
            id: id.clone(),
            operation_fingerprint: OperationFingerprint([0; 32]),
            kind: InteractionKind::Control,
            owner_account_id: account_id.clone(),
            owner_manager_id: manager_id.clone(),
            computer_id: target.clone(),
            affected_computer_ids: Vec::new(),
            state: InteractionState::Controlling,
        };
        let request = transition_request(
            TransitionOperation::TakeControl(id.clone()),
            "owner",
            &target,
        );
        let plan = plan_transition(request.clone(), 7, std::slice::from_ref(&existing), None);
        assert_eq!(plan.disposition, TransitionDisposition::ReuseExisting);
        assert_eq!(plan.impacts[0].effect, InteractionImpactEffect::Reuse);

        let mut changed_payload = request.clone();
        changed_payload.operation_fingerprint = OperationFingerprint([1; 32]);
        let replay = plan_transition(changed_payload, 7, std::slice::from_ref(&existing), None);
        assert_eq!(
            replay.disposition,
            TransitionDisposition::Refused(ReasonCode::Replayed)
        );

        let mut pending = existing;
        pending.state = InteractionState::PendingRelease;
        let blocked = plan_transition(request.clone(), 7, &[pending], None);
        assert_eq!(
            blocked.disposition,
            TransitionDisposition::Refused(ReasonCode::PendingRelease)
        );

        let mut foreign = request;
        foreign.actor = TransitionActor {
            account_id: AccountId::new("acc-foreign").unwrap(),
            manager_id: ManagerId::new("mgr-foreign").unwrap(),
        };
        let replay = plan_transition(
            foreign,
            7,
            &[claim(
                "owner",
                InteractionKind::Control,
                &target,
                InteractionState::Controlling,
                Vec::new(),
            )],
            None,
        );
        assert_eq!(
            replay.disposition,
            TransitionDisposition::Refused(ReasonCode::Replayed)
        );
    }

    #[test]
    fn machine_action_review_ends_observation_and_retries_are_owner_bound() {
        let target = ComputerId::new("computer-action").unwrap();
        let observer = claim(
            "actor",
            InteractionKind::Observation,
            &target,
            InteractionState::Live,
            Vec::new(),
        );
        let action_id = crate::id::ActionId::new("action-1").unwrap();
        let request = transition_request(
            TransitionOperation::MachineAction(
                action_id.clone(),
                crate::capability::MachineActionKind::Restart,
            ),
            "actor",
            &target,
        );
        let plan = plan_transition(request.clone(), 7, &[observer], None);
        assert_eq!(plan.disposition, TransitionDisposition::ReviewRequired);
        assert_eq!(
            plan.impacts[0].effect,
            InteractionImpactEffect::EndAfterReview
        );

        let pending = PendingMachineAction {
            id: action_id.clone(),
            owner_account_id: AccountId::new("acc-actor").unwrap(),
            owner_manager_id: ManagerId::new("mgr-actor").unwrap(),
            kind: crate::capability::MachineActionKind::Restart,
            operation_fingerprint: OperationFingerprint([0; 32]),
        };
        let retry = plan_transition(request.clone(), 8, &[], Some(&pending));
        assert_eq!(
            retry.disposition,
            TransitionDisposition::ReturnExistingAction
        );

        let mut changed_action = request.clone();
        changed_action.operation_fingerprint = OperationFingerprint([2; 32]);
        let changed = plan_transition(changed_action, 7, &[], Some(&pending));
        assert_eq!(
            changed.disposition,
            TransitionDisposition::Refused(ReasonCode::Replayed)
        );

        let foreign_retry = transition_request(
            TransitionOperation::MachineAction(
                action_id,
                crate::capability::MachineActionKind::Restart,
            ),
            "foreign",
            &target,
        );
        let denied = plan_transition(foreign_retry, 7, &[], Some(&pending));
        assert_eq!(
            denied.disposition,
            TransitionDisposition::Refused(ReasonCode::Replayed)
        );
    }

    #[test]
    fn transition_plan_fails_closed_on_permission_and_revision() {
        let target = ComputerId::new("computer-revision").unwrap();
        let request = transition_request(
            TransitionOperation::Observe(InteractionId::new("observe-1").unwrap()),
            "actor",
            &target,
        );
        let stale = plan_transition(request.clone(), 8, &[], None);
        assert_eq!(
            stale.disposition,
            TransitionDisposition::Refused(ReasonCode::ConflictChanged)
        );

        let mut denied_request = request;
        denied_request.operation_permitted = false;
        let denied = plan_transition(denied_request, 7, &[], None);
        assert_eq!(
            denied.disposition,
            TransitionDisposition::Refused(ReasonCode::PermissionDenied)
        );
    }

    #[test]
    fn transition_planner_bounds_single_computer_snapshot() {
        let target = ComputerId::new("computer-bounds").unwrap();
        let request = transition_request(
            TransitionOperation::Observe(InteractionId::new("observe-bounds").unwrap()),
            "actor",
            &target,
        );
        let too_many_claims: Vec<_> = (0..=crate::bounds::MAX_INTERACTION_CLAIMS_PER_COMPUTER)
            .map(|index| {
                claim(
                    &format!("overflow-{index}"),
                    InteractionKind::Observation,
                    &target,
                    InteractionState::Live,
                    Vec::new(),
                )
            })
            .collect();
        let bounded = plan_transition(request.clone(), 7, &too_many_claims, None);
        assert_eq!(
            bounded.disposition,
            TransitionDisposition::Refused(ReasonCode::QuotaReached)
        );

        let other_target = ComputerId::new("computer-other").unwrap();
        let mixed = claim(
            "mixed-target",
            InteractionKind::Observation,
            &other_target,
            InteractionState::Live,
            Vec::new(),
        );
        let mixed_plan = plan_transition(request.clone(), 7, &[mixed], None);
        assert_eq!(
            mixed_plan.disposition,
            TransitionDisposition::Refused(ReasonCode::InvalidInput)
        );

        let too_many_receivers = claim(
            "too-many-receivers",
            InteractionKind::ShareSource,
            &target,
            InteractionState::Live,
            (0..=crate::bounds::MAX_SHARE_RECEIVERS)
                .map(|index| ComputerId::new(format!("receiver-{index}")).unwrap())
                .collect(),
        );
        let receiver_plan = plan_transition(request, 7, &[too_many_receivers], None);
        assert_eq!(
            receiver_plan.disposition,
            TransitionDisposition::Refused(ReasonCode::QuotaReached)
        );
    }

    #[test]
    fn several_observers_one_controller() {
        let mut reg = InteractionRegistry::new();
        let c1 = ComputerId::new("c-1").unwrap();
        let now = TimestampMs::new(0);

        begin_obs(&mut reg, "1", &c1, DesktopGeneration(1), now);
        begin_obs(&mut reg, "2", &c1, DesktopGeneration(1), now);
        assert_eq!(reg.observers_on(&c1).len(), 2);

        begin_ctl(&mut reg, "3", &c1, DesktopGeneration(1), now);
        assert!(reg.controller_on(&c1).is_some());

        let (a4, m4, _, ci2) = parts("4");
        assert!(reg
            .begin_control(BeginInteraction {
                id: ci2,
                owner_account_id: a4,
                owner_manager_id: m4,
                monitoring_id: None,
                computer_id: c1.clone(),
                desktop_generation: DesktopGeneration(1),
                now,
                lease_ms: None,
                initial_generation: None,
            })
            .is_err());
    }

    #[test]
    fn pending_release_blocks_retake() {
        let mut reg = InteractionRegistry::new();
        let c1 = ComputerId::new("c-1").unwrap();
        let now = TimestampMs::new(0);
        let i1 = begin_ctl(&mut reg, "1", &c1, DesktopGeneration(1), now);
        reg.set_control_state(&i1, ControlState::Controlling, now)
            .unwrap();
        reg.set_input_forwarding(&i1, true).unwrap();
        reg.note_injected_input_down(&i1).unwrap();
        reg.set_control_state(&i1, ControlState::PendingRelease, now)
            .unwrap();
        assert_eq!(reg.get(&i1).unwrap().held_input_count, 0);
        assert!(
            reg.controller_on(&c1).is_some(),
            "slot held while unresolved"
        );

        let (a2, m2, _, i2) = parts("2");
        let err = reg
            .begin_control(BeginInteraction {
                id: i2,
                owner_account_id: a2,
                owner_manager_id: m2,
                monitoring_id: None,
                computer_id: c1.clone(),
                desktop_generation: DesktopGeneration(1),
                now,
                lease_ms: None,
                initial_generation: None,
            })
            .unwrap_err();
        assert_eq!(err.reason(), ReasonCode::PendingRelease);

        reg.acknowledge_control_release(&i1, now).unwrap();
        assert!(reg.controller_on(&c1).is_none());
        begin_ctl(&mut reg, "3", &c1, DesktopGeneration(1), now);
    }

    #[test]
    fn minimize_releases_control_keeps_viewing() {
        let mut reg = InteractionRegistry::new();
        let c1 = ComputerId::new("c-1").unwrap();
        let now = TimestampMs::new(0);
        begin_obs(&mut reg, "obs", &c1, DesktopGeneration(1), now);
        let i_ctl = begin_ctl(&mut reg, "ctl", &c1, DesktopGeneration(1), now);
        reg.set_control_state(&i_ctl, ControlState::Controlling, now)
            .unwrap();
        reg.set_input_forwarding(&i_ctl, true).unwrap();
        reg.note_injected_input_down(&i_ctl).unwrap();

        let outcome = reg.minimize_control_window(&i_ctl, now).unwrap();
        assert!(outcome.released_input);
        assert!(outcome.observation_preserved);
        assert_eq!(
            outcome.control_disposition,
            ControlDisposition::PendingRelease
        );
        assert_eq!(reg.observers_on(&c1).len(), 1, "viewing preserved");
    }

    #[test]
    fn desktop_change_tears_down_bound_work() {
        let mut reg = InteractionRegistry::new();
        let c1 = ComputerId::new("c-1").unwrap();
        let now = TimestampMs::new(0);
        let i1 = begin_obs(&mut reg, "1", &c1, DesktopGeneration(1), now);
        let ended = reg.teardown_desktop(DesktopGeneration(1));
        assert_eq!(ended, vec![i1]);
    }

    #[test]
    fn focus_loss_stops_forwarding_without_ending_lease() {
        let plan = plan_teardown(WindowEvent::FocusLost, true);
        assert!(plan.stop_forwarding);
        assert!(plan.release_held_input);
        assert!(!plan.end_observation);
        assert!(!plan.require_explicit_retake);
    }

    #[test]
    fn user_cannot_stop_share_branch() {
        let (a1, m1, c1, sid) = parts("1");
        let (a2, _, c2, _) = parts("2");
        let mut dist =
            SharingDistribution::new(sid, a1.clone(), m1, Some(c1), [c2.clone()]).unwrap();
        assert!(dist.user_stop_attempt(&c2).is_err());
        assert!(dist.stop_branch(&c2, &a2, false).is_err());
        assert!(dist.stop_branch(&c2, &a1, false).is_ok());
        assert!(dist.all_branches_terminal());
    }

    #[test]
    fn input_routing_requires_full_local_ownership() {
        let mut r = InputRouting {
            control_active: true,
            canvas_focused: true,
            local_ui_modal: false,
            window_foreground: true,
            generations_match: true,
        };
        assert!(r.forwards_input());
        r.local_ui_modal = true;
        assert!(!r.forwards_input());
        r.local_ui_modal = false;
        r.canvas_focused = false;
        assert!(!r.forwards_input());
    }

    #[test]
    fn expiry_ends_interactions_and_releases_input() {
        let mut reg = InteractionRegistry::new();
        let c1 = ComputerId::new("c-1").unwrap();
        let (a, m, _, i1) = parts("1");
        reg.begin_control(BeginInteraction {
            id: i1.clone(),
            owner_account_id: a,
            owner_manager_id: m,
            monitoring_id: None,
            computer_id: c1.clone(),
            desktop_generation: DesktopGeneration(1),
            now: TimestampMs::new(0),
            lease_ms: Some(1_000),
            initial_generation: None,
        })
        .unwrap();
        reg.set_control_state(&i1, ControlState::Controlling, TimestampMs::new(0))
            .unwrap();
        reg.set_input_forwarding(&i1, true).unwrap();
        reg.note_injected_input_down(&i1).unwrap();
        assert!(reg.has_held_input(&c1));

        let expired = reg.expire_at(TimestampMs::new(2_000));
        assert_eq!(expired.len(), 1);
        assert!(!reg.has_held_input(&c1));
        assert!(reg.controller_on(&c1).is_none());
    }
}
