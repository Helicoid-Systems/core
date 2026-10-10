//! Immutable action snapshots and action result states.
//!
//! Opening an action composer freezes its computer IDs. Group edits, search,
//! new enrollment, reconnect, and selection changes behind the dialog cannot
//! expand that snapshot. A zero-sized target set cannot dispatch. Results are
//! per computer; same-ID duplicates with a different payload are rejected.

use crate::bounds::{MAX_ACTION_DEADLINE_MS, MAX_TARGETS, MIN_ACTION_DEADLINE_MS};
use crate::error::{Error, Result};
use crate::id::{ActionId, ComputerId, DesktopGeneration};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Monotonic milliseconds supplied by the host. Wall-clock changes cannot
/// extend a lease; hosts convert deadlines to local monotonic deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimestampMs(pub u64);

impl TimestampMs {
    /// Milliseconds since a host-defined monotonic origin.
    pub const fn new(ms: u64) -> Self {
        Self(ms)
    }

    /// Raw millisecond value.
    pub const fn as_ms(self) -> u64 {
        self.0
    }

    /// Duration between two timestamps; zero when `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A typed operation an action performs. Payloads stay typed; never shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OperationKind {
    /// Stop this owner's monitoring session.
    StopMonitoring,
    /// Start view-only observation on the current desktop.
    StartObservation,
    /// Stop an identified observation.
    StopObservation,
    /// Request exclusive control on the current desktop.
    TakeControl,
    /// Release exclusive control.
    StopControl,
    /// Start screen sharing to the frozen receiver set.
    StartSharing,
    /// Stop a sharing distribution or named branch.
    StopSharing,
    /// Apply attention with a bounded plain message.
    ApplyAttention,
    /// Release attention on the frozen targets.
    ReleaseAttention,
    /// Send a bounded plain message.
    SendMessage,
    /// Request help on the frozen targets.
    RequestHelp,
    /// Open an HTTP(S) website.
    OpenWebsite,
    /// Launch an approved catalog application.
    LaunchApp,
    /// Send files under a scoped manifest (D14/D29 recipient binding lives server-side).
    SendFiles,
    /// Request files from computer users.
    RequestFiles,
    /// Capture a screenshot.
    Screenshot,
    /// Typed machine action.
    MachineAction(crate::capability::MachineActionKind),
    /// Tear down an identified interaction.
    StopInteraction,
}

/// Immutable action snapshot captured when the composer opens.
///
/// `target_ids` never expands. Partial results refer to this snapshot.
///
/// Deserialization runs the same freeze invariants as [`ActionSnapshot::freeze`]:
/// non-empty bounded targets and a deadline inside the accepted horizon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSnapshot {
    /// Stable action identity for dispatch and deduplication.
    pub action_id: ActionId,
    /// Actor account that opened the composer.
    pub actor_account_id: crate::id::AccountId,
    /// Typed operation.
    pub operation: OperationKind,
    /// Frozen computer IDs. Immutable after construction.
    target_ids: BTreeSet<ComputerId>,
    /// Inclusive deadline; work is not attempted after this timestamp.
    pub deadline: TimestampMs,
    /// Creation timestamp.
    pub created_at: TimestampMs,
    /// Desktop generation recorded at snapshot time when the operation is
    /// desktop-bound. Used to refuse stale execution after desktop change.
    pub desktop_generation: Option<DesktopGeneration>,
    /// Optional monitoring context this action belongs to.
    pub monitoring_id: Option<crate::id::MonitoringId>,
}

/// Parameters for freezing a new [`ActionSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreezeAction {
    /// Stable action identity for dispatch and deduplication.
    pub action_id: ActionId,
    /// Actor account that opened the composer.
    pub actor_account_id: crate::id::AccountId,
    /// Typed operation.
    pub operation: OperationKind,
    /// Computer IDs to freeze. Must be non-empty.
    pub target_ids: Vec<ComputerId>,
    /// Creation timestamp.
    pub created_at: TimestampMs,
    /// Deadline horizon in milliseconds from `created_at`.
    pub deadline_in_ms: u64,
    /// Desktop generation at snapshot time when the operation is desktop-bound.
    pub desktop_generation: Option<DesktopGeneration>,
    /// Optional monitoring context this action belongs to.
    pub monitoring_id: Option<crate::id::MonitoringId>,
}

impl ActionSnapshot {
    /// Freeze a new action snapshot.
    ///
    /// `target_ids` must be non-empty (zero targets cannot dispatch) and within
    /// [`MAX_TARGETS`]. The deadline must lie within the accepted horizon.
    pub fn freeze(params: FreezeAction) -> Result<Self> {
        if !(MIN_ACTION_DEADLINE_MS..=MAX_ACTION_DEADLINE_MS).contains(&params.deadline_in_ms) {
            return Err(Error::InvalidInput {
                field: "deadline_in_ms",
                reason: ReasonCode::InvalidInput,
            });
        }
        let mut frozen = BTreeSet::new();
        for id in params.target_ids {
            if frozen.len() >= MAX_TARGETS {
                return Err(Error::QuotaReached {
                    limit: "MAX_TARGETS action targets",
                });
            }
            frozen.insert(id);
        }
        validate_snapshot_targets(&frozen)?;
        Ok(Self {
            action_id: params.action_id,
            actor_account_id: params.actor_account_id,
            operation: params.operation,
            target_ids: frozen,
            deadline: TimestampMs(params.created_at.0.saturating_add(params.deadline_in_ms)),
            created_at: params.created_at,
            desktop_generation: params.desktop_generation,
            monitoring_id: params.monitoring_id,
        })
    }

    /// The immutable target set.
    pub fn target_ids(&self) -> &BTreeSet<ComputerId> {
        &self.target_ids
    }

    /// Number of frozen targets.
    pub fn target_count(&self) -> usize {
        self.target_ids.len()
    }

    /// True when `now` is still within the frozen deadline.
    pub fn is_open_at(&self, now: TimestampMs) -> bool {
        now.0 <= self.deadline.0
    }

    /// True when `id` is one of the frozen targets.
    pub fn targets(&self, id: &ComputerId) -> bool {
        self.target_ids.contains(id)
    }

    /// Rebuild a snapshot from parts, enforcing the same invariants as freeze.
    ///
    /// Used by deserialization so a wire document cannot bypass
    /// [`ActionSnapshot::freeze`].
    pub fn from_parts(parts: ActionSnapshotParts) -> Result<Self> {
        validate_snapshot_targets(&parts.target_ids)?;
        validate_snapshot_deadline(parts.created_at, parts.deadline)?;
        Ok(Self {
            action_id: parts.action_id,
            actor_account_id: parts.actor_account_id,
            operation: parts.operation,
            target_ids: parts.target_ids,
            deadline: parts.deadline,
            created_at: parts.created_at,
            desktop_generation: parts.desktop_generation,
            monitoring_id: parts.monitoring_id,
        })
    }
}

/// Validated reconstruction input for [`ActionSnapshot::from_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSnapshotParts {
    /// Action identity.
    pub action_id: ActionId,
    /// Actor account.
    pub actor_account_id: crate::id::AccountId,
    /// Typed operation.
    pub operation: OperationKind,
    /// Frozen computer IDs.
    pub target_ids: BTreeSet<ComputerId>,
    /// Inclusive deadline.
    pub deadline: TimestampMs,
    /// Creation timestamp.
    pub created_at: TimestampMs,
    /// Desktop generation at snapshot time, when desktop-bound.
    pub desktop_generation: Option<DesktopGeneration>,
    /// Optional monitoring context.
    pub monitoring_id: Option<crate::id::MonitoringId>,
}

/// Non-empty and within [`MAX_TARGETS`].
fn validate_snapshot_targets(target_ids: &BTreeSet<ComputerId>) -> Result<()> {
    if target_ids.is_empty() {
        return Err(Error::refused(ReasonCode::ZeroTargets));
    }
    if target_ids.len() > MAX_TARGETS {
        return Err(Error::QuotaReached {
            limit: "MAX_TARGETS action targets",
        });
    }
    Ok(())
}

/// Deadline must lie inside the accepted horizon after `created_at`.
fn validate_snapshot_deadline(created_at: TimestampMs, deadline: TimestampMs) -> Result<()> {
    let horizon = deadline.0.saturating_sub(created_at.0);
    if deadline.0 < created_at.0
        || !(MIN_ACTION_DEADLINE_MS..=MAX_ACTION_DEADLINE_MS).contains(&horizon)
    {
        return Err(Error::InvalidInput {
            field: "deadline",
            reason: ReasonCode::InvalidInput,
        });
    }
    Ok(())
}

/// Wire form of [`ActionSnapshot`] with the frozen target set exposed.
#[derive(Serialize, Deserialize)]
struct ActionSnapshotWire {
    action_id: ActionId,
    actor_account_id: crate::id::AccountId,
    operation: OperationKind,
    target_ids: BTreeSet<ComputerId>,
    deadline: TimestampMs,
    created_at: TimestampMs,
    desktop_generation: Option<DesktopGeneration>,
    monitoring_id: Option<crate::id::MonitoringId>,
}

impl Serialize for ActionSnapshot {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        ActionSnapshotWire {
            action_id: self.action_id.clone(),
            actor_account_id: self.actor_account_id.clone(),
            operation: self.operation.clone(),
            target_ids: self.target_ids.clone(),
            deadline: self.deadline,
            created_at: self.created_at,
            desktop_generation: self.desktop_generation,
            monitoring_id: self.monitoring_id.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ActionSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let wire = ActionSnapshotWire::deserialize(deserializer)?;
        Self::from_parts(ActionSnapshotParts {
            action_id: wire.action_id,
            actor_account_id: wire.actor_account_id,
            operation: wire.operation,
            target_ids: wire.target_ids,
            deadline: wire.deadline,
            created_at: wire.created_at,
            desktop_generation: wire.desktop_generation,
            monitoring_id: wire.monitoring_id,
        })
        .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Per-target action result state. Issued, delivered, applied, unavailable,
/// and outcome unknown are different (I11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ActionResultState {
    /// Undispatched current user intent. Cancel or dispatch before deadline.
    QueuedLocally,
    /// Server durably accepted scope/action.
    Issued,
    /// Authenticated endpoint accepted the message.
    Delivered,
    /// Endpoint reported the defined effect.
    Applied,
    /// Authority/capability/policy/input denied.
    Rejected,
    /// Target offline or session absent before execution.
    Unavailable,
    /// Cancellable work stopped before its stated boundary.
    Cancelled,
    /// Deadline/authority ended without verified effect.
    Expired,
    /// Effect may have happened but durable ack is missing.
    OutcomeUnknown,
}

/// One computer's result for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetResult {
    /// Action the result belongs to.
    pub action_id: ActionId,
    /// Computer the result is for.
    pub computer_id: ComputerId,
    /// Desktop generation at execution time, when applicable.
    pub desktop_generation: Option<DesktopGeneration>,
    /// Result state.
    pub state: ActionResultState,
    /// Stable reason when not `Applied`.
    pub reason: Option<ReasonCode>,
    /// Evidence time reported by the endpoint.
    pub evidence_time: Option<TimestampMs>,
    /// Endpoint generation that produced the result (fencing).
    pub endpoint_generation: Option<u64>,
}

impl TargetResult {
    /// True when the result is terminal and must not be retried automatically.
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ActionResultState::Applied
                | ActionResultState::Rejected
                | ActionResultState::Unavailable
                | ActionResultState::Cancelled
                | ActionResultState::Expired
                | ActionResultState::OutcomeUnknown
        )
    }
}

/// Action journal: immutable snapshots plus per-target results with
/// deduplication (I12).
///
/// Same action ID with a different payload is rejected. A repeat of the same
/// ID returns the recorded result rather than re-executing.
#[derive(Debug, Clone, Default)]
pub struct ActionJournal {
    snapshots: std::collections::BTreeMap<ActionId, ActionSnapshot>,
    results: std::collections::BTreeMap<(ActionId, ComputerId), TargetResult>,
}

impl ActionJournal {
    /// Empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a frozen snapshot. Fails if the ID already exists with a
    /// different payload (stable-ID deduplication).
    pub fn record_snapshot(&mut self, snapshot: ActionSnapshot) -> Result<()> {
        match self.snapshots.get(&snapshot.action_id) {
            Some(existing) => {
                if existing == &snapshot {
                    Ok(())
                } else {
                    Err(Error::refused(ReasonCode::Replayed))
                }
            }
            None => {
                self.snapshots.insert(snapshot.action_id.clone(), snapshot);
                Ok(())
            }
        }
    }

    /// Borrow a recorded snapshot.
    pub fn snapshot(&self, action_id: &ActionId) -> Option<&ActionSnapshot> {
        self.snapshots.get(action_id)
    }

    /// Record a per-target result. Replaces only a non-terminal prior state
    /// with a newer state for the same (action, computer) pair; a terminal
    /// result is immutable so late acks cannot resurrect work.
    pub fn record_result(&mut self, result: TargetResult) -> Result<()> {
        let key = (result.action_id.clone(), result.computer_id.clone());
        if let Some(existing) = self.results.get(&key) {
            if existing.is_terminal() {
                // Allow recording OutcomeUnknown over a non-terminal path only
                // via explicit reconcile; a terminal record is final.
                return Err(Error::refused(ReasonCode::Replayed));
            }
        }
        self.results.insert(key, result);
        Ok(())
    }

    /// Explicit reconciliation for a crash between effect and durable ack.
    ///
    /// Moves a non-terminal or `OutcomeUnknown` record to the reconciled
    /// terminal state. Never auto-repeats a destructive effect.
    pub fn reconcile_result(&mut self, result: TargetResult) -> Result<()> {
        let key = (result.action_id.clone(), result.computer_id.clone());
        match self.results.get(&key) {
            Some(existing) if existing.state == ActionResultState::OutcomeUnknown => {
                self.results.insert(key, result);
                Ok(())
            }
            Some(existing) if existing.is_terminal() => Err(Error::refused(ReasonCode::Replayed)),
            _ => {
                self.results.insert(key, result);
                Ok(())
            }
        }
    }

    /// Recorded result for one (action, computer) pair.
    pub fn result(&self, action_id: &ActionId, computer_id: &ComputerId) -> Option<&TargetResult> {
        self.results.get(&(action_id.clone(), computer_id.clone()))
    }

    /// All recorded snapshots, for audit/export.
    pub fn snapshots(&self) -> impl Iterator<Item = &ActionSnapshot> {
        self.snapshots.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::AccountId;

    fn id(s: &str) -> ComputerId {
        ComputerId::new(s).unwrap()
    }

    #[test]
    fn snapshot_targets_are_immutable() {
        let snap = ActionSnapshot::freeze(FreezeAction {
            action_id: ActionId::new("act-1").unwrap(),
            actor_account_id: AccountId::new("acc-1").unwrap(),
            operation: OperationKind::StartObservation,
            target_ids: vec![id("c1"), id("c2")],
            created_at: TimestampMs::new(1_000),
            deadline_in_ms: 5_000,
            desktop_generation: None,
            monitoring_id: None,
        })
        .unwrap();
        assert_eq!(snap.target_count(), 2);
        assert!(snap.targets(&id("c1")));
        assert!(!snap.targets(&id("c3")));
        assert!(snap.is_open_at(TimestampMs::new(6_000)));
        assert!(!snap.is_open_at(TimestampMs::new(6_001)));
    }

    #[test]
    fn zero_targets_cannot_dispatch() {
        assert!(matches!(
            ActionSnapshot::freeze(FreezeAction {
                action_id: ActionId::new("act-0").unwrap(),
                actor_account_id: AccountId::new("acc-1").unwrap(),
                operation: OperationKind::SendMessage,
                target_ids: vec![],
                created_at: TimestampMs::new(0),
                deadline_in_ms: 5_000,
                desktop_generation: None,
                monitoring_id: None,
            }),
            Err(Error::Refused {
                reason: ReasonCode::ZeroTargets
            })
        ));
    }

    #[test]
    fn journal_rejects_same_id_different_payload() {
        let mut journal = ActionJournal::new();
        let a = ActionSnapshot::freeze(FreezeAction {
            action_id: ActionId::new("act-1").unwrap(),
            actor_account_id: AccountId::new("acc-1").unwrap(),
            operation: OperationKind::SendMessage,
            target_ids: vec![id("c1")],
            created_at: TimestampMs::new(0),
            deadline_in_ms: 5_000,
            desktop_generation: None,
            monitoring_id: None,
        })
        .unwrap();
        let b = ActionSnapshot::freeze(FreezeAction {
            action_id: ActionId::new("act-1").unwrap(),
            actor_account_id: AccountId::new("acc-1").unwrap(),
            operation: OperationKind::SendMessage,
            target_ids: vec![id("c2")],
            created_at: TimestampMs::new(0),
            deadline_in_ms: 5_000,
            desktop_generation: None,
            monitoring_id: None,
        })
        .unwrap();
        journal.record_snapshot(a.clone()).unwrap();
        journal.record_snapshot(a).unwrap();
        assert!(journal.record_snapshot(b).is_err());
    }

    #[test]
    fn terminal_results_are_final() {
        let mut journal = ActionJournal::new();
        let action_id = ActionId::new("act-1").unwrap();
        journal
            .record_result(TargetResult {
                action_id: action_id.clone(),
                computer_id: id("c1"),
                desktop_generation: None,
                state: ActionResultState::Applied,
                reason: None,
                evidence_time: Some(TimestampMs::new(10)),
                endpoint_generation: Some(1),
            })
            .unwrap();
        assert!(journal
            .record_result(TargetResult {
                action_id: action_id.clone(),
                computer_id: id("c1"),
                desktop_generation: None,
                state: ActionResultState::Applied,
                reason: None,
                evidence_time: Some(TimestampMs::new(20)),
                endpoint_generation: Some(2),
            })
            .is_err());
    }

    #[test]
    fn outcome_unknown_can_be_reconciled_without_replay() {
        let mut journal = ActionJournal::new();
        let action_id = ActionId::new("act-2").unwrap();
        journal
            .record_result(TargetResult {
                action_id: action_id.clone(),
                computer_id: id("c1"),
                desktop_generation: None,
                state: ActionResultState::OutcomeUnknown,
                reason: Some(ReasonCode::OutcomeUnknown),
                evidence_time: None,
                endpoint_generation: None,
            })
            .unwrap();
        journal
            .reconcile_result(TargetResult {
                action_id: action_id.clone(),
                computer_id: id("c1"),
                desktop_generation: None,
                state: ActionResultState::Applied,
                reason: None,
                evidence_time: Some(TimestampMs::new(30)),
                endpoint_generation: Some(3),
            })
            .unwrap();
        assert_eq!(
            journal.result(&action_id, &id("c1")).unwrap().state,
            ActionResultState::Applied
        );
    }
}
