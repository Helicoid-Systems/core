//! Integration tests: immutable action snapshots and result journal (V04, V06).

use hs_core::{
    AccountId, ActionId, ActionJournal, ActionResultState, ActionSnapshot, ComputerId, Error,
    FreezeAction, OperationKind, ReasonCode, TargetResult, TimestampMs,
};

fn computer(s: &str) -> ComputerId {
    ComputerId::new(s).unwrap()
}

fn freeze(id: &str, targets: Vec<ComputerId>) -> ActionSnapshot {
    ActionSnapshot::freeze(FreezeAction {
        action_id: ActionId::new(id).unwrap(),
        actor_account_id: AccountId::new("acc-1").unwrap(),
        operation: OperationKind::StartObservation,
        target_ids: targets,
        created_at: TimestampMs::new(1_000),
        deadline_in_ms: 5_000,
        desktop_generation: None,
        monitoring_id: None,
    })
    .unwrap()
}

#[test]
fn frozen_targets_do_not_follow_later_selection() {
    let snap = freeze("act-1", vec![computer("c1"), computer("c2")]);
    // Simulate later selection change: the snapshot is a value and stays fixed.
    assert_eq!(snap.target_count(), 2);
    assert!(snap.targets(&computer("c1")));
    assert!(!snap.targets(&computer("c3")));
}

#[test]
fn duplicate_action_id_with_different_payload_is_rejected() {
    let mut journal = ActionJournal::new();
    let a = freeze("act-dup", vec![computer("c1")]);
    let b = freeze("act-dup", vec![computer("c2")]);
    journal.record_snapshot(a).unwrap();
    let err = journal.record_snapshot(b).unwrap_err();
    assert_eq!(err.reason(), ReasonCode::Replayed);
}

#[test]
fn deadline_horizon_is_bounded() {
    let err = ActionSnapshot::freeze(FreezeAction {
        action_id: ActionId::new("act-bad").unwrap(),
        actor_account_id: AccountId::new("acc-1").unwrap(),
        operation: OperationKind::SendMessage,
        target_ids: vec![computer("c1")],
        created_at: TimestampMs::new(0),
        deadline_in_ms: 1,
        desktop_generation: None,
        monitoring_id: None,
    })
    .unwrap_err();
    assert!(matches!(err, Error::InvalidInput { .. }));

    let err = ActionSnapshot::freeze(FreezeAction {
        action_id: ActionId::new("act-bad2").unwrap(),
        actor_account_id: AccountId::new("acc-1").unwrap(),
        operation: OperationKind::SendMessage,
        target_ids: vec![computer("c1")],
        created_at: TimestampMs::new(0),
        deadline_in_ms: 25 * 60 * 60 * 1_000,
        desktop_generation: None,
        monitoring_id: None,
    })
    .unwrap_err();
    assert!(matches!(err, Error::InvalidInput { .. }));
}

#[test]
fn applied_result_is_final_until_explicit_reconcile() {
    let mut journal = ActionJournal::new();
    let snap = freeze("act-final", vec![computer("c1")]);
    journal.record_snapshot(snap).unwrap();
    journal
        .record_result(TargetResult {
            action_id: ActionId::new("act-final").unwrap(),
            computer_id: computer("c1"),
            desktop_generation: None,
            state: ActionResultState::Applied,
            reason: None,
            evidence_time: Some(TimestampMs::new(2_000)),
            endpoint_generation: Some(1),
        })
        .unwrap();
    let err = journal
        .record_result(TargetResult {
            action_id: ActionId::new("act-final").unwrap(),
            computer_id: computer("c1"),
            desktop_generation: None,
            state: ActionResultState::Applied,
            reason: None,
            evidence_time: Some(TimestampMs::new(3_000)),
            endpoint_generation: Some(2),
        })
        .unwrap_err();
    assert_eq!(err.reason(), ReasonCode::Replayed);
}

#[test]
fn outcome_unknown_never_auto_repeats() {
    let mut journal = ActionJournal::new();
    journal
        .record_result(TargetResult {
            action_id: ActionId::new("act-unk").unwrap(),
            computer_id: computer("c1"),
            desktop_generation: None,
            state: ActionResultState::OutcomeUnknown,
            reason: Some(ReasonCode::OutcomeUnknown),
            evidence_time: None,
            endpoint_generation: None,
        })
        .unwrap();
    // A second record attempt is refused (no automatic repeat).
    let err = journal
        .record_result(TargetResult {
            action_id: ActionId::new("act-unk").unwrap(),
            computer_id: computer("c1"),
            desktop_generation: None,
            state: ActionResultState::Applied,
            reason: None,
            evidence_time: None,
            endpoint_generation: Some(9),
        })
        .unwrap_err();
    assert_eq!(err.reason(), ReasonCode::Replayed);

    // Explicit reconciliation is the only path forward.
    journal
        .reconcile_result(TargetResult {
            action_id: ActionId::new("act-unk").unwrap(),
            computer_id: computer("c1"),
            desktop_generation: None,
            state: ActionResultState::Applied,
            reason: None,
            evidence_time: Some(TimestampMs::new(4_000)),
            endpoint_generation: Some(9),
        })
        .unwrap();
    assert_eq!(
        journal
            .result(&ActionId::new("act-unk").unwrap(), &computer("c1"))
            .unwrap()
            .state,
        ActionResultState::Applied
    );
}
