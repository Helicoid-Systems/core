//! Regression tests for the coordinator review findings.
//!
//! These encode the exact public-API defects that were reproduced against the
//! previous build:
//!
//! 1. `serde_json::from_str::<ComputerId>("\"\"")` returned `Ok` (constructor
//!    bypass).
//! 2. `DesktopGeneration(u64::MAX).next()` saturated into the same generation
//!    (reusable authority).
//!
//! Plus the related validation gaps: bounded text/search, action snapshot
//! freeze invariants on the wire, unknown envelope schema versions, and
//! out-of-scope action results.

use hs_core::{
    parse_snapshot_json, to_snapshot_json, AccountId, ActionId, ActionResultDoc, ActionResultState,
    ActionSnapshot, ActionSnapshotDoc, BeginInteraction, BoundedText, ComputerId, ControlState,
    DesktopGeneration, DisplayName, FreezeAction, InteractionGeneration, InteractionId,
    InteractionRegistry, ManagerId, OperationKind, ReasonCode, SearchQuery, SharingDistribution,
    SnapshotEnvelope, TimestampMs,
};

fn computer(s: &str) -> ComputerId {
    ComputerId::new(s).unwrap()
}

// ---------------------------------------------------------------------------
// Finding 1: constructor bypass via serde
// ---------------------------------------------------------------------------

#[test]
fn empty_computer_id_deserialize_is_rejected() {
    // This was Ok("") before the fix.
    assert!(serde_json::from_str::<ComputerId>("\"\"").is_err());
}

#[test]
fn empty_display_name_and_bounded_text_deserialize_are_rejected() {
    assert!(serde_json::from_str::<DisplayName>("\"\"").is_err());
    assert!(serde_json::from_str::<BoundedText>("\"   \"").is_err());
    assert!(serde_json::from_str::<BoundedText>("\"hi\"").is_ok());
}

#[test]
fn oversized_search_query_deserialize_is_rejected() {
    let oversized = format!("\"{}\"", "a".repeat(65));
    assert!(serde_json::from_str::<SearchQuery>(&oversized).is_err());
    assert!(serde_json::from_str::<SearchQuery>("\"ok\"").is_ok());
}

#[test]
fn valid_computer_id_still_deserializes() {
    let id: ComputerId = serde_json::from_str("\"pc-01\"").unwrap();
    assert_eq!(id.as_str(), "pc-01");
}

// ---------------------------------------------------------------------------
// Finding 2: generation exhaustion must not saturate
// ---------------------------------------------------------------------------

#[test]
fn generation_exhaustion_refuses_reuse() {
    let max = DesktopGeneration(u64::MAX);
    assert!(max.is_exhausted());
    assert_eq!(max.next(), None, "must not return the same generation");
    assert!(max.try_next().is_err());
}

#[test]
fn max_generation_minimize_still_tears_down_conservatively() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-max");
    let now = TimestampMs::new(0);

    // New authority bound to an exhausted desktop generation is refused.
    let err = reg
        .begin_control(BeginInteraction {
            id: InteractionId::new("ctl-desk-max").unwrap(),
            owner_account_id: AccountId::new("acc").unwrap(),
            owner_manager_id: ManagerId::new("mgr").unwrap(),
            monitoring_id: None,
            computer_id: c.clone(),
            desktop_generation: DesktopGeneration(u64::MAX),
            now,
            lease_ms: None,
            initial_generation: None,
        })
        .unwrap_err();
    assert_eq!(err.reason(), ReasonCode::Expired);

    // An interaction already at the exhausted generation can still minimize
    // (safety teardown), but cannot advance to a reusable fence.
    let ctl = InteractionId::new("ctl-gen-max").unwrap();
    reg.begin_control(BeginInteraction {
        id: ctl.clone(),
        owner_account_id: AccountId::new("acc").unwrap(),
        owner_manager_id: ManagerId::new("mgr").unwrap(),
        monitoring_id: None,
        computer_id: c.clone(),
        desktop_generation: DesktopGeneration(1),
        now,
        lease_ms: None,
        initial_generation: Some(InteractionGeneration(u64::MAX)),
    })
    .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap();
    reg.set_input_forwarding(&ctl, true).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();

    let outcome = reg.minimize_control_window(&ctl, now).unwrap();
    assert!(
        outcome.released_input,
        "teardown must not depend on generation"
    );
    assert_eq!(
        outcome.generation_fenced, None,
        "exhausted generation must not saturate into a reusable fence"
    );
    assert_eq!(reg.get(&ctl).unwrap().held_input_count, 0);
    assert!(!reg.get(&ctl).unwrap().input_forwarding);
}

#[test]
fn exhausted_interaction_generation_blocks_new_authority_but_allows_teardown() {
    // Direct counter semantics: exhaustion is Option::None, never Self.
    let g = InteractionGeneration(u64::MAX);
    assert!(g.next().is_none());
    assert!(g.try_next().is_err());
    // A non-exhausted counter still advances.
    assert_eq!(
        InteractionGeneration(1).next(),
        Some(InteractionGeneration(2))
    );
}

#[test]
fn share_teardown_at_max_generation_is_conservative() {
    let owner = AccountId::new("owner").unwrap();
    let mut dist = SharingDistribution::new(
        InteractionId::new("share").unwrap(),
        owner.clone(),
        ManagerId::new("mgr").unwrap(),
        Some(computer("src")),
        [computer("r1"), computer("r2")],
    )
    .unwrap();
    // Normal source-generation bump works.
    assert!(dist.bump_source_generation().is_ok());

    // Branch and distribution teardown do not depend on generation capacity.
    assert!(dist.stop_branch(&computer("r1"), &owner, false).is_ok());
    assert!(!dist.all_branches_terminal());
    assert!(dist.stop_all(&owner, true).is_ok());
    assert!(dist.all_branches_terminal());
    // User stop remains refused even at teardown.
    assert!(dist.user_stop_attempt(&computer("r2")).is_err());

    // Exhaustion of the generation counter refuses a further bump and never
    // saturates into a reusable value.
    assert!(InteractionGeneration(u64::MAX).next().is_none());
    assert!(InteractionGeneration(u64::MAX).try_next().is_err());
}

// ---------------------------------------------------------------------------
// Wire validation: action snapshots and envelopes
// ---------------------------------------------------------------------------

#[test]
fn action_snapshot_deserialize_rejects_zero_targets() {
    let json = r#"{
        "action_id":"act",
        "actor_account_id":"acc",
        "operation":"SendMessage",
        "target_ids":[],
        "deadline":6000,
        "created_at":1000,
        "desktop_generation":null,
        "monitoring_id":null
    }"#;
    let parsed = serde_json::from_str::<ActionSnapshot>(json);
    assert!(parsed.is_err(), "zero targets must be refused on the wire");
}

#[test]
fn action_snapshot_deserialize_rejects_invalid_horizon() {
    // deadline == created_at (0 ms horizon) is below MIN_ACTION_DEADLINE_MS.
    let json = r#"{
        "action_id":"act",
        "actor_account_id":"acc",
        "operation":"SendMessage",
        "target_ids":["c1"],
        "deadline":1000,
        "created_at":1000,
        "desktop_generation":null,
        "monitoring_id":null
    }"#;
    assert!(serde_json::from_str::<ActionSnapshot>(json).is_err());
}

#[test]
fn action_snapshot_deserialize_roundtrips_valid_payload() {
    let snap = ActionSnapshot::freeze(FreezeAction {
        action_id: ActionId::new("act-rt").unwrap(),
        actor_account_id: AccountId::new("acc").unwrap(),
        operation: OperationKind::StartObservation,
        target_ids: vec![computer("c1"), computer("c2")],
        created_at: TimestampMs::new(1_000),
        deadline_in_ms: 5_000,
        desktop_generation: Some(DesktopGeneration(1)),
        monitoring_id: None,
    })
    .unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    let back: ActionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, snap);
}

#[test]
fn action_doc_rejects_out_of_scope_results() {
    let snap = ActionSnapshot::freeze(FreezeAction {
        action_id: ActionId::new("act-scope").unwrap(),
        actor_account_id: AccountId::new("acc").unwrap(),
        operation: OperationKind::StartObservation,
        target_ids: vec![computer("c1")],
        created_at: TimestampMs::new(1_000),
        deadline_in_ms: 5_000,
        desktop_generation: None,
        monitoring_id: None,
    })
    .unwrap();

    let out_of_scope = ActionResultDoc {
        computer_id: computer("intruder"),
        state: ActionResultState::Applied,
        reason: None,
        evidence_time: None,
    };
    let err = ActionSnapshotDoc::from_parts(&snap, vec![out_of_scope]).unwrap_err();
    assert_eq!(err.reason(), ReasonCode::ComputerOutOfScope);
}

#[test]
fn action_doc_wire_rejects_out_of_scope_results() {
    let json = r#"{
        "action_id":"act",
        "actor_account_id":"acc",
        "operation":"SendMessage",
        "target_ids":["c1"],
        "deadline":6000,
        "created_at":1000,
        "monitoring_id":null,
        "results":[{"computer_id":"intruder","state":"Applied","reason":null,"evidence_time":null}]
    }"#;
    assert!(serde_json::from_str::<ActionSnapshotDoc>(json).is_err());
}

#[test]
fn envelope_rejects_unknown_schema_version() {
    let json = r#"{"schema_version":2,"captured_at":1,"payload":{
        "organization_id":"o","account_id":"a","computers":[]
    }}"#;
    let parsed = parse_snapshot_json::<hs_core::snapshot::InventoryStatusSnapshot>(json);
    assert!(parsed.is_err());
}

#[test]
fn envelope_roundtrips_through_parse_entry_point() {
    let doc = hs_core::snapshot::InventoryStatusSnapshot {
        organization_id: hs_core::OrganizationId::new("org").unwrap(),
        account_id: AccountId::new("acc").unwrap(),
        computers: vec![],
    };
    let env = SnapshotEnvelope {
        schema_version: hs_core::snapshot::SNAPSHOT_SCHEMA_VERSION,
        captured_at: TimestampMs::new(3),
        payload: doc,
    };
    let json = to_snapshot_json(&env).unwrap();
    let back = parse_snapshot_json(&json).unwrap();
    assert_eq!(back, env);
}
