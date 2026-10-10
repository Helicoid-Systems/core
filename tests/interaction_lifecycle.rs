//! Integration tests: observation/control lifecycle, teardown, and races
//! (D19, D24, D27, V08, V37, V41).

use hs_core::{
    plan_teardown, AccountId, BeginInteraction, ComputerId, ControlDisposition, ControlState,
    DesktopGeneration, InteractionId, InteractionRegistry, ManagerId, ReasonCode,
    SharingDistribution, TimestampMs, WindowEvent,
};

fn computer(s: &str) -> ComputerId {
    ComputerId::new(s).unwrap()
}

fn obs_params(
    n: &str,
    c: &ComputerId,
    gen: DesktopGeneration,
    now: TimestampMs,
) -> BeginInteraction {
    BeginInteraction {
        id: InteractionId::new(format!("obs-{n}")).unwrap(),
        owner_account_id: AccountId::new(format!("acc-{n}")).unwrap(),
        owner_manager_id: ManagerId::new(format!("mgr-{n}")).unwrap(),
        monitoring_id: None,
        computer_id: c.clone(),
        desktop_generation: gen,
        now,
        lease_ms: None,
        initial_generation: None,
    }
}

fn ctl_params(
    n: &str,
    c: &ComputerId,
    gen: DesktopGeneration,
    now: TimestampMs,
) -> BeginInteraction {
    BeginInteraction {
        id: InteractionId::new(format!("ctl-{n}")).unwrap(),
        owner_account_id: AccountId::new(format!("acc-{n}")).unwrap(),
        owner_manager_id: ManagerId::new(format!("mgr-{n}")).unwrap(),
        monitoring_id: None,
        computer_id: c.clone(),
        desktop_generation: gen,
        now,
        lease_ms: None,
        initial_generation: None,
    }
}

#[test]
fn two_operators_observe_independently_one_controls() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    reg.begin_observation(obs_params("alice", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.begin_observation(obs_params("bob", &c, DesktopGeneration(1), now))
        .unwrap();
    assert_eq!(reg.observers_on(&c).len(), 2);

    reg.begin_control(ctl_params("alice", &c, DesktopGeneration(1), now))
        .unwrap();
    // Bob cannot silently displace Alice's control.
    let err = reg
        .begin_control(ctl_params("bob", &c, DesktopGeneration(1), now))
        .unwrap_err();
    assert_eq!(err.reason(), ReasonCode::InUse);

    // Alice's pause (stop her observation) does not stop Bob.
    let alice_obs = InteractionId::new("obs-alice").unwrap();
    reg.end_interaction(&alice_obs).unwrap();
    assert_eq!(reg.observers_on(&c).len(), 1);
    assert!(reg.controller_on(&c).is_some(), "control is independent");
}

#[test]
fn minimize_pending_release_then_explicit_retake() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    reg.begin_observation(obs_params("alice", &c, DesktopGeneration(1), now))
        .unwrap();
    let ctl = InteractionId::new("ctl-alice").unwrap();
    reg.begin_control(ctl_params("alice", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap();
    reg.set_input_forwarding(&ctl, true).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();

    let outcome = reg.minimize_control_window(&ctl, now).unwrap();
    assert!(outcome.released_input);
    assert_eq!(
        outcome.control_disposition,
        ControlDisposition::PendingRelease
    );
    assert_eq!(reg.get(&ctl).unwrap().held_input_count, 0);
    assert!(!reg.get(&ctl).unwrap().input_forwarding);

    // Restore does not resume control; retake is refused while unresolved.
    assert!(reg
        .begin_control(ctl_params("alice-2", &c, DesktopGeneration(1), now))
        .is_err());
    // Viewing remains.
    assert_eq!(reg.observers_on(&c).len(), 1);

    // After release reconciliation, explicit Take Control works again.
    reg.acknowledge_control_release(&ctl, now).unwrap();
    assert!(reg.controller_on(&c).is_none());
    reg.begin_control(ctl_params("alice-2", &c, DesktopGeneration(1), now))
        .unwrap();
}

#[test]
fn focus_loss_releases_held_input_but_keeps_lease() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    let ctl = InteractionId::new("ctl-a").unwrap();
    reg.begin_control(BeginInteraction {
        id: ctl.clone(),
        owner_account_id: AccountId::new("acc-a").unwrap(),
        owner_manager_id: ManagerId::new("mgr-a").unwrap(),
        monitoring_id: None,
        computer_id: c.clone(),
        desktop_generation: DesktopGeneration(1),
        now,
        lease_ms: None,
        initial_generation: None,
    })
    .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap();
    reg.set_input_forwarding(&ctl, true).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();

    reg.set_input_forwarding(&ctl, false).unwrap();
    assert_eq!(reg.get(&ctl).unwrap().held_input_count, 0);
    assert!(!reg.get(&ctl).unwrap().input_forwarding);
    // Lease still held: not a Pending Release.
    assert!(reg.controller_on(&c).is_some());
}

#[test]
fn desktop_change_tears_down_observation_and_control() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    reg.begin_observation(obs_params("a", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.begin_control(ctl_params("a", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.set_control_state(
        &InteractionId::new("ctl-a").unwrap(),
        ControlState::Controlling,
        now,
    )
    .unwrap();
    reg.set_input_forwarding(&InteractionId::new("ctl-a").unwrap(), true)
        .unwrap();
    reg.note_injected_input_down(&InteractionId::new("ctl-a").unwrap())
        .unwrap();

    let ended = reg.teardown_desktop(DesktopGeneration(1));
    assert_eq!(ended.len(), 2);
    assert!(!reg.has_held_input(&c));
    assert!(reg.controller_on(&c).is_none());
    assert!(reg.observers_on(&c).is_empty());
}

#[test]
fn expiry_releases_input_and_clears_controller() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let ctl = InteractionId::new("ctl-a").unwrap();
    reg.begin_control(BeginInteraction {
        id: ctl.clone(),
        owner_account_id: AccountId::new("acc-a").unwrap(),
        owner_manager_id: ManagerId::new("mgr-a").unwrap(),
        monitoring_id: None,
        computer_id: c.clone(),
        desktop_generation: DesktopGeneration(1),
        now: TimestampMs::new(0),
        lease_ms: Some(2_000),
        initial_generation: None,
    })
    .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, TimestampMs::new(0))
        .unwrap();
    reg.set_input_forwarding(&ctl, true).unwrap();
    reg.note_injected_input_down(&ctl).unwrap();

    let expired = reg.expire_at(TimestampMs::new(5_000));
    assert_eq!(expired, vec![ctl]);
    assert!(!reg.has_held_input(&c));
    assert!(reg.controller_on(&c).is_none());
}

#[test]
fn race_late_ack_cannot_resurrect_stopped_control() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    let ctl = InteractionId::new("ctl-a").unwrap();
    reg.begin_control(ctl_params("a", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap();
    reg.set_control_state(&ctl, ControlState::Stopped, now)
        .unwrap();

    // Late Authorizing/Controlling acknowledgment is fenced.
    let err = reg
        .set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap_err();
    assert_eq!(err.reason(), ReasonCode::LateGeneration);
    assert!(reg.controller_on(&c).is_none());
}

#[test]
fn race_desktop_change_during_pending_release_still_ends_claim() {
    let mut reg = InteractionRegistry::new();
    let c = computer("pc-01");
    let now = TimestampMs::new(0);
    let ctl = InteractionId::new("ctl-a").unwrap();
    reg.begin_control(ctl_params("a", &c, DesktopGeneration(1), now))
        .unwrap();
    reg.set_control_state(&ctl, ControlState::Controlling, now)
        .unwrap();
    reg.minimize_control_window(&ctl, now).unwrap();

    // Desktop change wins the race and ends the unresolved claim.
    let ended = reg.teardown_desktop(DesktopGeneration(1));
    assert!(ended.contains(&ctl));
    assert!(reg.controller_on(&c).is_none(), "slot released by teardown");
}

#[test]
fn teardown_plan_minimize_vs_focus_are_distinct() {
    let min = plan_teardown(WindowEvent::Minimized, true);
    let focus = plan_teardown(WindowEvent::FocusLost, true);
    assert!(min.release_active_control && min.require_explicit_retake);
    assert!(!focus.release_active_control && !focus.require_explicit_retake);
    assert!(min.keep_observation && focus.keep_observation);

    let desktop = plan_teardown(WindowEvent::DesktopChanged, true);
    assert!(desktop.end_observation && desktop.clear_frames);
}

#[test]
fn share_branch_stop_is_owner_or_it_only() {
    let owner = AccountId::new("owner").unwrap();
    let stranger = AccountId::new("stranger").unwrap();
    let mut dist = SharingDistribution::new(
        InteractionId::new("share-1").unwrap(),
        owner.clone(),
        ManagerId::new("mgr").unwrap(),
        Some(computer("src")),
        [computer("r1"), computer("r2")],
    )
    .unwrap();

    assert!(dist.stop_branch(&computer("r1"), &stranger, false).is_err());
    assert!(dist.stop_branch(&computer("r1"), &owner, false).is_ok());
    // Branch stop does not end the other recipient.
    assert!(!dist.all_branches_terminal());
    assert!(dist.stop_all(&stranger, false).is_err());
    // Scoped IT stop is allowed.
    assert!(dist.stop_all(&stranger, true).is_ok());
    assert!(dist.all_branches_terminal());
}

#[test]
fn user_stop_attempt_never_succeeds() {
    let mut dist = SharingDistribution::new(
        InteractionId::new("share-1").unwrap(),
        AccountId::new("owner").unwrap(),
        ManagerId::new("mgr").unwrap(),
        Some(computer("src")),
        [computer("r1")],
    )
    .unwrap();
    let err = dist.user_stop_attempt(&computer("r1")).unwrap_err();
    assert_eq!(err.reason(), ReasonCode::PermissionDenied);
}
