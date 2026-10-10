//! Integration tests: fail-closed engine boundary and console generations
//! (I01/I03/I05/I09/I16, I20, D25, D26, V40).

use hs_core::{
    preview_readiness, select_physical_console, BootGeneration, ComputerId, ComputerRuntime,
    DesktopGeneration, DesktopIdentity, DisplayId, EngineHealth, LayoutGeneration,
    PreviewReadiness, ReasonCode, SessionEligibility, TimestampMs, WorkerGeneration,
};

fn desktop(
    id: &str,
    session: u32,
    gen: u64,
    eligibility: SessionEligibility,
    display: Option<&str>,
) -> DesktopIdentity {
    DesktopIdentity {
        computer_id: ComputerId::new(id).unwrap(),
        os_session_ref: session,
        local_user: None,
        desktop_generation: DesktopGeneration(gen),
        boot_generation: BootGeneration(1),
        worker_generation: WorkerGeneration(1),
        primary_display: display.map(|d| DisplayId::new(d).unwrap()),
        layout_generation: LayoutGeneration(1),
        eligibility,
    }
}

#[test]
fn rdp_or_background_sessions_are_never_selected() {
    let c = ComputerId::new("pc").unwrap();
    let only_rdp = desktop(
        "pc",
        2,
        1,
        SessionEligibility::UnsupportedSession,
        Some("d"),
    );
    assert!(select_physical_console(c.clone(), &[only_rdp]).is_err());

    let unlocked_bg = desktop("pc", 3, 1, SessionEligibility::NoUserSignedIn, Some("d"));
    assert!(select_physical_console(c, &[unlocked_bg]).is_err());
}

#[test]
fn ambiguous_multi_session_facts_refuse_rather_than_pick_first() {
    let c = ComputerId::new("pc").unwrap();
    let mut a = desktop("pc", 1, 1, SessionEligibility::Eligible, Some("d"));
    let mut b = desktop("pc", 2, 2, SessionEligibility::Eligible, Some("d"));
    a.desktop_generation = DesktopGeneration(1);
    b.desktop_generation = DesktopGeneration(2);
    assert!(select_physical_console(c, &[a, b]).is_err());
}

#[test]
fn reused_os_session_number_is_not_reusable_authority() {
    let a = desktop("pc", 1, 1, SessionEligibility::Eligible, Some("d"));
    let mut b = desktop("pc", 1, 2, SessionEligibility::Eligible, Some("d"));
    b.desktop_generation = DesktopGeneration(2);
    assert!(!a.same_authority(&b));
    assert_eq!(a.os_session_ref, b.os_session_ref);
}

#[test]
fn engine_unavailable_fails_closed_for_new_work_but_not_teardown() {
    let mut rt = ComputerRuntime::new(ComputerId::new("pc").unwrap());
    rt.set_desktop(desktop("pc", 1, 1, SessionEligibility::Eligible, Some("d")));
    assert!(rt.ensure_new_work().is_ok());

    rt.set_engine_unavailable(ReasonCode::NotSaved, TimestampMs::new(10));
    let err = rt.ensure_new_work().unwrap_err();
    assert_eq!(err.reason(), ReasonCode::EngineUnavailable);

    // Teardown paths do not consult ensure_new_work.
    assert!(rt.clear_desktop().is_some());
    assert!(rt.clear_desktop().is_none());

    // Healthy only after explicit repair.
    rt.set_engine_healthy();
    assert!(rt.ensure_new_work().is_ok());
}

#[test]
fn machine_action_reservation_blocks_new_desktop_claims() {
    let mut rt = ComputerRuntime::new(ComputerId::new("pc").unwrap());
    rt.reserve_machine_action().unwrap();
    let err = rt.ensure_new_work().unwrap_err();
    assert_eq!(err.reason(), ReasonCode::MachineActionPending);
    rt.clear_machine_action_reservation();
    assert!(rt.ensure_new_work().is_ok());
}

#[test]
fn preview_readiness_never_substitutes_missing_primary_display() {
    let healthy = EngineHealth::Healthy;
    let mut d = desktop("pc", 1, 1, SessionEligibility::Eligible, None);
    d.primary_display = None;
    assert_eq!(
        preview_readiness(&d, &healthy),
        PreviewReadiness::PrimaryDisplayUnavailable
    );

    let with_display = desktop("pc", 1, 1, SessionEligibility::Eligible, Some("disp"));
    match preview_readiness(&with_display, &healthy) {
        PreviewReadiness::ReadyForAdmission { display_id, .. } => {
            assert_eq!(display_id.as_str(), "disp");
        }
        other => panic!("expected ReadyForAdmission, got {other:?}"),
    }
}

#[test]
fn preview_readiness_reflects_engine_and_session_state() {
    let mut d = desktop("pc", 1, 1, SessionEligibility::Eligible, Some("disp"));
    d.eligibility = SessionEligibility::LockedOrProtectedDesktop;
    assert_eq!(
        preview_readiness(&d, &EngineHealth::Healthy),
        PreviewReadiness::Locked
    );

    let healthy_desktop = desktop("pc", 1, 1, SessionEligibility::Eligible, Some("disp"));
    let down = EngineHealth::Unavailable {
        reason: ReasonCode::NotSaved,
        since: TimestampMs::new(1),
    };
    assert_eq!(
        preview_readiness(&healthy_desktop, &down),
        PreviewReadiness::EngineUnavailable
    );
}

#[test]
fn earliest_engine_unavailability_wins() {
    let mut rt = ComputerRuntime::new(ComputerId::new("pc").unwrap());
    rt.set_engine_unavailable(ReasonCode::NotSaved, TimestampMs::new(50));
    rt.set_engine_unavailable(ReasonCode::EngineUnavailable, TimestampMs::new(10));
    match rt.engine_health() {
        EngineHealth::Unavailable { since, reason } => {
            // The earliest latch time is retained; the later call with a
            // newer timestamp cannot move it forward.
            assert_eq!(since.as_ms(), 10);
            assert_eq!(*reason, ReasonCode::EngineUnavailable);
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }

    // A newer unavailability does not displace the earlier latch.
    rt.set_engine_unavailable(ReasonCode::NotSaved, TimestampMs::new(99));
    match rt.engine_health() {
        EngineHealth::Unavailable { since, .. } => assert_eq!(since.as_ms(), 10),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}
