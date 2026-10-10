//! Integration tests: overview inclusion/selection/target separation (V06).

use hs_core::{
    ComputerId, ComputerInventoryEntry, DisplayName, Error, InclusionMode, OverviewState, Presence,
    ReasonCode, SearchQuery, StatusFilter,
};

fn entry(id: &str, name: &str, presence: Presence) -> ComputerInventoryEntry {
    ComputerInventoryEntry {
        computer_id: ComputerId::new(id).unwrap(),
        display_name: DisplayName::new(name).unwrap(),
        presence,
        current_user: None,
        group_ids: vec![],
    }
}

#[test]
fn inventory_change_while_composer_open_does_not_expand_snapshot() {
    let mut ov = OverviewState::new();
    ov.set_inventory([
        entry("c1", "Alpha", Presence::Online),
        entry("c2", "Beta", Presence::Online),
    ])
    .unwrap();

    // Freeze an action over the currently displayed set.
    let targets = ov.default_action_targets().unwrap();
    assert_eq!(targets.len(), 2);

    // New enrollment appears; explicit inclusion never expands silently.
    ov.set_inventory([
        entry("c1", "Alpha", Presence::Online),
        entry("c2", "Beta", Presence::Online),
        entry("c3", "Gamma", Presence::Online),
    ])
    .unwrap();
    // The already-computed target set is a value: it is not live-expanded.
    assert_eq!(targets.len(), 2, "existing action snapshots stay fixed");
    assert!(!targets.contains(&ComputerId::new("c3").unwrap()));

    // Default targets for a NEW action may include the new computer in All mode.
    assert_eq!(ov.default_action_targets().unwrap().len(), 3);
}

#[test]
fn selection_requires_displayed_ids() {
    let mut ov = OverviewState::new();
    ov.set_inventory([
        entry("c1", "Alpha", Presence::Online),
        entry("c2", "Beta", Presence::Offline),
    ])
    .unwrap();
    ov.set_status_filter(StatusFilter::OnlineOnly);

    // c2 is included but not displayed under OnlineOnly.
    assert!(ov.set_selection([ComputerId::new("c2").unwrap()]).is_err());
    ov.set_selection([ComputerId::new("c1").unwrap()]).unwrap();
    assert_eq!(ov.selection_ids().len(), 1);
}

#[test]
fn search_matches_computer_name_case_insensitively() {
    let mut ov = OverviewState::new();
    ov.set_inventory([
        entry("c1", "Lab Mac", Presence::Online),
        entry("c2", "Lab PC", Presence::Online),
    ])
    .unwrap();
    ov.set_search(Some(SearchQuery::new("mac").unwrap()));
    assert_eq!(ov.displayed_ids().len(), 1);
    assert!(ov.displayed_ids().contains(&ComputerId::new("c1").unwrap()));
}

#[test]
fn zero_displayed_disables_dispatch() {
    let mut ov = OverviewState::new();
    ov.set_inventory([entry("c1", "Alpha", Presence::Online)])
        .unwrap();
    ov.set_search(Some(SearchQuery::new("zzz").unwrap()));
    let err = ov.default_action_targets().unwrap_err();
    assert_eq!(err.reason(), ReasonCode::ZeroTargets);
}

#[test]
fn inclusion_outside_inventory_is_refused() {
    let mut ov = OverviewState::new();
    ov.set_inventory([entry("c1", "Alpha", Presence::Online)])
        .unwrap();
    let err = ov
        .set_inclusion(InclusionMode::Explicit {
            ids: [ComputerId::new("ghost").unwrap()].into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::Refused { .. }));
}

#[test]
fn offline_computers_stay_action_targets_when_displayed() {
    let mut ov = OverviewState::new();
    ov.set_inventory([
        entry("c1", "Alpha", Presence::Online),
        entry("c2", "Beta", Presence::Offline),
    ])
    .unwrap();
    let targets = ov.default_action_targets().unwrap();
    assert!(targets.contains(&ComputerId::new("c2").unwrap()));
}
