//! Named opt-in development fixtures.
//!
//! Explicit development fixtures are allowed behind the
//! `development-fixtures` cargo feature. They are never production pixels and
//! never become live preview frames. Enabling this feature is a build-time
//! opt-in for local development and tests only.

/// Marker proving development fixtures are explicitly enabled.
///
/// Production builds compile this module to an empty surface: without the
/// `development-fixtures` feature there is no way to construct fixture data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevelopmentMode;

#[cfg(feature = "development-fixtures")]
mod fixtures {
    use crate::id::{ComputerId, DisplayName};
    use crate::inventory::{ComputerInventoryEntry, Presence};

    /// Deterministic overview inventory for local UI development.
    ///
    /// These entries are labeled development fixtures. They are not enrolled
    /// computers, not captured screens, and must never be shown as live
    /// previews. Callers must render them behind an explicit development badge.
    pub fn development_inventory() -> Vec<ComputerInventoryEntry> {
        vec![
            ComputerInventoryEntry {
                computer_id: ComputerId::new("dev-fix-01").expect("static id"),
                display_name: DisplayName::new("Dev Lab 01").expect("static name"),
                presence: Presence::Online,
                current_user: None,
                group_ids: vec![],
            },
            ComputerInventoryEntry {
                computer_id: ComputerId::new("dev-fix-02").expect("static id"),
                display_name: DisplayName::new("Dev Lab 02").expect("static name"),
                presence: Presence::Offline,
                current_user: None,
                group_ids: vec![],
            },
            ComputerInventoryEntry {
                computer_id: ComputerId::new("dev-fix-03").expect("static id"),
                display_name: DisplayName::new("Dev Lab 03").expect("static name"),
                presence: Presence::NoUserSignedIn,
                current_user: None,
                group_ids: vec![],
            },
        ]
    }
}

#[cfg(feature = "development-fixtures")]
pub use fixtures::development_inventory;
