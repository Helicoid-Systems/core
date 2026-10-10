//! Inventory, monitoring inclusion, displayed filters, and temporary selection.
//!
//! Five state objects stay separate (ui.md selection rules):
//!
//! 1. **Authorized inventory** — computer IDs the account may currently see.
//! 2. **Monitoring inclusion** — the remembered All/explicit choice of which
//!    authorized computers appear in the overview. A preference only; it
//!    grants no permission and never retargets an open action.
//! 3. **Displayed IDs** — inclusion after search and status filters.
//! 4. **Temporary action selection** — selected overview tiles for the next
//!    command. Cleared when inclusion, search, or status filters change.
//! 5. **Admitted streams** — not modeled here; see [`crate::interaction`].
//!
//! New bulk actions target selected displayed IDs, or all displayed IDs when
//! nothing is selected. A zero-sized target set cannot dispatch.

use crate::bounds::{char_count, MAX_SEARCH_CHARS, MAX_TARGETS};
use crate::error::{Error, Result};
use crate::id::{ComputerId, DisplayName, GroupId, LocalUserId};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How the overview chooses which authorized computers appear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionMode {
    /// Follow current authorized inventory (D18: newly eligible IDs may appear).
    All,
    /// Only these explicit IDs. Never silently expands.
    Explicit {
        /// Included computer IDs.
        ids: BTreeSet<ComputerId>,
    },
}

/// Bounded overview search query. Matches computer name and trusted user name.
///
/// Deserialization runs the same length validation as construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery(String);

impl SearchQuery {
    /// Create a validated search query.
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if char_count(&raw) > MAX_SEARCH_CHARS {
            return Err(Error::InvalidInput {
                field: "SearchQuery",
                reason: ReasonCode::InvalidInput,
            });
        }
        Ok(Self(raw))
    }

    /// Borrow the query text. May be empty (no filter).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when no search filter is active.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl serde::Serialize for SearchQuery {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SearchQuery {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Overview status filter. Offline computers remain displayed when included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum StatusFilter {
    /// Show every included computer regardless of online state.
    #[default]
    Any,
    /// Show only computers currently reporting online.
    OnlineOnly,
    /// Show only computers currently reporting offline.
    OfflineOnly,
}

/// Stable sort order for overview tiles. Sort changes preserve selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum SortOrder {
    /// Default stable order by computer display name then ID.
    #[default]
    Name,
    /// Order by current online state then name.
    StatusThenName,
}

/// One computer's presence/status as shown in the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Presence {
    /// Reachable; work can proceed subject to capability checks.
    Online,
    /// Not currently reachable.
    Offline,
    /// Reachable but no eligible console user.
    NoUserSignedIn,
    /// Reachable but screen permission is missing.
    ScreenPermissionNeeded,
    /// Reachable but the build/platform is unsupported for monitoring.
    UnsupportedVersion,
    /// Identity needs review / quarantined.
    IdentityNeedsReview,
}

impl Presence {
    /// True when the computer counts as "online" for status filtering.
    pub const fn is_online(self) -> bool {
        matches!(
            self,
            Self::Online | Self::NoUserSignedIn | Self::ScreenPermissionNeeded
        )
    }
}

/// Per-computer overview inventory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerInventoryEntry {
    /// Immutable enrolled computer identity.
    pub computer_id: ComputerId,
    /// Display label. Never authority.
    pub display_name: DisplayName,
    /// Current presence as reported by the endpoint/server.
    pub presence: Presence,
    /// Trusted current console user identity for search, if verified.
    pub current_user: Option<LocalUserId>,
    /// Optional flat group memberships. Membership alone never grants access.
    pub group_ids: Vec<GroupId>,
}

/// Overview preference: remembered, revalidated UI state. No grants, frames,
/// or persisted control state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverviewPreference {
    /// All mode or explicit included IDs.
    pub inclusion: InclusionMode,
    /// Optional search filter.
    pub search: Option<SearchQuery>,
    /// Status filter.
    pub status_filter: StatusFilter,
    /// Tile sort order.
    pub sort: SortOrder,
}

impl Default for OverviewPreference {
    fn default() -> Self {
        Self {
            inclusion: InclusionMode::All,
            search: None,
            status_filter: StatusFilter::Any,
            sort: SortOrder::Name,
        }
    }
}

/// Tri-state checkbox used by the optional group inclusion UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckboxState {
    /// No member IDs included.
    Unchecked,
    /// Every member ID included.
    Checked,
    /// Some member IDs included.
    Mixed,
}

/// Overview scope state: inventory + inclusion + filters + temporary selection.
///
/// This type deliberately keeps the five concerns separate. Selection is
/// cleared whenever inclusion, search, or status filter changes; sort changes
/// preserve selected IDs that remain displayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OverviewState {
    inventory: BTreeMap<ComputerId, ComputerInventoryEntry>,
    preference: OverviewPreference,
    selection: BTreeSet<ComputerId>,
}

impl OverviewState {
    /// Empty overview with the default All-inclusion preference.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the authorized inventory snapshot.
    ///
    /// Restoring a preference never invents authority: IDs that left the
    /// authorized inventory are dropped from inclusion and selection.
    pub fn set_inventory(
        &mut self,
        entries: impl IntoIterator<Item = ComputerInventoryEntry>,
    ) -> Result<()> {
        let mut map = BTreeMap::new();
        for entry in entries {
            if map.len() >= MAX_TARGETS {
                return Err(Error::QuotaReached {
                    limit: "MAX_TARGETS inventory",
                });
            }
            map.insert(entry.computer_id.clone(), entry);
        }
        self.inventory = map;
        self.reconcile_selection_and_inclusion();
        Ok(())
    }

    /// Update one inventory entry in place (presence, user, groups, name).
    pub fn upsert_entry(&mut self, entry: ComputerInventoryEntry) -> Result<()> {
        if !self.inventory.contains_key(&entry.computer_id) && self.inventory.len() >= MAX_TARGETS {
            return Err(Error::QuotaReached {
                limit: "MAX_TARGETS inventory",
            });
        }
        self.inventory.insert(entry.computer_id.clone(), entry);
        self.reconcile_selection_and_inclusion();
        Ok(())
    }

    /// Look up one inventory entry.
    pub fn entry(&self, id: &ComputerId) -> Option<&ComputerInventoryEntry> {
        self.inventory.get(id)
    }

    /// Current authorized inventory IDs.
    pub fn inventory_ids(&self) -> impl Iterator<Item = &ComputerId> {
        self.inventory.keys()
    }

    /// True when `id` is in the authorized inventory.
    pub fn is_authorized(&self, id: &ComputerId) -> bool {
        self.inventory.contains_key(id)
    }

    /// Current preference snapshot.
    pub const fn preference(&self) -> &OverviewPreference {
        &self.preference
    }

    /// Change monitoring inclusion. Clears temporary selection.
    pub fn set_inclusion(&mut self, mode: InclusionMode) -> Result<()> {
        if let InclusionMode::Explicit { ids } = &mode {
            if ids.len() > MAX_TARGETS {
                return Err(Error::QuotaReached {
                    limit: "MAX_TARGETS inclusion",
                });
            }
            if ids.iter().any(|id| !self.inventory.contains_key(id)) {
                return Err(Error::refused(ReasonCode::ComputerOutOfScope));
            }
        }
        self.preference.inclusion = mode;
        self.selection.clear();
        self.reconcile_selection_and_inclusion();
        Ok(())
    }

    /// Set the search filter. Clears temporary selection.
    pub fn set_search(&mut self, query: Option<SearchQuery>) {
        self.preference.search = query;
        self.selection.clear();
    }

    /// Set the status filter. Clears temporary selection.
    pub fn set_status_filter(&mut self, filter: StatusFilter) {
        self.preference.status_filter = filter;
        self.selection.clear();
    }

    /// Set the sort order. Preserves selected IDs that remain displayed.
    pub fn set_sort(&mut self, sort: SortOrder) {
        self.preference.sort = sort;
        self.reconcile_selection_and_inclusion();
    }

    /// Included IDs under the current inclusion mode, intersected with inventory.
    pub fn included_ids(&self) -> BTreeSet<ComputerId> {
        match &self.preference.inclusion {
            InclusionMode::All => self.inventory.keys().cloned().collect(),
            InclusionMode::Explicit { ids } => ids
                .iter()
                .filter(|id| self.inventory.contains_key(id))
                .cloned()
                .collect(),
        }
    }

    /// Displayed IDs: inclusion after search and status filters.
    ///
    /// Displayed offline computers remain displayed; callers decide whether an
    /// action can execute on them. Zero displayed IDs cannot dispatch.
    pub fn displayed_ids(&self) -> BTreeSet<ComputerId> {
        self.included_ids()
            .into_iter()
            .filter(|id| self.passes_filters(id))
            .collect()
    }

    /// Temporary action selection (may be empty).
    pub fn selection_ids(&self) -> &BTreeSet<ComputerId> {
        &self.selection
    }

    /// Replace the temporary selection with exactly these displayed IDs.
    pub fn set_selection(&mut self, ids: impl IntoIterator<Item = ComputerId>) -> Result<()> {
        let displayed = self.displayed_ids();
        let mut selection = BTreeSet::new();
        for id in ids {
            if !displayed.contains(&id) {
                return Err(Error::refused(ReasonCode::ComputerOutOfScope));
            }
            selection.insert(id);
        }
        if selection.len() > MAX_TARGETS {
            return Err(Error::QuotaReached {
                limit: "MAX_TARGETS selection",
            });
        }
        self.selection = selection;
        Ok(())
    }

    /// Toggle one displayed tile in the temporary selection.
    pub fn toggle_selected(&mut self, id: &ComputerId) -> Result<()> {
        if !self.displayed_ids().contains(id) {
            return Err(Error::refused(ReasonCode::ComputerOutOfScope));
        }
        if !self.selection.remove(id) {
            self.selection.insert(id.clone());
        }
        Ok(())
    }

    /// Clear the temporary selection (empty-grid click / Clear Selection).
    pub fn clear_selection(&mut self) {
        self.selection.clear();
    }

    /// Default target IDs for a new bulk action: selected displayed IDs, or
    /// all displayed IDs when nothing is selected.
    ///
    /// Returns [`Error::Refused`] with [`ReasonCode::ZeroTargets`] when empty.
    /// Displayed offline computers remain valid targets.
    pub fn default_action_targets(&self) -> Result<BTreeSet<ComputerId>> {
        let targets = if self.selection.is_empty() {
            self.displayed_ids()
        } else {
            self.selection
                .iter()
                .filter(|id| self.displayed_ids().contains(id))
                .cloned()
                .collect()
        };
        if targets.is_empty() {
            return Err(Error::refused(ReasonCode::ZeroTargets));
        }
        Ok(targets)
    }

    /// Checkbox tri-state for one optional flat group.
    pub fn group_checkbox_state(&self, group_id: &GroupId) -> CheckboxState {
        let members = self.group_member_ids(group_id);
        if members.is_empty() {
            return CheckboxState::Unchecked;
        }
        let included = self.included_ids();
        let included_count = members.iter().filter(|id| included.contains(id)).count();
        if included_count == 0 {
            CheckboxState::Unchecked
        } else if included_count == members.len() {
            CheckboxState::Checked
        } else {
            CheckboxState::Mixed
        }
    }

    /// Apply a group checkbox action to inclusion, then clear selection.
    ///
    /// Checking adds the group's currently authorized members; unchecking
    /// removes them. Clicking mixed adds all. Always results in explicit
    /// inclusion (All mode cannot partially include).
    pub fn apply_group_checkbox(
        &mut self,
        group_id: &GroupId,
        desired: CheckboxState,
    ) -> Result<()> {
        let members = self.group_member_ids(group_id);
        let mut current = self.included_ids();
        match desired {
            CheckboxState::Checked | CheckboxState::Mixed => current.extend(members),
            CheckboxState::Unchecked => {
                for id in &members {
                    current.remove(id);
                }
            }
        }
        self.set_inclusion(InclusionMode::Explicit { ids: current })
    }

    /// Switch to All mode (the All Computers checkbox checked).
    pub fn select_all_mode(&mut self) -> Result<()> {
        self.set_inclusion(InclusionMode::All)
    }

    /// Uncheck All Computers: explicit empty set.
    pub fn clear_inclusion(&mut self) -> Result<()> {
        self.set_inclusion(InclusionMode::Explicit {
            ids: BTreeSet::new(),
        })
    }

    fn group_member_ids(&self, group_id: &GroupId) -> BTreeSet<ComputerId> {
        self.inventory
            .values()
            .filter(|e| e.group_ids.iter().any(|g| g == group_id))
            .map(|e| e.computer_id.clone())
            .collect()
    }

    fn passes_filters(&self, id: &ComputerId) -> bool {
        let Some(entry) = self.inventory.get(id) else {
            return false;
        };
        let status_ok = match self.preference.status_filter {
            StatusFilter::Any => true,
            StatusFilter::OnlineOnly => entry.presence.is_online(),
            StatusFilter::OfflineOnly => !entry.presence.is_online(),
        };
        if !status_ok {
            return false;
        }
        match &self.preference.search {
            None => true,
            Some(q) if q.is_empty() => true,
            Some(q) => {
                let needle = q.as_str().to_lowercase();
                entry.display_name.as_str().to_lowercase().contains(&needle)
                    || entry
                        .current_user
                        .as_ref()
                        .map(|u| u.as_str().to_lowercase().contains(&needle))
                        .unwrap_or(false)
            }
        }
    }

    fn reconcile_selection_and_inclusion(&mut self) {
        let included = self.included_ids();
        self.selection.retain(|id| included.contains(id));
        if let InclusionMode::Explicit { ids } = &mut self.preference.inclusion {
            ids.retain(|id| self.inventory.contains_key(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, online: bool) -> ComputerInventoryEntry {
        ComputerInventoryEntry {
            computer_id: ComputerId::new(id).unwrap(),
            display_name: DisplayName::new(name).unwrap(),
            presence: if online {
                Presence::Online
            } else {
                Presence::Offline
            },
            current_user: None,
            group_ids: vec![],
        }
    }

    #[test]
    fn displayed_selection_and_targets_are_separate() {
        let e1 = entry("c1", "Alpha", true);
        let e2 = entry("c2", "Beta", false);
        let e3 = entry("c3", "Gamma", true);

        let mut ov = OverviewState::new();
        ov.set_inventory([e1.clone(), e2.clone(), e3.clone()])
            .unwrap();
        ov.set_inclusion(InclusionMode::Explicit {
            ids: [e1.computer_id.clone(), e2.computer_id.clone()].into(),
        })
        .unwrap();

        assert_eq!(ov.included_ids().len(), 2);
        assert_eq!(ov.displayed_ids().len(), 2);

        // No selection → default targets are all displayed (including offline).
        let targets = ov.default_action_targets().unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&e2.computer_id), "offline stays a target");

        ov.set_selection([e1.computer_id.clone()]).unwrap();
        assert_eq!(
            ov.default_action_targets().unwrap(),
            [e1.computer_id.clone()].into()
        );

        ov.set_search(Some(SearchQuery::new("Beta").unwrap()));
        assert!(ov.selection_ids().is_empty());
        assert_eq!(ov.displayed_ids(), [e2.computer_id.clone()].into());
    }

    #[test]
    fn filter_changes_clear_selection_but_sort_preserves_it() {
        let e1 = entry("c1", "Alpha", true);
        let e2 = entry("c2", "Beta", true);
        let mut ov = OverviewState::new();
        ov.set_inventory([e1.clone(), e2.clone()]).unwrap();
        ov.set_selection([e2.computer_id.clone()]).unwrap();
        ov.set_sort(SortOrder::StatusThenName);
        assert_eq!(ov.selection_ids().len(), 1, "sort preserves selection");
        ov.set_status_filter(StatusFilter::OnlineOnly);
        assert!(
            ov.selection_ids().is_empty(),
            "status filter clears selection"
        );
    }

    #[test]
    fn zero_displayed_cannot_dispatch() {
        let ov = OverviewState::new();
        assert!(matches!(
            ov.default_action_targets(),
            Err(Error::Refused {
                reason: ReasonCode::ZeroTargets
            })
        ));
    }

    #[test]
    fn explicit_inclusion_never_silently_expands() {
        let e1 = entry("c1", "Alpha", true);
        let e2 = entry("c2", "Beta", true);
        let mut ov = OverviewState::new();
        ov.set_inventory([e1.clone()]).unwrap();
        ov.set_inclusion(InclusionMode::Explicit {
            ids: [e1.computer_id.clone()].into(),
        })
        .unwrap();

        // D18: new inventory in explicit mode does not join inclusion.
        ov.set_inventory([e1.clone(), e2.clone()]).unwrap();
        assert_eq!(ov.included_ids(), [e1.computer_id.clone()].into());
        assert_eq!(ov.displayed_ids(), [e1.computer_id.clone()].into());
    }

    #[test]
    fn group_checkbox_mixed_adds_all() {
        let mut e1 = entry("c1", "Alpha", true);
        let mut e2 = entry("c2", "Beta", true);
        let g = GroupId::new("g1").unwrap();
        e1.group_ids = vec![g.clone()];
        e2.group_ids = vec![g.clone()];
        let mut ov = OverviewState::new();
        ov.set_inventory([e1.clone(), e2.clone()]).unwrap();
        ov.set_inclusion(InclusionMode::Explicit {
            ids: [e1.computer_id.clone()].into(),
        })
        .unwrap();
        assert_eq!(ov.group_checkbox_state(&g), CheckboxState::Mixed);
        ov.apply_group_checkbox(&g, CheckboxState::Mixed).unwrap();
        assert_eq!(ov.group_checkbox_state(&g), CheckboxState::Checked);
    }
}
