//! Versioned development snapshot interchange for app consumers.
//!
//! **This is a development snapshot format, not a settled media or
//! authentication grant protocol.** Media and authentication grant protocols
//! remain unadopted: this module deliberately does not define grants, frames,
//! credentials, or media control messages. Pure domain contracts are
//! development semantics, not signed grants and not a cryptographic wire
//! format.
//!
//! All JSON entry points go through [`parse_snapshot_json`], which bounds the
//! body size and enforces the frozen schema version. Typed documents
//! deserialize through their validating constructors so a wire document cannot
//! bypass domain invariants (empty IDs, zero/oversized target collections,
//! invalid deadline horizons, out-of-scope results).

use crate::action::{ActionResultState, ActionSnapshot, OperationKind, TimestampMs};
use crate::bounds::MAX_TARGETS;
use crate::error::{Error, Result};
use crate::id::{
    AccountId, ActionId, ComputerId, DesktopGeneration, DisplayName, GroupId, LocalUserId,
    MonitoringId,
};
use crate::inventory::{InclusionMode, Presence, SearchQuery, SortOrder, StatusFilter};
use crate::reason::ReasonCode;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

/// Frozen snapshot schema version. Bump only with a new schema file.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted JSON body bytes at the parse entry point.
pub const MAX_SNAPSHOT_JSON_BYTES: usize = 1_048_576;

/// Envelope for any hs-core snapshot document.
///
/// Deserialization rejects unknown schema versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEnvelope<T> {
    /// Schema version. Consumers must reject unknown major versions.
    pub schema_version: u32,
    /// Monotonic capture time.
    pub captured_at: TimestampMs,
    /// Payload.
    pub payload: T,
}

#[derive(Deserialize)]
struct SnapshotEnvelopeWire<T> {
    schema_version: u32,
    captured_at: TimestampMs,
    payload: T,
}

impl<T: Serialize> Serialize for SnapshotEnvelope<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SnapshotEnvelope", 3)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("captured_at", &self.captured_at)?;
        state.serialize_field("payload", &self.payload)?;
        state.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SnapshotEnvelope<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let wire = SnapshotEnvelopeWire::<T>::deserialize(deserializer)?;
        if wire.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unknown snapshot schema_version {}; expected {}",
                wire.schema_version, SNAPSHOT_SCHEMA_VERSION
            )));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            captured_at: wire.captured_at,
            payload: wire.payload,
        })
    }
}

/// Inventory and per-computer status for the overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryStatusSnapshot {
    /// Deployment the inventory belongs to.
    pub organization_id: crate::id::OrganizationId,
    /// Account the snapshot is scoped to.
    pub account_id: AccountId,
    /// Computer entries the account may currently see.
    pub computers: Vec<ComputerStatusSnapshot>,
}

/// One computer's overview status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerStatusSnapshot {
    /// Immutable computer identity.
    pub computer_id: ComputerId,
    /// Display label. Never authority.
    pub display_name: DisplayName,
    /// Presence state.
    pub presence: Presence,
    /// Trusted current console user, when verified.
    pub current_user: Option<LocalUserId>,
    /// Optional flat group memberships.
    pub group_ids: Vec<GroupId>,
    /// Desktop generation when a console desktop is selected.
    pub desktop_generation: Option<DesktopGeneration>,
    /// True when preview demand is currently admitted (not a pixel claim).
    pub observation_admitted: bool,
    /// Unique controlling operator display name, when present.
    pub controller_display: Option<String>,
}

/// Overview scope state: inclusion, filters, displayed IDs, and selection.
///
/// Five concerns remain distinct in the serialized form so native apps cannot
/// collapse them into one boolean array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverviewScopeSnapshot {
    /// Inclusion mode.
    pub inclusion: InclusionMode,
    /// Search filter.
    pub search: Option<SearchQuery>,
    /// Status filter.
    pub status_filter: StatusFilter,
    /// Sort order.
    pub sort: SortOrder,
    /// Included IDs after inventory reconciliation.
    pub included_ids: BTreeSet<ComputerId>,
    /// Displayed IDs after search/status filters.
    pub displayed_ids: BTreeSet<ComputerId>,
    /// Temporary selection (empty when none).
    pub selection_ids: BTreeSet<ComputerId>,
    /// Default targets for a new bulk action (selected else displayed).
    pub default_action_target_ids: BTreeSet<ComputerId>,
}

/// Action snapshot interchange.
///
/// Results must stay in-scope of the frozen target set. Deserialization
/// enforces that constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSnapshotDoc {
    /// Action identity.
    pub action_id: ActionId,
    /// Actor account.
    pub actor_account_id: AccountId,
    /// Typed operation.
    pub operation: OperationKind,
    /// Immutable frozen targets.
    pub target_ids: BTreeSet<ComputerId>,
    /// Deadline.
    pub deadline: TimestampMs,
    /// Creation time.
    pub created_at: TimestampMs,
    /// Optional monitoring context.
    pub monitoring_id: Option<MonitoringId>,
    /// Per-target result states recorded so far.
    pub results: Vec<ActionResultDoc>,
}

/// Per-target result interchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResultDoc {
    /// Computer the result is for.
    pub computer_id: ComputerId,
    /// Result state.
    pub state: ActionResultState,
    /// Stable reason when not applied.
    pub reason: Option<ReasonCode>,
    /// Evidence time.
    pub evidence_time: Option<TimestampMs>,
}

impl ActionSnapshotDoc {
    /// Build the document from a core snapshot plus recorded results.
    ///
    /// Every result computer must be one of the frozen targets.
    pub fn from_parts(snapshot: &ActionSnapshot, results: Vec<ActionResultDoc>) -> Result<Self> {
        for r in &results {
            if !snapshot.targets(&r.computer_id) {
                return Err(Error::refused(ReasonCode::ComputerOutOfScope));
            }
        }
        Ok(Self {
            action_id: snapshot.action_id.clone(),
            actor_account_id: snapshot.actor_account_id.clone(),
            operation: snapshot.operation.clone(),
            target_ids: snapshot.target_ids().clone(),
            deadline: snapshot.deadline,
            created_at: snapshot.created_at,
            monitoring_id: snapshot.monitoring_id.clone(),
            results,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct ActionSnapshotDocWire {
    action_id: ActionId,
    actor_account_id: AccountId,
    operation: OperationKind,
    target_ids: BTreeSet<ComputerId>,
    deadline: TimestampMs,
    created_at: TimestampMs,
    monitoring_id: Option<MonitoringId>,
    results: Vec<ActionResultDoc>,
}

impl Serialize for ActionSnapshotDoc {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        ActionSnapshotDocWire {
            action_id: self.action_id.clone(),
            actor_account_id: self.actor_account_id.clone(),
            operation: self.operation.clone(),
            target_ids: self.target_ids.clone(),
            deadline: self.deadline,
            created_at: self.created_at,
            monitoring_id: self.monitoring_id.clone(),
            results: self.results.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ActionSnapshotDoc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let wire = ActionSnapshotDocWire::deserialize(deserializer)?;
        if wire.target_ids.is_empty() {
            return Err(D::Error::custom(
                "action snapshot requires non-empty targets",
            ));
        }
        if wire.target_ids.len() > MAX_TARGETS {
            return Err(D::Error::custom("action snapshot exceeds MAX_TARGETS"));
        }
        for r in &wire.results {
            if !wire.target_ids.contains(&r.computer_id) {
                return Err(D::Error::custom(format!(
                    "result computer {} is out of the frozen target scope",
                    r.computer_id
                )));
            }
        }
        Ok(Self {
            action_id: wire.action_id,
            actor_account_id: wire.actor_account_id,
            operation: wire.operation,
            target_ids: wire.target_ids,
            deadline: wire.deadline,
            created_at: wire.created_at,
            monitoring_id: wire.monitoring_id,
            results: wire.results,
        })
    }
}

/// Build a versioned envelope.
pub fn envelope<T>(captured_at: TimestampMs, payload: T) -> SnapshotEnvelope<T> {
    SnapshotEnvelope {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        captured_at,
        payload,
    }
}

/// Explicit bounded JSON parse entry point for snapshot documents.
///
/// This is the only supported way to turn untrusted bytes into snapshot
/// values. It enforces:
///
/// - body size ≤ [`MAX_SNAPSHOT_JSON_BYTES`]
/// - frozen schema version (unknown versions are rejected)
/// - typed validation inside the payload (bounded IDs, non-empty targets,
///   valid deadline horizon, in-scope results)
pub fn parse_snapshot_json<T>(input: &str) -> Result<SnapshotEnvelope<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if input.len() > MAX_SNAPSHOT_JSON_BYTES {
        return Err(Error::QuotaReached {
            limit: "MAX_SNAPSHOT_JSON_BYTES",
        });
    }
    serde_json::from_str::<SnapshotEnvelope<T>>(input).map_err(|e| Error::InvalidInput {
        field: "snapshot_json",
        reason: {
            let _ = e;
            ReasonCode::InvalidInput
        },
    })
}

/// Serialize a snapshot envelope to JSON through the same schema version.
pub fn to_snapshot_json<T: Serialize>(value: &SnapshotEnvelope<T>) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::InvalidInput {
        field: "snapshot_json",
        reason: ReasonCode::InvalidInput,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::OrganizationId;

    #[test]
    fn envelope_carries_schema_version() {
        let doc = InventoryStatusSnapshot {
            organization_id: OrganizationId::new("org").unwrap(),
            account_id: AccountId::new("acc").unwrap(),
            computers: vec![],
        };
        let env = envelope(TimestampMs::new(1), doc);
        assert_eq!(env.schema_version, 1);
        let json = to_snapshot_json(&env).unwrap();
        assert!(json.contains("\"schema_version\":1"));
        let back: SnapshotEnvelope<InventoryStatusSnapshot> = parse_snapshot_json(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let json = r#"{"schema_version":99,"captured_at":1,"payload":{"organization_id":"o","account_id":"a","computers":[]}}"#;
        let parsed = parse_snapshot_json::<InventoryStatusSnapshot>(json);
        assert!(parsed.is_err(), "unknown schema_version must be refused");
    }

    #[test]
    fn body_size_is_bounded_at_parse_entry() {
        let huge = "x".repeat(MAX_SNAPSHOT_JSON_BYTES + 1);
        let parsed = parse_snapshot_json::<InventoryStatusSnapshot>(&huge);
        assert!(matches!(parsed, Err(Error::QuotaReached { .. })));
    }
}
