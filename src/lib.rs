//! # hs-core
//!
//! Shared Helicoid computer-monitoring domain contracts for Helicoid Systems'
//! **Helicoid Manager** / **Helicoid Computer** product.
//!
//! ## Intended consumers
//!
//! The intended native consumers are the Helicoid Manager and Helicoid Computer
//! apps: Swift on macOS (Intel and Apple Silicon) and WinUI 3 / C# on Windows,
//! plus the shared Rust coordination server. Those apps do **not** currently
//! link this Rust crate directly; they consume the versioned development
//! snapshot interchange in [`snapshot`] and the contracts documented here.
//! Native ABI exports are intentionally absent until E03 can prove
//! lifetime/panic/bounds rules.
//!
//! ## What this crate is
//!
//! Pure domain and lifecycle state:
//!
//! - typed bounded identifiers and capability evaluations
//! - inventory inclusion, displayed filters, and temporary action selection
//! - immutable action snapshots and per-target result journal
//! - OS physical-console selection, desktop generations, preview readiness
//! - observation/control lifecycle (several observers, one controller)
//! - focus/minimize/desktop-change/expiry teardown rules
//! - a fail-closed engine-unavailable boundary
//!
//! ## What this crate is not
//!
//! These contracts are **development semantics**. They are **not** signed
//! grants and **not** a cryptographic wire format. This crate does not
//! implement custom cryptography, capture, input injection, networking, or
//! persistence. Media and authentication grant protocols remain unadopted.
//! RustDesk engine adoption is pending — see [`rustdesk_pending`].
//!
//! Engineering proof gates (E01–E08, V01–V51) stay explicit. Deterministic
//! unit tests in this crate verify domain rules only; they are not real
//! platform proof of capture, input, installation, or performance.
//!
//! ## Ownership and independence
//!
//! This crate owns `modules/core/**` only. It has no sibling path dependencies
//! and builds alone with `cargo build` / `cargo test`.
//!
//! ## Quick map
//!
//! | Concern | Module |
//! |---|---|
//! | Identifiers, generations, bounded text | [`id`] |
//! | Numeric bounds | [`bounds`] |
//! | Reason codes | [`reason`] |
//! | Errors | [`error`] |
//! | Capabilities, computer scope, access | [`capability`] |
//! | Inventory / inclusion / selection | [`inventory`] |
//! | Action snapshots and results | [`action`] |
//! | Console selection and engine health | [`console`] |
//! | Observation / control / sharing / teardown | [`interaction`] |
//! | Versioned development snapshot interchange | [`snapshot`] |
//! | Opt-in development fixtures | [`development`] |
//! | Pending engine adoption checklist | [`rustdesk_pending`] |

pub mod action;
pub mod bounds;
pub mod capability;
pub mod console;
pub mod development;
pub mod error;
pub mod id;
pub mod interaction;
pub mod inventory;
pub mod reason;
pub mod rustdesk_pending;
pub mod snapshot;

pub use action::{
    ActionJournal, ActionResultState, ActionSnapshot, ActionSnapshotParts, FreezeAction,
    OperationKind, TargetResult, TimestampMs,
};
pub use capability::{AccessAssignment, CapabilityKind, CapabilityState, ComputerScope};
pub use console::{
    preview_readiness, select_physical_console, CapabilitySnapshot, ComputerRuntime,
    DesktopIdentity, EngineHealth, PreviewReadiness, SessionEligibility,
};
pub use error::{Error, Result};
pub use id::{
    AccountId, ActionId, BootGeneration, BoundedText, ComputerId, DesktopGeneration, DisplayId,
    DisplayName, EnrollmentEpoch, GroupId, InteractionGeneration, InteractionId, LayoutGeneration,
    LocalUserId, ManagerId, MonitoringId, OrganizationId, WorkerGeneration,
};
pub use interaction::{
    plan_teardown, BeginInteraction, ControlDisposition, ControlState, InputRouting, Interaction,
    InteractionKind, InteractionRegistry, InteractionState, MinimizeOutcome,
    MonitoredUserVisibility, ObservationState, ReceiverBranchState, SharingDistribution,
    TeardownPlan, WindowEvent,
};
pub use inventory::{
    CheckboxState, ComputerInventoryEntry, InclusionMode, OverviewPreference, OverviewState,
    Presence, SearchQuery, SortOrder, StatusFilter,
};
pub use reason::ReasonCode;
pub use snapshot::{
    envelope, parse_snapshot_json, to_snapshot_json, ActionResultDoc, ActionSnapshotDoc,
    ComputerStatusSnapshot, InventoryStatusSnapshot, OverviewScopeSnapshot, SnapshotEnvelope,
    SNAPSHOT_SCHEMA_VERSION,
};
