//! Pending RustDesk adoption feasibility tasks.
//!
//! Real RustDesk adoption is **not done**. This module records the pinned
//! upstream feasibility work that must complete before E01 can adopt an
//! engine. Nothing here is a built integration, an ABI, or a launch path.
//!
//! Research snapshot (inspected 9 October 2026, not an adopted pin):
//! `rustdesk/rustdesk` commit `001b0e96173cea4e49f9f7a67bea95a177dd1de3`.
//! Later implementation must repeat the critical review against its chosen
//! revision.
//!
//! The product constraints this checklist exists to protect:
//!
//! - No unrestricted generic RustDesk launch (E01 / build-map B02).
//! - No fictional remote ABI; the C header is an E03 deliverable.
//! - An engine that cannot enforce I01, I03, I05, I09, or I16 at every
//!   admission path fails adoption.
//! - An unrestricted upstream listener behind a native UI is not a valid
//!   implementation.

use serde::{Deserialize, Serialize};

/// One pending feasibility task. Status is always [`FeasibilityStatus::Pending`]
/// until a separate evidence record says otherwise; this crate never marks
/// them done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeasibilityTask {
    /// Stable task identifier matching the integration plan.
    pub id: &'static str,
    /// What must be proved.
    pub required_output: &'static str,
    /// Current status in this crate.
    pub status: FeasibilityStatus,
}

/// Status of a feasibility task. This crate only records Pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeasibilityStatus {
    /// Not yet proved. Blocks dependent implementation.
    Pending,
}

/// Pinned upstream feasibility checklist. All entries are Pending.
///
/// Do not treat this list as completed work. It exists so integrators have one
/// honest place that refuses to pretend the engine is adopted.
pub const PENDING_RUSTDESK_FEASIBILITY: &[FeasibilityTask] = &[
    FeasibilityTask {
        id: "RD01",
        required_output:
            "Pinned upstream revision builds a native library with no required Flutter/Sciter runtime",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD02",
        required_output:
            "Actual header/lifetime rules for any product-owned native bridge; no fictional ABI",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD03",
        required_output:
            "Authenticated route and endpoint authority; no raw-IP listener or insecure fallback",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD04",
        required_output:
            "Real native observation proof on admitted physical-console desktops",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD05",
        required_output:
            "Explicit unique control with held-input release and teardown evidence",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD06",
        required_output:
            "Mixed media/encode fan-out bounds and receiver admission results",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD07",
        required_output: "Platform/load matrix on both Mac architectures and Windows",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD08",
        required_output: "Private hosting/relay quotas and non-bypassable admission",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD09",
        required_output:
            "Adoption decision with license inventory and redistribution obligations",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD10",
        required_output: "Capture/input/attention permission behavior under D26/D27",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD11",
        required_output: "Security review of every admission path (I01/I03/I05/I09/I16)",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD12",
        required_output: "Maintenance/upstream-sync plan for the chosen fork strategy",
        status: FeasibilityStatus::Pending,
    },
];

/// True when every recorded feasibility task is still Pending.
pub fn engine_adoption_is_pending() -> bool {
    PENDING_RUSTDESK_FEASIBILITY
        .iter()
        .all(|t| t.status == FeasibilityStatus::Pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_is_honestly_pending() {
        assert!(engine_adoption_is_pending());
        assert_eq!(PENDING_RUSTDESK_FEASIBILITY.len(), 12);
    }
}
