//! Pending native engine adoption requirements.
//!
//! Google WebRTC is the selected transport route. E01 remains pending until
//! the product bridge, server-issued admission, endpoint enforcement, actual
//! capture/media, and platform evidence pass together. The historical
//! RustDesk feasibility work is not the selected route. Nothing here is a
//! production integration or a launch path.
//!
//! The product constraints this checklist exists to protect:
//!
//! - No arbitrary generic transport launch or insecure fallback.
//! - No fictional remote ABI; native headers and wrappers must match exports.
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
pub const PENDING_ENGINE_ADOPTION: &[FeasibilityTask] = &[
    FeasibilityTask {
        id: "RD01",
        required_output:
            "Pinned WebRTC source and toolchain build the native bridge without product UI runtimes",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD02",
        required_output:
            "Generated native ABI, bounded inputs, owned frames, and asynchronous close/drain lifetime",
        status: FeasibilityStatus::Pending,
    },
    FeasibilityTask {
        id: "RD03",
        required_output:
            "Server-issued authority is bound to the verified peer channel and enforced by the endpoint",
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
    PENDING_ENGINE_ADOPTION
        .iter()
        .all(|t| t.status == FeasibilityStatus::Pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_engine_adoption_is_honestly_pending() {
        assert!(engine_adoption_is_pending());
        assert_eq!(PENDING_ENGINE_ADOPTION.len(), 12);
    }
}
