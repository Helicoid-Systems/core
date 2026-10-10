//! Typed reason codes for every domain refusal or non-live state.
//!
//! Every refusal names a machine-readable reason. Callers map these to plain
//! localized copy and a recovery route; this crate never invents user-facing
//! sentences or leaks privileged paths.

use serde::{Deserialize, Serialize};

/// Why an operation, capability, or lifecycle transition is refused or not live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReasonCode {
    // --- authority / scope ---
    /// Caller is not authenticated.
    AuthenticationRequired,
    /// Caller's authentication or lease has ended.
    AuthenticationExpired,
    /// Authority exists but does not cover this capability.
    PermissionDenied,
    /// Target computer is outside the caller's assigned computer scope.
    ComputerOutOfScope,
    /// Manager identity is pending one-time administrator approval.
    ManagerNotApproved,
    /// Manager identity has been revoked.
    ManagerRevoked,
    /// Interaction is owned by another account/manager.
    InteractionOwnershipConflict,
    /// The expected interaction set changed before the transition committed.
    ConflictChanged,
    /// Operation requires the interaction owner or scoped IT stop authority.
    StopAuthorityRequired,

    // --- identity / enrollment ---
    /// Presented identity does not match the bound peer identity.
    IdentityMismatch,
    /// Enrolled identity is quarantined after competing claims.
    IdentityQuarantined,
    /// Restored identity has not completed recovery reconciliation.
    RecoveryQuarantine,

    // --- desktop / console ---
    /// The previous desktop generation is no longer current.
    DesktopChanged,
    /// No eligible physical/primary console session exists.
    UnsupportedSession,
    /// No user is signed in to the physical console.
    NoUserSignedIn,
    /// Console is at the lock/login/protected desktop.
    LockedOrProtectedDesktop,
    /// OS session facts are mid-transition or ambiguous.
    SessionChanging,
    /// Capture/screen permission is missing for the current desktop.
    CapturePermissionMissing,
    /// Input permission is missing for the current desktop.
    InputPermissionMissing,
    /// Primary display is unavailable for the current layout generation.
    PrimaryDisplayUnavailable,

    // --- lifetime ---
    /// Authority lease or action deadline has ended.
    Expired,
    /// Request was already applied or is a replay of a completed request.
    Replayed,
    /// Interaction is mid-release and cannot be reused or restarted.
    PendingRelease,
    /// Late callback/frame/ack belongs to a stopped or fenced generation.
    LateGeneration,

    // --- capability / policy ---
    /// The operation is not supported on this platform or build.
    Unsupported,
    /// Capability is supported but not currently available (offline, no session).
    Unavailable,
    /// Target set is empty after filtering; dispatch is disabled.
    ZeroTargets,
    /// Input value failed typed validation (empty, oversized, illegal characters).
    InvalidInput,
    /// Bounded quota or capacity would be exceeded.
    QuotaReached,
    /// A conflicting exclusive interaction occupies the computer.
    InUse,
    /// A machine-action reservation blocks new desktop claims.
    MachineActionPending,

    // --- engine / transport ---
    /// Engine cannot enforce required admission boundaries; fail closed.
    EngineUnavailable,
    /// Required durable commit failed; no new authority or side effects.
    NotSaved,
    /// Target is offline or the request timed out before execution.
    OfflineOrTimeout,
    /// Side effect may have occurred but durable acknowledgment is missing.
    OutcomeUnknown,
    /// Protocol or ABI version is incompatible.
    IncompatibleVersion,
}

impl ReasonCode {
    /// Stable machine string for logs, snapshots, and protocol mapping.
    ///
    /// Transport enum values are an E03 deliverable; this mapping is the
    /// domain-local stable name, not a frozen wire constant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::AuthenticationExpired => "authentication_expired",
            Self::PermissionDenied => "permission_denied",
            Self::ComputerOutOfScope => "computer_out_of_scope",
            Self::ManagerNotApproved => "manager_not_approved",
            Self::ManagerRevoked => "manager_revoked",
            Self::InteractionOwnershipConflict => "interaction_ownership_conflict",
            Self::ConflictChanged => "conflict_changed",
            Self::StopAuthorityRequired => "stop_authority_required",
            Self::IdentityMismatch => "identity_mismatch",
            Self::IdentityQuarantined => "identity_quarantined",
            Self::RecoveryQuarantine => "recovery_quarantine",
            Self::DesktopChanged => "desktop_changed",
            Self::UnsupportedSession => "unsupported_session",
            Self::NoUserSignedIn => "no_user_signed_in",
            Self::LockedOrProtectedDesktop => "locked_or_protected_desktop",
            Self::SessionChanging => "session_changing",
            Self::CapturePermissionMissing => "capture_permission_missing",
            Self::InputPermissionMissing => "input_permission_missing",
            Self::PrimaryDisplayUnavailable => "primary_display_unavailable",
            Self::Expired => "expired",
            Self::Replayed => "replayed",
            Self::PendingRelease => "pending_release",
            Self::LateGeneration => "late_generation",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::ZeroTargets => "zero_targets",
            Self::InvalidInput => "invalid_input",
            Self::QuotaReached => "quota_reached",
            Self::InUse => "in_use",
            Self::MachineActionPending => "machine_action_pending",
            Self::EngineUnavailable => "engine_unavailable",
            Self::NotSaved => "not_saved",
            Self::OfflineOrTimeout => "offline_or_timeout",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::IncompatibleVersion => "incompatible_version",
        }
    }
}

impl core::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
