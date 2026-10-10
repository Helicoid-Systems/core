//! Typed capability model.
//!
//! Support, availability, and permission are independent fields (I11-adjacent
//! capability rule). A capability that is supported may still be unavailable
//! (offline, no session) or not permitted for a particular account/computer.
//! Caller-supplied role labels are never authority.

use crate::error::{Error, Result};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

/// A typed operation a caller may attempt on a computer or account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CapabilityKind {
    /// Live view of the current desktop (preview or detail).
    Observe,
    /// Exclusive remote input authority on the current desktop.
    Control,
    /// Capture and distribute this computer's display/window as a share source.
    ShareSource,
    /// Present an incoming share on this computer.
    ShareReceive,
    /// Apply a temporary managed restriction with a plain message.
    Attention,
    /// Send a bounded plain message.
    Message,
    /// Request or resolve help on the current computer.
    Help,
    /// Deliver a scoped file to the intended local user.
    FileSend,
    /// Request files from computer users (collection).
    FileRequest,
    /// Capture a current-desktop screenshot under separate authority.
    Screenshot,
    /// Open an HTTP(S) website in the user's normal browser.
    OpenWebsite,
    /// Launch an approved catalog application.
    LaunchApp,
    /// Execute a typed machine action (wake/lock/logoff/restart/shutdown).
    MachineAction(MachineActionKind),
    /// Tear down an identified interaction without opening its media.
    StopInteraction,
    /// Recover an identified owned interaction or scoped IT interaction.
    RecoverInteraction,
}

/// Typed machine actions. Never an arbitrary shell or privileged executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MachineActionKind {
    /// Wake-on-LAN style wake of an already configured computer.
    Wake,
    /// OS lock that preserves native authentication.
    OsLock,
    /// OS logoff of the console user.
    Logoff,
    /// OS restart.
    Restart,
    /// OS shutdown.
    Shutdown,
}

/// Independent capability evaluation for one operation on one computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityState {
    /// Platform/build supports this operation at all.
    pub supported: bool,
    /// Operation is currently available (online, session ready, not reserved).
    pub available: bool,
    /// The actor holds current permission for this operation and computer.
    pub permitted: bool,
    /// Present when any of the three fields is false.
    pub reason: Option<ReasonCode>,
}

impl CapabilityState {
    /// Fully allowed state.
    pub const ALLOWED: Self = Self {
        supported: true,
        available: true,
        permitted: true,
        reason: None,
    };

    /// Construct an unavailable state with a single named reason.
    pub const fn denied(reason: ReasonCode) -> Self {
        Self {
            supported: false,
            available: false,
            permitted: false,
            reason: Some(reason),
        }
    }

    /// Construct a state that is supported but currently unavailable.
    pub const fn unavailable(reason: ReasonCode) -> Self {
        Self {
            supported: true,
            available: false,
            permitted: false,
            reason: Some(reason),
        }
    }

    /// Construct a state that is supported and available but not permitted.
    pub const fn not_permitted() -> Self {
        Self {
            supported: true,
            available: true,
            permitted: false,
            reason: Some(ReasonCode::PermissionDenied),
        }
    }

    /// True only when all three independent fields hold.
    pub const fn is_allowed(&self) -> bool {
        self.supported && self.available && self.permitted
    }

    /// Convert a non-allowed state into the crate error.
    pub fn check(&self) -> Result<()> {
        if self.is_allowed() {
            Ok(())
        } else {
            Err(Error::Refused {
                reason: self.reason.unwrap_or(ReasonCode::Unavailable),
            })
        }
    }
}

/// Explicit computer scope. Names, groups, and discovery results confer nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputerScope {
    /// No computers.
    None,
    /// Exactly these computer IDs.
    Explicit(Vec<crate::id::ComputerId>),
}

impl ComputerScope {
    /// True when `computer_id` is inside this scope.
    pub fn contains(&self, computer_id: &crate::id::ComputerId) -> bool {
        match self {
            Self::None => false,
            Self::Explicit(ids) => ids.iter().any(|id| id == computer_id),
        }
    }
}

/// Access assignment: what an account may do, on which computers.
///
/// Role names are convenient presets only. The server checks these explicit
/// fields; a caller-supplied role label is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessAssignment {
    /// Account the assignment belongs to.
    pub account_id: crate::id::AccountId,
    /// Deployment the assignment is scoped to.
    pub organization_id: crate::id::OrganizationId,
    /// Capabilities granted.
    pub capabilities: Vec<CapabilityKind>,
    /// Explicit computer IDs in scope.
    pub computer_scope: ComputerScope,
    /// Revision used for optimistic concurrency on updates.
    pub revision: u64,
}

impl AccessAssignment {
    /// True when the assignment covers `capability` on `computer_id`.
    pub fn allows(&self, capability: CapabilityKind, computer_id: &crate::id::ComputerId) -> bool {
        self.computer_scope.contains(computer_id) && self.capabilities.contains(&capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{AccountId, ComputerId, OrganizationId};

    #[test]
    fn allowed_requires_all_three_fields() {
        assert!(CapabilityState::ALLOWED.is_allowed());
        assert!(!CapabilityState::not_permitted().is_allowed());
        assert!(!CapabilityState::unavailable(ReasonCode::OfflineOrTimeout).is_allowed());
        assert!(CapabilityState::not_permitted().check().is_err());
    }

    #[test]
    fn scope_and_capabilities_are_both_required() {
        let c1 = ComputerId::new("c1").unwrap();
        let c2 = ComputerId::new("c2").unwrap();
        let assignment = AccessAssignment {
            account_id: AccountId::new("a1").unwrap(),
            organization_id: OrganizationId::new("org").unwrap(),
            capabilities: vec![CapabilityKind::Observe],
            computer_scope: ComputerScope::Explicit(vec![c1.clone()]),
            revision: 1,
        };
        assert!(assignment.allows(CapabilityKind::Observe, &c1));
        assert!(!assignment.allows(CapabilityKind::Observe, &c2));
        assert!(!assignment.allows(CapabilityKind::Control, &c1));
    }
}
