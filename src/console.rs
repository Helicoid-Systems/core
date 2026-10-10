//! OS physical-console selection, desktop generations, and capability state.
//!
//! D26: version 1 monitors only the desktop on the computer's own screen. The
//! selected session is the signed-in physical/primary console. RDP, background,
//! and separate virtual user sessions are unsupported and never substitute.
//!
//! A session number is not reusable authority: user, lock, attachment, boot, or
//! worker changes invalidate the old generation. Selection, user, lock state,
//! boot, or worker replacement invalidates old authority before capture/input
//! on a replacement. A safe return can regain view-only after fresh admission,
//! never control.
//!
//! D25: overview previews use the endpoint-reported primary display of the
//! current desktop/layout generation. Missing/unavailable primary display
//! produces a named readiness state; never silently substitute another display.

use crate::capability::{CapabilityKind, CapabilityState};
use crate::error::{Error, Result};
use crate::id::{
    BootGeneration, ComputerId, DesktopGeneration, DisplayId, LayoutGeneration, LocalUserId,
    WorkerGeneration,
};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

/// Why a console session is or is not eligible for monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionEligibility {
    /// Exactly the physical/primary console user, unlocked.
    Eligible,
    /// No user is signed in to the physical console.
    NoUserSignedIn,
    /// Console is locked or at a protected/login desktop.
    LockedOrProtectedDesktop,
    /// Session attachment is transitioning or OS facts are ambiguous.
    SessionChanging,
    /// Only RDP/background/virtual sessions exist, or the session type is unsupported.
    UnsupportedSession,
    /// Trusted local session resolver cannot currently decide.
    Ambiguous,
}

impl SessionEligibility {
    /// True when this eligibility admits independently permitted capture/input.
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }

    /// Reason code that describes a non-eligible state.
    pub const fn reason(self) -> Option<ReasonCode> {
        match self {
            Self::Eligible => None,
            Self::NoUserSignedIn => Some(ReasonCode::NoUserSignedIn),
            Self::LockedOrProtectedDesktop => Some(ReasonCode::LockedOrProtectedDesktop),
            Self::SessionChanging => Some(ReasonCode::SessionChanging),
            Self::UnsupportedSession => Some(ReasonCode::UnsupportedSession),
            Self::Ambiguous => Some(ReasonCode::UnsupportedSession),
        }
    }
}

/// The selected physical-console desktop of one computer.
///
/// `os_session_ref` is diagnostic only. Authority binds to the generation
/// triple, never to the session number alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIdentity {
    /// Computer the desktop belongs to.
    pub computer_id: ComputerId,
    /// Diagnostic OS session number. Not authority.
    pub os_session_ref: u32,
    /// Trusted local OS user on this desktop, when resolved.
    pub local_user: Option<LocalUserId>,
    /// Invalidated by desktop replacement, lock/user change, or worker restart.
    pub desktop_generation: DesktopGeneration,
    /// Invalidated by OS reboot.
    pub boot_generation: BootGeneration,
    /// Invalidated by monitored-worker process replacement.
    pub worker_generation: WorkerGeneration,
    /// Primary display of the current layout generation, when available.
    pub primary_display: Option<DisplayId>,
    /// Layout/primary-display mapping generation.
    pub layout_generation: LayoutGeneration,
    /// Why this desktop is or is not eligible.
    pub eligibility: SessionEligibility,
}

impl DesktopIdentity {
    /// True when two identities refer to the same admitted desktop authority.
    ///
    /// Equal generation triples mean the same authority; a reused OS session
    /// number with any generation change is a different desktop.
    pub fn same_authority(&self, other: &Self) -> bool {
        self.computer_id == other.computer_id
            && self.desktop_generation == other.desktop_generation
            && self.boot_generation == other.boot_generation
            && self.worker_generation == other.worker_generation
    }
}

/// Per-operation capability snapshot for one desktop, with independent fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// Desktop the snapshot describes.
    pub desktop: DesktopIdentity,
    /// Capability evaluations keyed by kind.
    pub states: Vec<(CapabilityKind, CapabilityState)>,
}

impl CapabilitySnapshot {
    /// Evaluate one capability kind.
    pub fn state_for(&self, kind: CapabilityKind) -> Option<CapabilityState> {
        self.states
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, s)| *s)
    }
}

/// Fail-closed readiness of the local engine that must enforce admission
/// boundaries (I01, I03, I05, I09, I16).
///
/// An engine that cannot enforce those invariants at every admission path is
/// unavailable: no new authority, media, or effects. Teardown and independent
/// safety cleanup remain available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineHealth {
    /// Engine can enforce required admission boundaries.
    Healthy,
    /// Engine cannot enforce them. Fail closed for new authority/effects.
    Unavailable {
        /// Why the engine is unavailable.
        reason: ReasonCode,
        /// When unavailability was latched.
        since: crate::action::TimestampMs,
    },
}

impl EngineHealth {
    /// True when new authority and effects may be issued.
    pub const fn admits_new_work(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Per-computer runtime tracker for console state and engine health.
///
/// Callers feed observed OS facts; this type enforces generation fencing and
/// the fail-closed engine boundary. It does not perform capture, input, crypto,
/// or networking — those remain platform/engine responsibilities under E01/E04.
#[derive(Debug, Clone)]
pub struct ComputerRuntime {
    computer_id: ComputerId,
    desktop: Option<DesktopIdentity>,
    engine: EngineHealth,
    /// Pending machine-action reservation blocking new desktop claims.
    machine_action_reserved: bool,
}

impl ComputerRuntime {
    /// Create runtime for one computer with a healthy engine and no desktop.
    pub fn new(computer_id: ComputerId) -> Self {
        Self {
            computer_id,
            desktop: None,
            engine: EngineHealth::Healthy,
            machine_action_reserved: false,
        }
    }

    /// Computer identity this runtime tracks.
    pub const fn computer_id(&self) -> &ComputerId {
        &self.computer_id
    }

    /// Current desktop identity, if any is selected.
    pub const fn desktop(&self) -> Option<&DesktopIdentity> {
        self.desktop.as_ref()
    }

    /// Current engine health.
    pub const fn engine_health(&self) -> &EngineHealth {
        &self.engine
    }

    /// True when new authority/effects are currently admitted.
    pub fn admits_new_work(&self) -> bool {
        self.engine.admits_new_work() && !self.machine_action_reserved
    }

    /// Latch the engine unavailable. Idempotent; earliest `since` wins.
    pub fn set_engine_unavailable(
        &mut self,
        reason: ReasonCode,
        since: crate::action::TimestampMs,
    ) {
        if let EngineHealth::Unavailable {
            since: existing, ..
        } = self.engine
        {
            if existing.0 <= since.0 {
                return;
            }
        }
        self.engine = EngineHealth::Unavailable { reason, since };
    }

    /// Mark the engine healthy again after scoped repair and a real durable
    /// probe. Callers must have completed integrity/checkpoint reconciliation
    /// before calling this; a freed disk alone is not enough.
    pub fn set_engine_healthy(&mut self) {
        self.engine = EngineHealth::Healthy;
    }

    /// Install a newly selected desktop identity.
    ///
    /// If the previous identity is not the same authority, the old desktop is
    /// considered invalidated and callers must tear down observation/control
    /// and release input before admitting the replacement. Returns the
    /// invalidation reason when the previous desktop is no longer current.
    pub fn set_desktop(&mut self, desktop: DesktopIdentity) -> Option<ReasonCode> {
        if desktop.computer_id != self.computer_id {
            // Caller bug: refuse to install a foreign desktop.
            return Some(ReasonCode::IdentityMismatch);
        }
        let invalidated = match &self.desktop {
            None => None,
            Some(prev) if prev.same_authority(&desktop) => None,
            Some(_) => Some(ReasonCode::DesktopChanged),
        };
        self.desktop = Some(desktop);
        invalidated
    }

    /// Clear the current desktop (logout, lock, session change, worker loss).
    /// Returns the cleared identity so callers can tear down bound work.
    pub fn clear_desktop(&mut self) -> Option<DesktopIdentity> {
        self.desktop.take()
    }

    /// Reserve a machine-action slot on this computer. Refuses when a
    /// reservation already exists or the engine is unavailable.
    pub fn reserve_machine_action(&mut self) -> Result<()> {
        self.ensure_new_work()?;
        if self.machine_action_reserved {
            return Err(Error::refused(ReasonCode::MachineActionPending));
        }
        self.machine_action_reserved = true;
        Ok(())
    }

    /// Clear the machine-action reservation after a reconciled terminal result
    /// or expiry. Unknown outcome never clears it automatically.
    pub fn clear_machine_action_reservation(&mut self) {
        self.machine_action_reserved = false;
    }

    /// True when a machine-action reservation blocks new desktop claims.
    pub const fn machine_action_reserved(&self) -> bool {
        self.machine_action_reserved
    }

    /// Gate: refuse new authority/effects when the engine is unavailable or a
    /// machine-action reservation is held. Teardown paths must not call this.
    pub fn ensure_new_work(&self) -> Result<()> {
        match &self.engine {
            EngineHealth::Unavailable { reason, .. } => Err(Error::engine_unavailable(*reason)),
            EngineHealth::Healthy => {
                if self.machine_action_reserved {
                    Err(Error::refused(ReasonCode::MachineActionPending))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// True when `desktop` is still the current admitted authority.
    pub fn desktop_is_current(&self, desktop: &DesktopIdentity) -> bool {
        match &self.desktop {
            Some(current) => current.same_authority(desktop),
            None => false,
        }
    }
}

/// Resolve the single eligible physical/primary console desktop from observed
/// OS facts (D26). Never falls back to another signed-in user.
///
/// Callers supply the independently validated local session resolver output;
/// this function only applies the deterministic selection rules. Session 0,
/// login windows, and protected desktops are not ordinary user desktops.
pub fn select_physical_console(
    computer_id: ComputerId,
    candidates: &[DesktopIdentity],
) -> Result<DesktopIdentity> {
    let mut eligible: Vec<&DesktopIdentity> = candidates
        .iter()
        .filter(|d| {
            d.computer_id == computer_id && d.eligibility.is_eligible() && d.os_session_ref != 0
        })
        .collect();

    if eligible.is_empty() {
        // Prefer the most specific named reason from the candidates.
        let reason = candidates
            .iter()
            .find_map(|d| d.eligibility.reason())
            .unwrap_or(ReasonCode::UnsupportedSession);
        return Err(Error::refused(reason));
    }

    if eligible.len() > 1 {
        // Ambiguous OS facts: refuse rather than pick a first-Active session.
        return Err(Error::refused(ReasonCode::UnsupportedSession));
    }

    let chosen = eligible.remove(0).clone();
    if chosen.primary_display.is_none() {
        // Eligible user desktop, but overview previews need a primary display.
        // Callers surface PrimaryDisplayUnavailable as a readiness state.
        return Ok(chosen);
    }
    Ok(chosen)
}

/// Named readiness for overview previews under D25.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreviewReadiness {
    /// Primary display is current and authorized source admission is required
    /// before the first frame (I01). This state does not mean pixels exist.
    ReadyForAdmission {
        /// Display that must be admitted.
        display_id: DisplayId,
        /// Layout generation the mapping belongs to.
        layout_generation: LayoutGeneration,
    },
    /// No eligible console user.
    NoUserSignedIn,
    /// Console is locked/protected.
    Locked,
    /// Session transition or ambiguous OS facts.
    SessionChanging,
    /// Unsupported session type (RDP-only, background, virtual).
    UnsupportedSession,
    /// Primary display is missing or unavailable for this layout generation.
    /// Never silently substitutes another display.
    PrimaryDisplayUnavailable,
    /// Engine cannot enforce admission; no preview demand is created.
    EngineUnavailable,
}

/// Compute overview preview readiness from a desktop identity.
pub fn preview_readiness(desktop: &DesktopIdentity, engine: &EngineHealth) -> PreviewReadiness {
    if !engine.admits_new_work() {
        return PreviewReadiness::EngineUnavailable;
    }
    if !desktop.eligibility.is_eligible() {
        return match desktop.eligibility {
            SessionEligibility::NoUserSignedIn => PreviewReadiness::NoUserSignedIn,
            SessionEligibility::LockedOrProtectedDesktop => PreviewReadiness::Locked,
            SessionEligibility::SessionChanging | SessionEligibility::Ambiguous => {
                PreviewReadiness::SessionChanging
            }
            SessionEligibility::UnsupportedSession => PreviewReadiness::UnsupportedSession,
            SessionEligibility::Eligible => PreviewReadiness::PrimaryDisplayUnavailable,
        };
    }
    match (&desktop.primary_display, desktop.eligibility) {
        (Some(display_id), SessionEligibility::Eligible) => PreviewReadiness::ReadyForAdmission {
            display_id: display_id.clone(),
            layout_generation: desktop.layout_generation,
        },
        (None, _) => PreviewReadiness::PrimaryDisplayUnavailable,
        _ => PreviewReadiness::UnsupportedSession,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desktop(id: &str, gen: u64, eligibility: SessionEligibility) -> DesktopIdentity {
        DesktopIdentity {
            computer_id: ComputerId::new(id).unwrap(),
            os_session_ref: 1,
            local_user: None,
            desktop_generation: DesktopGeneration(gen),
            boot_generation: BootGeneration(1),
            worker_generation: WorkerGeneration(1),
            primary_display: Some(DisplayId::new("disp-1").unwrap()),
            layout_generation: LayoutGeneration(1),
            eligibility,
        }
    }

    #[test]
    fn reused_session_number_is_not_authority() {
        let a = desktop("c1", 1, SessionEligibility::Eligible);
        let mut b = a.clone();
        b.desktop_generation = DesktopGeneration(2);
        assert!(!a.same_authority(&b));
    }

    #[test]
    fn select_physical_console_never_falls_back() {
        let computer = ComputerId::new("c1").unwrap();
        let rdp_only = DesktopIdentity {
            eligibility: SessionEligibility::UnsupportedSession,
            ..desktop("c1", 1, SessionEligibility::Eligible)
        };
        assert!(select_physical_console(computer.clone(), &[rdp_only]).is_err());

        let mut both = vec![
            desktop("c1", 1, SessionEligibility::Eligible),
            DesktopIdentity {
                os_session_ref: 2,
                eligibility: SessionEligibility::Eligible,
                ..desktop("c1", 1, SessionEligibility::Eligible)
            },
        ];
        both[1].desktop_generation = DesktopGeneration(2);
        assert!(
            select_physical_console(computer.clone(), &both).is_err(),
            "ambiguous multi-session facts refuse rather than pick first-Active"
        );

        let ok =
            select_physical_console(computer, &[desktop("c1", 1, SessionEligibility::Eligible)])
                .unwrap();
        assert_eq!(ok.desktop_generation, DesktopGeneration(1));
    }

    #[test]
    fn engine_unavailable_fails_closed_for_new_work_but_not_teardown() {
        let mut rt = ComputerRuntime::new(ComputerId::new("c1").unwrap());
        assert!(rt.ensure_new_work().is_ok());
        rt.set_engine_unavailable(ReasonCode::NotSaved, crate::action::TimestampMs::new(5));
        assert!(rt.ensure_new_work().is_err());
        // Teardown never calls ensure_new_work; clear_desktop still works.
        assert!(rt.clear_desktop().is_none());
    }

    #[test]
    fn desktop_invalidation_reports_reason() {
        let mut rt = ComputerRuntime::new(ComputerId::new("c1").unwrap());
        assert_eq!(
            rt.set_desktop(desktop("c1", 1, SessionEligibility::Eligible)),
            None
        );
        assert_eq!(
            rt.set_desktop(desktop("c1", 2, SessionEligibility::Eligible)),
            Some(ReasonCode::DesktopChanged)
        );
    }

    #[test]
    fn machine_action_reservation_blocks_new_claims() {
        let mut rt = ComputerRuntime::new(ComputerId::new("c1").unwrap());
        rt.reserve_machine_action().unwrap();
        assert!(rt.reserve_machine_action().is_err());
        assert!(rt.ensure_new_work().is_err());
        rt.clear_machine_action_reservation();
        assert!(rt.ensure_new_work().is_ok());
    }

    #[test]
    fn preview_never_substitutes_a_missing_primary_display() {
        let mut d = desktop("c1", 1, SessionEligibility::Eligible);
        d.primary_display = None;
        assert_eq!(
            preview_readiness(&d, &EngineHealth::Healthy),
            PreviewReadiness::PrimaryDisplayUnavailable
        );
    }
}
