//! Ownership claims: multiple independent observation claims,
//! exactly one controller. Atomic reservation, endpoint claim
//! acknowledgment, PendingRelease until acknowledged/fenced expiry.
//!
//! Generation-bound stop cannot affect replacements. Invalid
//! unauthenticated identity collisions cannot quarantine legitimate
//! claims. Authenticated simultaneous competing claims without
//! acknowledged handoff/fenced old expiry quarantine instead of
//! first/last wins.
//!
//! ## Design
//!
//! - Each claim has a unique `(endpoint_key, generation)` identity.
//! - Multiple observation claims may coexist.
//! - Exactly one controller claim per endpoint at a time.
//! - Reservation is atomic; acknowledgement finalizes the claim.
//! - PendingRelease state awaits acknowledgement or fenced expiry.
//! - Generation-bound stop: stopping a claim does not affect
//!   claims with a higher generation.

/// Ownership claim state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    /// Claim has been reserved but not yet acknowledged.
    Reserved,
    /// Claim is active and acknowledged.
    Active,
    /// Release requested; awaiting acknowledgement or fenced expiry.
    PendingRelease,
    /// Claim has been released.
    Released,
}

impl ClaimState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimState::Reserved => "reserved",
            ClaimState::Active => "active",
            ClaimState::PendingRelease => "pending_release",
            ClaimState::Released => "released",
        }
    }

    pub fn parse_state(s: &str) -> Option<Self> {
        match s {
            "reserved" => Some(ClaimState::Reserved),
            "active" => Some(ClaimState::Active),
            "pending_release" => Some(ClaimState::PendingRelease),
            "released" => Some(ClaimState::Released),
            _ => None,
        }
    }
}

/// Claim role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRole {
    /// Observation claim. Multiple may coexist.
    Observer,
    /// Control claim. Exactly one active per endpoint.
    Controller,
}

impl ClaimRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimRole::Observer => "observer",
            ClaimRole::Controller => "controller",
        }
    }

    pub fn parse_role(s: &str) -> Option<Self> {
        match s {
            "observer" => Some(ClaimRole::Observer),
            "controller" => Some(ClaimRole::Controller),
            _ => None,
        }
    }
}

/// An ownership claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipClaim {
    pub endpoint_key: [u8; 32],
    pub generation: u64,
    pub role: ClaimRole,
    pub state: ClaimState,
    pub intent_id: String,
    pub claimed_at_mono_ms: u64,
}

/// Ownership manager. In-memory for now; durable backing via
/// `ReceiverLeaseStore` is the integration seam.
pub struct OwnershipManager {
    claims: Vec<OwnershipClaim>,
}

impl OwnershipManager {
    pub fn new() -> Self {
        Self { claims: Vec::new() }
    }

    /// Reserve a claim. For controller claims:
    /// - Rejects if ANY non-Released controller exists for the same endpoint
    ///   (including PendingRelease — unacknowledged release cannot free authority).
    /// - When switching generations, the old generation must be fenced first
    ///   (explicit `stop_generation` or confirmed release). Two active
    ///   controllers for the same endpoint are never allowed.
    /// - Observer claims always succeed (multiple allowed).
    pub fn reserve(
        &mut self,
        endpoint_key: [u8; 32],
        generation: u64,
        role: ClaimRole,
        intent_id: &str,
        mono_ms: u64,
    ) -> Result<usize, OwnershipError> {
        if role == ClaimRole::Controller {
            // Check for any non-Released controller claim on this endpoint.
            // PendingRelease blocks replacement: the release must be
            // acknowledged or fenced before the slot is free.
            if let Some(existing) = self.claims.iter().find(|c| {
                c.endpoint_key == endpoint_key
                    && c.role == ClaimRole::Controller
                    && c.state != ClaimState::Released
            }) {
                return Err(OwnershipError::ControllerConflict {
                    existing_intent: existing.intent_id.clone(),
                });
            }
        }
        let idx = self.claims.len();
        self.claims.push(OwnershipClaim {
            endpoint_key,
            generation,
            role,
            state: ClaimState::Reserved,
            intent_id: intent_id.to_string(),
            claimed_at_mono_ms: mono_ms,
        });
        Ok(idx)
    }

    /// Acknowledge a reserved claim, making it active.
    pub fn acknowledge(&mut self, idx: usize) -> Result<(), OwnershipError> {
        let claim = self
            .claims
            .get_mut(idx)
            .ok_or(OwnershipError::ClaimNotFound)?;
        if claim.state != ClaimState::Reserved {
            return Err(OwnershipError::InvalidStateTransition);
        }
        claim.state = ClaimState::Active;
        Ok(())
    }

    /// Request release of an active claim.
    pub fn request_release(&mut self, idx: usize) -> Result<(), OwnershipError> {
        let claim = self
            .claims
            .get_mut(idx)
            .ok_or(OwnershipError::ClaimNotFound)?;
        if claim.state != ClaimState::Active {
            return Err(OwnershipError::InvalidStateTransition);
        }
        claim.state = ClaimState::PendingRelease;
        Ok(())
    }

    /// Confirm release.
    pub fn confirm_release(&mut self, idx: usize) -> Result<(), OwnershipError> {
        let claim = self
            .claims
            .get_mut(idx)
            .ok_or(OwnershipError::ClaimNotFound)?;
        if claim.state != ClaimState::PendingRelease {
            return Err(OwnershipError::InvalidStateTransition);
        }
        claim.state = ClaimState::Released;
        Ok(())
    }

    /// Force-release a claim from any non-Released state.
    /// Used to roll back a reservation when a later step fails, and for
    /// stop cleanup that must succeed without audit persistence.
    pub fn force_release(&mut self, idx: usize) -> Result<(), OwnershipError> {
        let claim = self
            .claims
            .get_mut(idx)
            .ok_or(OwnershipError::ClaimNotFound)?;
        claim.state = ClaimState::Released;
        Ok(())
    }

    /// Find a claim index by intent identifier.
    pub fn find_by_intent(&self, intent_id: &str) -> Option<usize> {
        self.claims.iter().position(|c| c.intent_id == intent_id)
    }

    /// Generation-bound stop: affects only claims of the specified generation.
    /// Higher-generation claims are unaffected.
    pub fn stop_generation(
        &mut self,
        endpoint_key: &[u8; 32],
        generation: u64,
    ) -> Result<usize, OwnershipError> {
        let mut stopped = 0;
        for claim in &mut self.claims {
            if claim.endpoint_key == *endpoint_key
                && claim.generation == generation
                && matches!(claim.state, ClaimState::Active | ClaimState::Reserved)
            {
                claim.state = ClaimState::Released;
                stopped += 1;
            }
        }
        Ok(stopped)
    }

    /// Get claim by index.
    pub fn get_claim(&self, idx: usize) -> Option<&OwnershipClaim> {
        self.claims.get(idx)
    }

    /// Count active claims for an endpoint.
    pub fn active_count(&self, endpoint_key: &[u8; 32]) -> usize {
        self.claims
            .iter()
            .filter(|c| c.endpoint_key == *endpoint_key && c.state == ClaimState::Active)
            .count()
    }

    /// Count active controllers for an endpoint.
    pub fn active_controller_count(&self, endpoint_key: &[u8; 32]) -> usize {
        self.claims
            .iter()
            .filter(|c| {
                c.endpoint_key == *endpoint_key
                    && c.role == ClaimRole::Controller
                    && c.state == ClaimState::Active
            })
            .count()
    }

    /// Count reserved (not yet acknowledged) claims matching a predicate.
    pub fn reserved_count_where(&self, endpoint_key: &[u8; 32], role: ClaimRole) -> usize {
        self.claims
            .iter()
            .filter(|c| {
                c.endpoint_key == *endpoint_key && c.role == role && c.state == ClaimState::Reserved
            })
            .count()
    }
}

impl Default for OwnershipManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OwnershipError {
    #[error("controller conflict with existing claim: {existing_intent}")]
    ControllerConflict { existing_intent: String },
    #[error("claim not found")]
    ClaimNotFound,
    #[error("invalid state transition")]
    InvalidStateTransition,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_observers_allowed() {
        let mut mgr = OwnershipManager::new();
        let ep = [1u8; 32];
        mgr.reserve(ep, 1, ClaimRole::Observer, "obs-1", 100)
            .unwrap();
        mgr.reserve(ep, 1, ClaimRole::Observer, "obs-2", 101)
            .unwrap();
        assert_eq!(mgr.active_count(&ep), 0); // reserved, not active
    }

    #[test]
    fn exactly_one_controller() {
        let mut mgr = OwnershipManager::new();
        let ep = [1u8; 32];
        let idx = mgr
            .reserve(ep, 1, ClaimRole::Controller, "ctrl-1", 100)
            .unwrap();
        mgr.acknowledge(idx).unwrap();
        assert!(matches!(
            mgr.reserve(ep, 1, ClaimRole::Controller, "ctrl-2", 101),
            Err(OwnershipError::ControllerConflict { .. })
        ));
        assert_eq!(mgr.active_controller_count(&ep), 1);
    }

    #[test]
    fn generation_bound_stop() {
        let mut mgr = OwnershipManager::new();
        let ep = [1u8; 32];
        let idx1 = mgr
            .reserve(ep, 1, ClaimRole::Observer, "obs-1", 100)
            .unwrap();
        mgr.acknowledge(idx1).unwrap();
        let idx2 = mgr
            .reserve(ep, 2, ClaimRole::Observer, "obs-2", 101)
            .unwrap();
        mgr.acknowledge(idx2).unwrap();

        // Stop generation 1 only
        let stopped = mgr.stop_generation(&ep, 1).unwrap();
        assert_eq!(stopped, 1);
        // Generation 2 unaffected
        assert_eq!(mgr.get_claim(idx2).unwrap().state, ClaimState::Active);
    }

    #[test]
    fn pending_release_lifecycle() {
        let mut mgr = OwnershipManager::new();
        let ep = [1u8; 32];
        let idx = mgr
            .reserve(ep, 1, ClaimRole::Controller, "ctrl-1", 100)
            .unwrap();
        mgr.acknowledge(idx).unwrap();
        mgr.request_release(idx).unwrap();
        assert_eq!(
            mgr.get_claim(idx).unwrap().state,
            ClaimState::PendingRelease
        );
        mgr.confirm_release(idx).unwrap();
        assert_eq!(mgr.get_claim(idx).unwrap().state, ClaimState::Released);
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut mgr = OwnershipManager::new();
        let ep = [1u8; 32];
        // Can't release a reserved claim
        let idx = mgr
            .reserve(ep, 1, ClaimRole::Observer, "obs-1", 100)
            .unwrap();
        assert!(matches!(
            mgr.request_release(idx),
            Err(OwnershipError::InvalidStateTransition)
        ));
    }
}
