//! # authority-lab
//!
//! Bounded cryptographic admission proof — development candidate only.
//!
//! This crate proves a candidate peer admission contract using Ed25519
//! strict signatures over a canonical, domain-separated representation.
//! It is transport-independent and does not open network listeners, mint
//! real enrolled authority, or use user keys.
//!
//! ## Scope
//!
//! - Typed checked IDs (deployment, computer, incarnation, account, manager)
//! - Action scope: Observe never implies Control; StopOnly has no pixels
//! - Single immutable persisted authority binding (explicit init)
//! - Durable commit seam before returning signed bytes
//! - Atomic receiver nonce consumption with hard capacity
//! - Honest validity-clock names; fail-closed clock faults
//! - Storage IO faults latch the gate closed (no recovery API)
//!
//! ## Not in scope
//!
//! - Production callers (B03 not passed; production closed)
//! - Network transport or listeners; peer possession proof
//! - Media, file, or UI/admin automatic scope expansion
//! - MFA or identity friendly names as keys
//! - Real enrolled authority or user keys
//! - Independent approval / authority-cutover mechanism (unavailable)

pub mod admission;
pub mod canonical;
pub mod grant;
pub mod keys;
pub mod store;
pub mod types;

pub use admission::{
    AdmissionController, AdmissionDecision, ClockError, DenyReason, IssueError, IssuedGrant,
    ManualEpochClock, MonotonicLeaseClock, SystemEpochClock, ValidityClock,
    MAX_CANDIDATE_LIFETIME_MS,
};
pub use canonical::{CanonicalFields, MAX_CANONICAL_BODY, SCHEMA_VERSION};
pub use grant::{ExpectedAuthority, Grant, GrantError};
pub use keys::{random_32, IssuerSigningKey, IssuerVerifyingKey};
pub use store::{
    DurableStore, IssuedCredential, StoreError, StoreLimits, TrustBinding, DEFAULT_MAX_CLAIMED,
    DEFAULT_MAX_ISSUED, STORE_FORMAT_VERSION,
};
pub use types::*;
