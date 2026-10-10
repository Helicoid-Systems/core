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
//! - Network transport or listeners; distributed admission
//! - Media, file, or UI/admin automatic scope expansion
//! - MFA or identity friendly names as keys
//! - Real enrolled authority or user keys
//! - Independent approval / authority-cutover mechanism (unavailable)
//! - Real authenticated channel proof (channel binding is fixture input)

pub mod admission;
pub mod admission_v2;
pub mod canonical;
pub mod canonical_v2;
pub mod grant;
pub mod issuer_store;
pub mod keys;
pub mod ownership;
pub mod peer;
pub mod receiver_store;
pub mod store;
pub mod types;

pub use admission::{
    AdmissionController, AdmissionDecision, ClockError, DenyReason, ElapsedClock, IssueError,
    IssuedGrant, ManualElapsedClock, ManualEpochClock, MonotonicLeaseClock, SystemEpochClock,
    ValidityClock, MAX_CANDIDATE_LIFETIME_MS,
};
pub use admission_v2::{
    V2AdmissionController, V2AdmissionDecision, V2DenyReason, V2ExpectedAuthority, V2Grant,
    V2GrantError, V2IssueError, V2ReceiverContext, VerifiedAdmission, V2_MAX_CANDIDATE_LIFETIME_MS,
};
pub use canonical::{CanonicalFields, MAX_CANONICAL_BODY, SCHEMA_VERSION};
pub use canonical_v2::{
    CanonicalV2Error, CanonicalV2Fields, MAX_V2_CANONICAL_BODY, V2_DOMAIN_TAG, V2_SCHEMA_VERSION,
};
pub use grant::{ExpectedAuthority, Grant, GrantError};
pub use issuer_store::{IssuerError, IssuerJournal, JournalEntry};
pub use keys::{random_32, IssuerSigningKey, IssuerVerifyingKey};
pub use peer::{
    possession_signing_bytes, ChallengeBinding, ChannelBinding, GrantDigest, GrantDigestError,
    ManagerSigningKey, ManagerVerifyingKey, PeerChallenge, PeerChallengeError,
    PeerPossessionVerifier, PeerProofError, PossessionProof, VerifiedPossession,
    MAX_CHALLENGE_LIFETIME_MS, MAX_CHANNEL_BINDING_LEN, PEER_DOMAIN_TAG,
};
pub use receiver_store::{
    ConsumeLeaseParams, LeaseRecord, LeaseState, ReceiverError, ReceiverLeaseStore,
    RenewLeaseParams, FIXED_MAX_LEASE_MS, RECEIVER_FORMAT_VERSION,
};
pub use store::{
    DurableStore, IssuedCredential, StoreError, StoreLimits, TrustBinding, DEFAULT_MAX_CLAIMED,
    DEFAULT_MAX_ISSUED, STORE_FORMAT_VERSION,
};
pub use types::*;
