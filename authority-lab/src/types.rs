//! Typed identifiers and values for cryptographic admission.
//!
//! All identifiers are validated at construction: non-empty, length-bounded,
//! and restricted to unambiguous character sets (no control characters).
//! Friendly names are display metadata only and never keys.

use std::fmt;
use thiserror::Error;

/// Maximum length for any identifier string field.
pub const MAX_ID_LEN: usize = 128;

/// Maximum length for action scope strings.
pub const MAX_SCOPE_LEN: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    #[error("identifier empty")]
    Empty,
    #[error("identifier too long: {0} > {MAX_ID_LEN}")]
    TooLong(usize),
    #[error("identifier contains invalid characters: {0}")]
    InvalidChars(String),
    #[error("scope empty")]
    ScopeEmpty,
    #[error("scope too long: {0} > {MAX_SCOPE_LEN}")]
    ScopeTooLong(usize),
    #[error("zero nonce")]
    ZeroNonce,
    #[error("zero generation")]
    ZeroGeneration,
    #[error("zero grant digest")]
    ZeroGrantDigest,
    #[error("zero channel binding")]
    ZeroChannelBinding,
    #[error("timestamp does not fit i64")]
    TimestampOverflow,
    #[error("non-positive credential duration")]
    NonPositiveDuration,
}

/// Validate an identifier: non-empty, ≤ MAX_ID_LEN, `[A-Za-z0-9._@:+/-]`.
/// Rejects empty, oversized, and any control/ambiguous characters.
pub(crate) fn validate_id(s: &str) -> Result<(), TypeError> {
    if s.is_empty() {
        return Err(TypeError::Empty);
    }
    if s.len() > MAX_ID_LEN {
        return Err(TypeError::TooLong(s.len()));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '+' | '/' | '-'))
    {
        return Err(TypeError::InvalidChars(s.to_string()));
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, TypeError> {
                let s = s.into();
                validate_id(&s)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

id_type!(DeploymentId, "Deployment identifier.");
id_type!(AccountId, "Account identity (never a friendly name).");
id_type!(ManagerId, "Manager identity (never a friendly name).");
id_type!(ComputerId, "Enrolled computer identity.");
id_type!(IncarnationId, "Installation incarnation identity.");
id_type!(
    SchemaVersion,
    "Schema version tag for signing representation."
);
id_type!(AuthorityRevision, "Monotonic authority revision.");
id_type!(BootId, "Boot session identity.");
id_type!(WorkerId, "Worker identity.");
id_type!(EndpointIncarnation, "Endpoint installation incarnation.");
id_type!(OperationIntent, "Typed operation intent identifier.");
id_type!(PolicyRevision, "Policy revision for admission control.");

/// Nonce: must be exactly 32 bytes, non-zero.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn new(bytes: [u8; 32]) -> Result<Self, TypeError> {
        if bytes == [0u8; 32] {
            return Err(TypeError::ZeroNonce);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Issue/expiry timestamps: milliseconds since Unix epoch.
///
/// Values must fit `i64` so durable INTEGER columns and checked
/// conversions cannot silently truncate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampMs(u64);

impl TimestampMs {
    pub fn new(ms: u64) -> Result<Self, TypeError> {
        if i64::try_from(ms).is_err() {
            return Err(TypeError::TimestampOverflow);
        }
        Ok(Self(ms))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked conversion for SQLite INTEGER columns.
    pub fn to_i64(self) -> Result<i64, TypeError> {
        i64::try_from(self.0).map_err(|_| TypeError::TimestampOverflow)
    }
}

/// Action scope: explicit operation set. Observe never implies Control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// View pixels only. Cannot escalate to Control.
    Observe,
    /// Interact with the remote desktop.
    Control,
    /// Stop a sharing/assistance branch. No pixel access.
    StopOnly,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Observe => f.write_str("observe"),
            Operation::Control => f.write_str("control"),
            Operation::StopOnly => f.write_str("stop_only"),
        }
    }
}

impl Operation {
    /// Canonical one-byte opcode used in the signing representation.
    pub fn opcode(self) -> u8 {
        match self {
            Operation::Observe => 0x01,
            Operation::Control => 0x02,
            Operation::StopOnly => 0x03,
        }
    }

    pub fn from_opcode(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Operation::Observe),
            0x02 => Some(Operation::Control),
            0x03 => Some(Operation::StopOnly),
            _ => None,
        }
    }
}

/// Action scope: non-empty set of operations with no duplicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionScope(Vec<Operation>);

impl ActionScope {
    pub fn new(ops: impl IntoIterator<Item = Operation>) -> Result<Self, TypeError> {
        let mut out: Vec<Operation> = Vec::new();
        for op in ops {
            if out.contains(&op) {
                return Err(TypeError::InvalidChars(format!("duplicate op {op}")));
            }
            out.push(op);
        }
        if out.is_empty() {
            return Err(TypeError::ScopeEmpty);
        }
        Ok(Self(out))
    }

    pub fn operations(&self) -> &[Operation] {
        &self.0
    }

    /// Observe-only scope: pixel viewing, never control.
    pub fn observe_only() -> Self {
        Self(vec![Operation::Observe])
    }

    /// Stop-only scope: no pixels, no control.
    pub fn stop_only() -> Self {
        Self(vec![Operation::StopOnly])
    }

    /// True if this scope permits the given operation.
    pub fn permits(&self, op: Operation) -> bool {
        self.0.contains(&op)
    }

    /// Observe cannot authorize Control.
    pub fn can_control(&self) -> bool {
        self.permits(Operation::Control)
    }

    /// Stop-only has no pixel access.
    pub fn can_observe(&self) -> bool {
        self.permits(Operation::Observe)
    }
}

/// Desktop session generation. Invalidation (user change, lock, boot, worker
/// change) increments generation; old generations are not reusable authority.
/// Zero is rejected: it is never a valid live generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesktopGeneration(u64);

impl DesktopGeneration {
    pub fn new(n: u64) -> Result<Self, TypeError> {
        if n == 0 {
            return Err(TypeError::ZeroGeneration);
        }
        Ok(Self(n))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DesktopGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Display/layout session generation. Zero is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplayGeneration(u64);

impl DisplayGeneration {
    pub fn new(n: u64) -> Result<Self, TypeError> {
        if n == 0 {
            return Err(TypeError::ZeroGeneration);
        }
        Ok(Self(n))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DisplayGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Endpoint public key (32 bytes, non-zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointKey([u8; 32]);

impl EndpointKey {
    pub fn new(bytes: [u8; 32]) -> Result<Self, TypeError> {
        if bytes == [0u8; 32] {
            return Err(TypeError::ZeroNonce); // reuse nonce zero error for 32-byte key
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Interaction generation for operation context. Zero is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InteractionGeneration(u64);

impl InteractionGeneration {
    pub fn new(n: u64) -> Result<Self, TypeError> {
        if n == 0 {
            return Err(TypeError::ZeroGeneration);
        }
        Ok(Self(n))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Independent trusted receiver context.
///
/// These identities are caller-supplied preauthenticated fixture inputs.
/// This crate does **not** prove peer possession of any key or transport
/// authentication; it only compares signed credential fields against the
/// values the host already trusts for this desktop session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverContext {
    pub computer: ComputerId,
    pub incarnation: IncarnationId,
    pub account: AccountId,
    pub manager: ManagerId,
    pub desktop_generation: DesktopGeneration,
}

/// Issuer generation must be non-zero.
pub fn checked_issuer_generation(n: u64) -> Result<u64, TypeError> {
    if n == 0 {
        return Err(TypeError::ZeroGeneration);
    }
    Ok(n)
}

/// Credential duration must be strictly positive and fit `i64` endpoints.
pub fn checked_duration_ms(
    issued_at: TimestampMs,
    expires_at: TimestampMs,
) -> Result<u64, TypeError> {
    issued_at.to_i64()?;
    expires_at.to_i64()?;
    let expires = expires_at.as_u64();
    let issued = issued_at.as_u64();
    if expires <= issued {
        return Err(TypeError::NonPositiveDuration);
    }
    Ok(expires - issued)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_rejects_empty() {
        assert!(ComputerId::new("").is_err());
    }

    #[test]
    fn id_rejects_too_long() {
        let long = "a".repeat(MAX_ID_LEN + 1);
        assert!(ComputerId::new(long).is_err());
    }

    #[test]
    fn id_rejects_invalid_and_control_chars() {
        assert!(ComputerId::new("bad name!").is_err());
        assert!(ComputerId::new("drop;table").is_err());
        assert!(ComputerId::new("ctl\u{0007}").is_err());
        assert!(ComputerId::new("nl\nid").is_err());
    }

    #[test]
    fn id_accepts_valid() {
        assert!(ComputerId::new("room7-a03").is_ok());
        assert!(DeploymentId::new("deploy-1").is_ok());
    }

    #[test]
    fn nonce_rejects_zero() {
        assert!(Nonce::new([0u8; 32]).is_err());
    }

    #[test]
    fn nonce_accepts_nonzero() {
        assert!(Nonce::new([1u8; 32]).is_ok());
    }

    #[test]
    fn timestamp_overflow_rejected() {
        assert!(TimestampMs::new(u64::MAX).is_err());
        assert!(TimestampMs::new(i64::MAX as u64).is_ok());
    }

    #[test]
    fn desktop_generation_zero_rejected() {
        assert!(DesktopGeneration::new(0).is_err());
        assert!(DesktopGeneration::new(1).is_ok());
    }

    #[test]
    fn issuer_generation_zero_rejected() {
        assert!(checked_issuer_generation(0).is_err());
        assert!(checked_issuer_generation(1).is_ok());
    }

    #[test]
    fn duration_must_be_positive() {
        let a = TimestampMs::new(1000).unwrap();
        let b = TimestampMs::new(2000).unwrap();
        assert_eq!(checked_duration_ms(a, b).unwrap(), 1000);
        assert!(checked_duration_ms(a, a).is_err());
        assert!(checked_duration_ms(b, a).is_err());
    }

    #[test]
    fn observe_does_not_authorize_control() {
        let s = ActionScope::observe_only();
        assert!(s.can_observe());
        assert!(!s.can_control());
    }

    #[test]
    fn stop_only_has_no_pixels() {
        let s = ActionScope::stop_only();
        assert!(!s.can_observe());
        assert!(!s.can_control());
    }

    #[test]
    fn empty_and_duplicate_scope_rejected() {
        assert!(ActionScope::new([]).is_err());
        assert!(ActionScope::new([Operation::Observe, Operation::Observe]).is_err());
        assert!(ActionScope::new([Operation::Observe, Operation::Control]).is_ok());
    }

    #[test]
    fn display_generation_zero_rejected() {
        assert!(DisplayGeneration::new(0).is_err());
        assert!(DisplayGeneration::new(1).is_ok());
    }

    #[test]
    fn endpoint_key_rejects_zero() {
        assert!(EndpointKey::new([0u8; 32]).is_err());
        assert!(EndpointKey::new([1u8; 32]).is_ok());
    }

    #[test]
    fn interaction_generation_zero_rejected() {
        assert!(InteractionGeneration::new(0).is_err());
        assert!(InteractionGeneration::new(1).is_ok());
    }

    #[test]
    fn v2_id_types_validate() {
        assert!(BootId::new("boot-1").is_ok());
        assert!(BootId::new("").is_err());
        assert!(WorkerId::new("worker-1").is_ok());
        assert!(EndpointIncarnation::new("ep-inc-1").is_ok());
        assert!(OperationIntent::new("intent-1").is_ok());
        assert!(PolicyRevision::new("policy-1").is_ok());
    }
}
