//! Typed domain errors. Production paths never `unwrap` a fallible domain call.

use crate::reason::ReasonCode;
use core::fmt;

/// Domain error with a stable machine-readable reason.
///
/// This is development-semantics state, not a signed grant and not a
/// cryptographic wire format. Transport mapping is an E03 deliverable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Typed input validation failed.
    InvalidInput {
        /// Field name that failed validation.
        field: &'static str,
        /// Stable reason code.
        reason: ReasonCode,
    },
    /// Operation refused by authority, policy, or lifecycle rules.
    Refused {
        /// Stable reason code.
        reason: ReasonCode,
    },
    /// Engine cannot enforce required admission boundaries; fail closed.
    EngineUnavailable {
        /// Why the engine is unavailable.
        reason: ReasonCode,
    },
    /// A bounded capacity would be exceeded.
    QuotaReached {
        /// What bound was hit.
        limit: &'static str,
    },
    /// Required durable commit failed; no new authority or side effects.
    NotSaved {
        /// Which commit boundary failed.
        boundary: &'static str,
    },
}

impl Error {
    /// Stable machine-readable reason for this error.
    pub const fn reason(&self) -> ReasonCode {
        match self {
            Self::InvalidInput { reason, .. } => *reason,
            Self::Refused { reason } => *reason,
            // The engine-unavailable class always reports its own reason;
            // the wrapped cause is available via [`Error::cause`].
            Self::EngineUnavailable { .. } => ReasonCode::EngineUnavailable,
            Self::QuotaReached { .. } => ReasonCode::QuotaReached,
            Self::NotSaved { .. } => ReasonCode::NotSaved,
        }
    }

    /// Underlying cause for an engine-unavailable failure, when present.
    pub const fn cause(&self) -> Option<ReasonCode> {
        match self {
            Self::EngineUnavailable { reason } => Some(*reason),
            _ => None,
        }
    }

    /// Convenience constructor for a policy/lifecycle refusal.
    pub const fn refused(reason: ReasonCode) -> Self {
        Self::Refused { reason }
    }

    /// Convenience constructor for the fail-closed engine boundary.
    pub const fn engine_unavailable(reason: ReasonCode) -> Self {
        Self::EngineUnavailable { reason }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => {
                write!(f, "invalid input for {field}: {reason}")
            }
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::EngineUnavailable { reason } => write!(f, "engine unavailable: {reason}"),
            Self::QuotaReached { limit } => write!(f, "quota reached: {limit}"),
            Self::NotSaved { boundary } => write!(f, "required commit failed: {boundary}"),
        }
    }
}

impl std::error::Error for Error {}

/// Domain result alias.
pub type Result<T> = core::result::Result<T, Error>;
