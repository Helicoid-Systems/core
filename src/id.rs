//! Typed bounded identifiers and generation counters.
//!
//! Identifiers are opaque, immutable, and separate from display names and
//! network addresses. Construction is fallible and enforces
//! [`crate::bounds::MAX_ID_BYTES`]. A display name never confers authority.
//!
//! **Deserialization runs the same validation as construction.** A derived
//! `Deserialize` on a transparent newtype would accept empty or oversized
//! strings and bypass the constructors; every bounded type in this module
//! therefore uses a custom `Deserialize` that calls its validating constructor.
//!
//! Generation counters model the contract that an OS session number is not
//! reusable authority: user, lock, attachment, boot, or worker changes bump a
//! generation, and late callbacks carrying an older generation are fenced.
//! Exhaustion **refuses new authority** and never saturates into a reusable
//! current generation.

use crate::bounds::{char_count, MAX_DISPLAY_NAME_CHARS, MAX_ID_BYTES, MAX_MESSAGE_CHARS};
use crate::error::{Error, Result};
use crate::reason::ReasonCode;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Shared validation for opaque string identifiers.
fn validate_id(field: &'static str, raw: &str) -> Result<()> {
    if raw.is_empty() {
        return Err(Error::InvalidInput {
            field,
            reason: ReasonCode::InvalidInput,
        });
    }
    if raw.len() > MAX_ID_BYTES {
        return Err(Error::InvalidInput {
            field,
            reason: ReasonCode::InvalidInput,
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(Error::InvalidInput {
            field,
            reason: ReasonCode::InvalidInput,
        });
    }
    Ok(())
}

macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Create a validated identifier from an opaque non-empty string.
            pub fn new(raw: impl Into<String>) -> Result<Self> {
                let raw = raw.into();
                validate_id(stringify!($name), &raw)?;
                Ok(Self(raw))
            }

            /// Borrow the opaque string form.
            pub fn as_str(&self) -> &str {
                &self.0
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

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::new(raw).map_err(|e| D::Error::custom(e.to_string()))
            }
        }
    };
}

string_id!(
    /// Enrolled computer identity. Never an address, hostname, or discovered name.
    ComputerId
);
string_id!(
    /// Local operator/administrator account identity.
    AccountId
);
string_id!(
    /// Approved manager-device identity, separate from the account.
    ManagerId
);
string_id!(
    /// Organization/deployment identity.
    OrganizationId
);
string_id!(
    /// Operator-owned monitoring session identity.
    MonitoringId
);
string_id!(
    /// Observation, control, sharing, or attention interaction identity.
    InteractionId
);
string_id!(
    /// Action request identity used for dispatch and deduplication.
    ActionId
);
string_id!(
    /// Trusted local OS-user identity on an endpoint (opaque, not a display label).
    LocalUserId
);
string_id!(
    /// Optional flat organization group identity. A group name never grants access.
    GroupId
);
string_id!(
    /// Stable display identity for one output of the current desktop generation.
    DisplayId
);

/// Shared generation-counter newtype.
///
/// `next` returns `None` at exhaustion. Callers must refuse new authority when
/// exhausted; they must never reuse the current generation value.
macro_rules! generation {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl $name {
            /// The first generation for a fresh identity.
            pub const INITIAL: Self = Self(1);

            /// Next generation after the current one.
            ///
            /// Returns `None` when the counter is exhausted. Exhaustion must
            /// refuse new authority and permit safety teardown; it must never
            /// saturate into a reusable current generation.
            pub const fn next(self) -> Option<Self> {
                match self.0.checked_add(1) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// Fallible next generation for callers that surface a typed error.
            pub const fn try_next(self) -> Result<Self> {
                match self.next() {
                    Some(v) => Ok(v),
                    None => Err(Error::refused(ReasonCode::Expired)),
                }
            }

            /// True when this counter cannot advance and new authority must be refused.
            pub const fn is_exhausted(self) -> bool {
                self.0 == u64::MAX
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

generation!(
    /// Invalidated by user, lock, attachment, desktop replacement, or worker restart.
    DesktopGeneration
);
generation!(
    /// Invalidated by OS reboot.
    BootGeneration
);
generation!(
    /// Invalidated by monitored-worker process replacement.
    WorkerGeneration
);
generation!(
    /// Invalidated by enrollment quarantine, replacement, or epoch change.
    EnrollmentEpoch
);
generation!(
    /// Per-interaction fencing counter for late callbacks and frames.
    InteractionGeneration
);
generation!(
    /// Primary-display/layout mapping generation under the D25 contract.
    LayoutGeneration
);

/// Bounded plain user/operator text (messages, titles, instructions).
///
/// This is not a path, shell, or HTML field. Control characters and
/// whitespace-only content are rejected. Deserialization runs the same check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedText(String);

impl BoundedText {
    /// Validate and store plain text within [`MAX_MESSAGE_CHARS`].
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.trim().is_empty() {
            return Err(Error::InvalidInput {
                field: "BoundedText",
                reason: ReasonCode::InvalidInput,
            });
        }
        if char_count(&raw) > MAX_MESSAGE_CHARS {
            return Err(Error::InvalidInput {
                field: "BoundedText",
                reason: ReasonCode::InvalidInput,
            });
        }
        if raw
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(Error::InvalidInput {
                field: "BoundedText",
                reason: ReasonCode::InvalidInput,
            });
        }
        Ok(Self(raw))
    }

    /// Borrow the validated text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for BoundedText {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BoundedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(|e| D::Error::custom(e.to_string()))
    }
}

/// Bounded display label. Never used for authorization or uniqueness.
/// Deserialization runs the same validation as construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayName(String);

impl DisplayName {
    /// Validate and store a display label.
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.trim().is_empty() {
            return Err(Error::InvalidInput {
                field: "DisplayName",
                reason: ReasonCode::InvalidInput,
            });
        }
        if char_count(&raw) > MAX_DISPLAY_NAME_CHARS {
            return Err(Error::InvalidInput {
                field: "DisplayName",
                reason: ReasonCode::InvalidInput,
            });
        }
        Ok(Self(raw))
    }

    /// Borrow the validated label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for DisplayName {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DisplayName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(|e| D::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computer_id_rejects_empty_and_oversized() {
        assert!(ComputerId::new("").is_err());
        assert!(ComputerId::new("x".repeat(MAX_ID_BYTES + 1)).is_err());
        assert!(ComputerId::new("pc-01").is_ok());
    }

    #[test]
    fn computer_id_rejects_control_characters() {
        assert!(ComputerId::new("pc\u{0000}1").is_err());
    }

    #[test]
    fn generation_next_refuses_reuse_at_exhaustion() {
        let g = DesktopGeneration::INITIAL;
        assert_eq!(g.next(), Some(DesktopGeneration(2)));
        let max = DesktopGeneration(u64::MAX);
        assert!(max.is_exhausted());
        assert_eq!(max.next(), None, "exhaustion must not saturate into reuse");
        assert!(max.try_next().is_err());
    }

    #[test]
    fn bounded_text_rejects_whitespace_only_and_controls() {
        assert!(BoundedText::new("   ").is_err());
        assert!(BoundedText::new("hello").is_ok());
        assert!(BoundedText::new("a\u{0007}b").is_err());
    }

    #[test]
    fn deserialize_runs_constructor_validation() {
        assert!(serde_json::from_str::<ComputerId>("\"\"").is_err());
        assert!(serde_json::from_str::<ComputerId>("\"a\"").is_ok());
        let oversized = format!("\"{}\"", "x".repeat(MAX_ID_BYTES + 1));
        assert!(serde_json::from_str::<ComputerId>(&oversized).is_err());
        assert!(serde_json::from_str::<DisplayName>("\"\"").is_err());
        assert!(serde_json::from_str::<BoundedText>("\"   \"").is_err());
    }
}
