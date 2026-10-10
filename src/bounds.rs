//! Frozen structural bounds for domain values.
//!
//! These are engineering candidates pending the E06 measurement gate. They are
//! hard limits in this crate: callers cannot exceed them. When E06 freezes
//! different numbers the constants change in one place and every construction
//! site inherits the new limit.

/// Maximum UTF-8 bytes for an opaque identifier string.
pub const MAX_ID_BYTES: usize = 128;

/// Maximum Unicode scalar values for a display name.
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;

/// Maximum Unicode scalar values for an overview search query.
pub const MAX_SEARCH_CHARS: usize = 64;

/// Maximum Unicode scalar values for a plain operator message.
pub const MAX_MESSAGE_CHARS: usize = 1_000;

/// Maximum computers in one monitoring inclusion set or action snapshot.
pub const MAX_TARGETS: usize = 4_096;

/// Maximum concurrently admitted observers on one computer.
pub const MAX_OBSERVERS_PER_COMPUTER: usize = 16;

/// Maximum concurrently admitted sharing receivers in one distribution.
pub const MAX_SHARE_RECEIVERS: usize = 64;

/// Default control-authority lease without renewal (milliseconds).
///
/// Candidate from the bounded-lifetime contract; E06 freezes the production value.
pub const DEFAULT_CONTROL_LEASE_MS: u64 = 30_000;

/// Default observation-authority lease without renewal (milliseconds).
pub const DEFAULT_OBSERVATION_LEASE_MS: u64 = 30_000;

/// Default attention-authority lease without renewal (milliseconds).
pub const DEFAULT_ATTENTION_LEASE_MS: u64 = 60_000;

/// Maximum time an unresolved control release may remain Pending Release
/// before the local claim is treated as ended (milliseconds).
pub const DEFAULT_PENDING_RELEASE_TIMEOUT_MS: u64 = 10_000;

/// Minimum accepted action deadline horizon (milliseconds from dispatch).
pub const MIN_ACTION_DEADLINE_MS: u64 = 1_000;

/// Maximum accepted action deadline horizon (milliseconds from dispatch).
pub const MAX_ACTION_DEADLINE_MS: u64 = 24 * 60 * 60 * 1_000;

/// Count of Unicode scalar values in `s`.
pub fn char_count(s: &str) -> usize {
    s.chars().count()
}
