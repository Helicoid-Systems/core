# Authority-Lab Cryptographic Admission Proof Report

**Crate**: `modules/core/authority-lab`
**Date**: 2026-10-10
**License**: `Apache-2.0 OR MIT` (matches parent `modules/core`)
**Status**: Development **candidate** only — B03 **not** passed, RD03 **incomplete**. This is **not** a production freeze and **not** an approved schema. Coordinator review completed for the isolated candidate; production integration remains unproved.

## Scope

Candidate **same-store centralized** peer admission contract proving, at the
public `create`/`open` / `issue` / `admit` boundary:

- Ed25519 **strict** signature over a canonical, domain-separated representation
- Typed checked identifiers; action scope: Observe ≠ Control; StopOnly has no pixels
- Exclusive fresh creation separate from existing open (open never heals schema/state)
- Immutable trust binding initialized exactly once on a fresh handle
- Mandatory healthy fault record; missing/corrupt state denies
- Durable commit seam before signed bytes are returned
- Atomic receiver nonce consumption with full issued-row comparison inside `IMMEDIATE`
- Hard candidate lifetime **30s** (`MAX_CANDIDATE_LIFETIME_MS = 30_000`); exact bound allowed
- Storage IO/lock faults latch closed; siblings and reopen observe the latch

Additional **peer manager-key possession** primitive (`src/peer.rs`), still not
distributed admission:

- Real Ed25519 manager-secret signing, separate from the issuer credential signer
- Receiver-issued one-shot challenge: fresh nonzero random nonce, pinned manager key
- Domain-separated canonical transcript binding deployment, issuer key/generation,
  computer/incarnation, fixture desktop generation, typed operation, checked intent,
  exact grant digest (body || signature || issuer key), opaque nonzero channel binding
- Challenge constructed only by `PeerPossessionVerifier`; private one-shot acceptance
- Monotonic elapsed deadlines (`ElapsedClock`), lifetime ≤ 30s (exact bound allowed)
- Wrong key, each mutated bound field, cross-role/domain signatures, wrong channel,
  substituted grant digest, replay, foreign verifier, rewound clock, and expiry
  (including mid-verify and post-expiry rewind) all fail closed

## Test Results

**87/87 runtime tests and 2/2 compile-fail doc tests pass** (`cargo test --locked`).

| Suite | Tests | Command |
|-------|------:|---------|
| Unit (`src/**`) | 34 | `cargo test --locked --lib` |
| Public admission (`tests/public_boundary.rs`) | 30 | `cargo test --locked --test public_boundary` |
| Peer possession (`tests/peer_possession.rs`) | 17 | `cargo test --locked --test peer_possession` |
| Peer review regressions (`tests/peer_review.rs`) | 6 | `cargo test --locked --test peer_review` |
| **Runtime total** | **87** | `cargo test --locked` |
| Verified-result sealing (compile-fail docs) | 2 | `cargo test --locked --doc` |

The original **61** same-store admission candidate tests (31 unit + 30 public
boundary) remain intact and passing.

Checks this turn (toolchain `/tmp/hs-toolchain/cargo/bin`, `CARGO_HOME=/tmp/hs-toolchain/cargo`, `RUSTUP_HOME=/tmp/hs-toolchain/rustup`):

- `cargo fmt --all -- --check` — clean
- `cargo clippy --locked --all-targets -- -D warnings` — clean
- `cargo test --locked` — 87 runtime and 2 compile-fail doc tests passed

## Public-boundary coverage (selected)

| Behaviour | Result |
|-----------|--------|
| Lifetime > 30s / exact 30s | Rejected / allowed |
| Exclusive `create` | Second create → `AlreadyExists` |
| `open` missing file | `NotFound` |
| Reopen uninitialized | `initialize_trust` → `InitNotAllowed` |
| Same-binding re-init on fresh handle | No-op only when required state valid |
| Issue → admit → replay | Granted then `ReplayDetected` |
| Scope separation | Observe ↛ Control; StopOnly only StopOnly |
| Expired at `now == expires_at` | `Expired` |
| Wrong signing key | Rejected before store write |
| Signature substitution / field mutation | Denied; nonce not consumed |
| Wrong trusted account/manager/computer/incarnation/desktop | `TargetMismatch` |
| Intent mismatch | Denied |
| Closed epoch | Blocks issue/admit; no reopen |
| Closed epoch + deleted binding | Fail closed; no reinit |
| Deleted trust / fault / epoch on reopen | Fail closed; never heals |
| Corrupt epoch boolean | Deny/latch |
| Simultaneous two-connection consumption | Exactly one Granted |
| Capacity exhaustion | Fail closed; unexpired rows not pruned |
| Real lock contention on public `issue` | Automatic latch; survives reopen |
| Read-only DB on public `issue` | Automatic latch |
| Sibling handle after latch | Next public op denied |
| Clock rollback | `ClockFault` + latch |

## Peer possession coverage (selected)

| Behaviour | Result |
|-----------|--------|
| Independent manager secret → strict verify | `VerifiedPossession` |
| One proof succeeds once | Replay → `AlreadyAccepted` |
| Wrong manager key / foreign secret | `ManagerKeyMismatch` / `SignatureInvalid` |
| Each bound field mutation | `SignatureInvalid`; challenge unconsumed |
| Issuer grant signature as possession proof | `SignatureInvalid` (cross-role) |
| Admission domain tag as peer transcript | `SignatureInvalid` |
| Wrong channel / substituted grant digest | `SignatureInvalid` |
| Exact grant digest binds signature and issuer key | Digest changes when either changes |
| Deadline exact bound | Valid at deadline−1ms; expired at deadline |
| Lifetime 0 / >30s / exact 30s | Rejected / rejected / allowed |
| Zero/empty channel binding, zero grant digest, zero issuer gen/key, empty intent | Rejected at binding/transcript |
| Foreign verifier | `ForeignChallenge` |
| Monotonic rewind (before create or within lifetime) | `ClockFault`, terminal |
| Expired then clock rollback | Stays expired; never revives |
| Expire during verification | Refused after signature check |

## Security properties checked in this candidate

1. Domain separation `HAL-AUTH-ADMISSION` || `0x00` || schema
2. Bounded total canonical decode (no panics); structural rejects (zero nonce/gen/desktop, bad times, dup/unknown ops)
3. Raw signer `pub(crate)`; public issuance only via commit seam; no external issued-row manufacture
4. Strict Ed25519 (`verify_strict`)
5. Immutable persisted trust; no epoch reopen; no migration/recovery API
6. Issuance and claim validate fault + trust + epoch + full issued binding/hash/intent **inside** one `IMMEDIATE` transaction
7. Fault latch: mandatory `fault_state` healthy `latched=0`; missing/corrupt denies; sidecar file is synced; parent-directory sync is attempted where supported and cannot be ignored if present
8. Unique-index mapping limited to `claimed_nonces.nonce_hex` (other constraint failures are not “replay”)
9. Counts compared as `i64` against `i64` limits; negative DB integers rejected
10. `ValidityClock` (signed epoch) separate from `MonotonicLeaseClock` (local lease)
11. Peer domain separation `HAL-AUTH-PEER-PROOF` distinct from the admission domain
12. Manager signing key type is distinct from `IssuerSigningKey`; manager proofs cannot use the issuer credential path
13. Challenge objects have private state; only `PeerPossessionVerifier` constructs them; acceptance is one-shot and not rewound
14. Monotonic challenge deadlines re-checked after signature verification; observed expiry or rewind latches terminal

## Candid limitations (unavoidable)

- **Same-store centralized proof only.** `admit` requires a **local issued row** in the same store. This is **not** independent endpoint cryptographic admission and **not** distributed issuance/consumption.
- **Possession primitive only.** `src/peer.rs` proves manager-key possession against a receiver-issued challenge. It is **not** distributed admission, does not replace `admit`, and does not persist receiver state.
- **No real authenticated channel.** Channel binding is explicitly independently supplied fixture input. It is **not** TLS, a cryptographic channel proof, or transport authentication.
- **No durable replay/restart proof for challenges.** Challenge acceptance and clock-fault state are in-memory only. A process restart is not claimed to preserve replay refusal.
- **No OS desktop-generation source.** Generation values are fixture inputs, not bound to a real OS session.
- **No distributed transport, recovery, or authority cutover.** An independent approval / cutover mechanism is still **REQUIRED** and **unavailable** here.
- **Copied valid old DB rollback is not detectable** without an independent trusted anchor. An immutable local row does **not** solve database replay/rollback of an entire valid file.
- **Restart latch residual.** If both the DB and the sidecar/directory are unwritable, the in-memory latch is process-local. A complete restart latch requires an independent trusted anchor and explicitly approved recovery, which this candidate does not implement. Production completion is **not** claimed.
- **No measured latency guarantee.** The 30s bound is a hard lifetime cap, not a performance claim.
- **Not proved:** production callers (B03 not passed), listeners, media/file/UI scope expansion, MFA-as-key, real enrolled authority, user keys, concurrency clone detection.

## Canonical schema (candidate — not frozen)

Admission:

```
DOMAIN_TAG (18 bytes) || 0x00 ||
schema (LP) || deployment (LP) ||
issuer_generation (u64 BE) || authority_revision (LP) ||
computer (LP) || incarnation (LP) || account (LP) || manager (LP) ||
scope_count (u32 BE) || [op_byte...] ||
desktop_generation (u64 BE) || nonce (32 bytes) ||
issued_at (u64 BE) || expires_at (u64 BE)
```

Peer possession:

```
PEER_DOMAIN_TAG ("HAL-AUTH-PEER-PROOF") || 0x00 ||
deployment (LP) || issuer_public_key (32) || issuer_generation (u64 BE) ||
computer (LP) || incarnation (LP) || desktop_generation (u64 BE) ||
operation (1) || intent_id (LP) || grant_digest (32) ||
channel_binding (LP) || challenge_nonce (32) ||
expected_manager_key (32) || created_elapsed_ms (u64 BE) || lifetime_ms (u64 BE)
```

LP = `u32 BE length || bytes`. Exact grant digest =
SHA-256(canonical signed body || signature || issuer_public_key).
**Development candidate**, not an approved production freeze.

## Files

- `src/types.rs` — IDs, nonce, timestamps, scope, `ReceiverContext`
- `src/keys.rs` — Issuer Ed25519; strict verify; crate-private raw sign
- `src/canonical.rs` — bounded encode/decode
- `src/grant.rs` — signed credential; admission verification
- `src/store.rs` — `create`/`open`, trust init, issuance, claims, fault latch
- `src/admission.rs` — public `issue` / `admit`; 30s lifetime; clocks
- `src/peer.rs` — manager-key possession challenge/proof/verifier
- `tests/public_boundary.rs` — public admission-boundary proofs only
- `tests/peer_possession.rs` — public peer possession proofs
- `tests/peer_review.rs` — coordinator verifier/clock regressions

## Conclusion

Second-review corrections are applied in this independent development candidate: 30s lifetime, exclusive create vs non-healing open, mandatory fault health with cross-handle visibility, atomic full-binding claim/issuance, and automatic latch on real public storage faults. A bounded peer possession primitive is added with real manager-key signing, one-shot verifier-owned challenges, and fail-closed monotonic deadlines. **87/87** runtime and **2/2** compile-fail doc tests pass. The original **61** admission candidate tests remain intact. Production integration requires B03/RD03 approval and is out of scope. The entire canonical schema remains a candidate, not an approved production freeze.

## Coordinator public-boundary review

Three extra failing probes reproduced defects before correction: an exclusive
SQLite read lock denied without persisting a latch, deletion of required format
metadata still allowed issuance, and an empty/unbounded intent was accepted.
Required read/metadata failures now use the durable fault path; format state is
checked inside the issuance/claim transaction, and public intent identifiers
use the existing 128-byte identifier bound. Observed fault-row corruption
cannot be healed by writing a healthy row; the synced sidecar still closes the
reopened handle. The reopen assertion verifies the reopened handle itself.

Fresh coordinator checks: format, all 61 locked tests and strict all-target
clippy pass. Four added public-boundary tests retain these regressions. File
reopen evidence is not power-loss or filesystem-crash evidence; complete
rollback/sidecar loss still requires an independent trusted anchor.

## Peer possession review

Coordinator probes for the possession slice required: exact grant digest to
bind signature and issuer key (not body hash alone); challenges to refuse a
foreign verifier clock; backward elapsed time to fail closed even inside the
original lifetime and to latch terminal (never heal); expiry to stay terminal
after clock rollback; and deadline re-check after signature verification so a
proof expiring mid-verify is refused. `tests/peer_review.rs` holds these
regressions. All six pass with the original admission suite unchanged.

The coordinator additionally reproduced caller fabrication and mutation of the
verified result: both compile-fail checks went red when its fields were public.
`VerifiedPossession` now has private fields and immutable getters; the two
checks pass. Verifier ownership uses a private shared allocation identity,
so a challenge cannot move to another clock origin. Fresh challenge nonce
entropy failure returns `NonceUnavailable` instead of panicking. The full
87-test suite, both compile-fail checks, format and strict clippy passed after
these corrections. No production or transport integration was enabled.
