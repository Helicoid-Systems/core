# Authority-Lab Cryptographic Admission Proof Report

**Crate**: `modules/core/authority-lab`
**License**: `Apache-2.0 OR MIT` (matches parent `modules/core`)
**Status**: Development **candidate** only — B03 **not** passed, RD03 **incomplete**. This is **not** a production freeze, **not** an approved schema, and **no production API is frozen**. Production integration remains unproved.

---

## Current evidence (2026-10-10)

### Counts (coordinator-verified)

| Suite | Tests |
|-------|------:|
| Unit (`src/**`) | 86 |
| `tests/distributed_review.rs` | 28 |
| `tests/peer_possession.rs` | 17 |
| `tests/peer_review.rs` | 6 |
| `tests/public_boundary.rs` | 30 |
| **Runtime total** | **167** |
| Compile-fail doctests (sealed results) | **4** |
| **Total** | **171** |

Local acceptance this turn (`/tmp/hs-toolchain/cargo/bin`):

- `cargo fmt --all -- --check` — clean
- `cargo test --locked` — **167 runtime + 4 compile-fail doctests**
- `cargo clippy --locked --all-targets -- -D warnings` — clean

### What this candidate contains now

- **Separate issuance and consumption stores** (`IssuerJournal`,
  `ReceiverLeaseStore`). Receiver never opens the issuer DB.
- **Durable one-shot challenges and replay** (`consumed_challenges`,
  `consumed_nonces`), capacity-capped and preserved across restart.
- **Durable controller claims** (`control_claims` + partial unique index).
  Exactly one non-released controller per endpoint including Reserved and
  PendingRelease. Restart fences process authority. PendingRelease never
  auto-frees on mere time.
- **Bounded verified renewal** via `renew_with_possession` only (fresh signed
  grant + possession + exact lease-owner binding). Raw `renew_lease` is
  crate-private. Deadline clamped to fixed 30s. `current_mono >=
  lease_deadline` (exact boundary) denies — expired authority is not revived.
- **Sealed verified results** (`VerifiedAdmission`, `VerifiedPossession`).

### Still absent (do not over-claim)

- No real transport, OS session/desktop source, or accounts (fixture inputs).
- No independent whole-DB rollback anchor (copied valid DB is undetectable).
- No production adoption. B03/RD03 not passed. No production API frozen.
- No authority cutover / recovery (REQUIRED, unavailable).

### Native portability CI

`modules/core/.github/workflows/ci.yml` job `authority-proof` runs a matrix
on **Ubuntu, macOS, and Windows** (timeout 20m) with `cargo fmt --check`,
`cargo test --locked`, and `cargo clippy --all-targets -- -D warnings`
against `authority-lab/Cargo.toml`. Existing `fmt-test-clippy` and
`engine-header` jobs are unchanged. SQLite sidecar/durable-storage semantics
are checked with actual native tests; no skips or weakened checks.

**Windows portability (2026-10-10):** `tests/public_boundary.rs` no longer
uses Unix-only `PermissionsExt` / `from_mode(0o644)`. The read-only
required-write-failure test saves and restores original permissions metadata
and still injects a genuine read-only fault via `set_readonly` (native
`FILE_ATTRIBUTE_READONLY` on Windows). Local Unix suite remains 167 runtime
+ 4 doctests. GitHub `windows-latest` compile and test execution are
**NOT VERIFIED** until a coordinator rerun.

---

## Historical evidence (retained, dated)

The sections below record earlier coordinator-verified runs. Counts and
statements about “what is missing” are **historical snapshots**, not the
current state. Current state is the section above.

### Historical: same-store candidate + peer possession (87 runtime / 2 doctests)

**Date**: 2026-10-10 (earlier revision)

#### Scope (historical)

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

Additional **peer manager-key possession** primitive (`src/peer.rs`):

- Real Ed25519 manager-secret signing, separate from the issuer credential signer
- Receiver-issued one-shot challenge: fresh nonzero random nonce, pinned manager key
- Domain-separated canonical transcript binding deployment, issuer key/generation,
  computer/incarnation, fixture desktop generation, typed operation, checked intent,
  exact grant digest (body || signature || issuer key), opaque nonzero channel binding
- Challenge constructed only by `PeerPossessionVerifier`; private one-shot acceptance
- Monotonic elapsed deadlines (`ElapsedClock`), lifetime ≤ 30s (exact bound allowed)

#### Historical test results

**87/87 runtime tests and 2/2 compile-fail doc tests pass** (`cargo test --locked`).

| Suite | Tests |
|-------|------:|
| Unit (`src/**`) | 34 |
| Public admission (`tests/public_boundary.rs`) | 30 |
| Peer possession (`tests/peer_possession.rs`) | 17 |
| Peer review regressions (`tests/peer_review.rs`) | 6 |
| **Runtime total** | **87** |
| Verified-result sealing (compile-fail docs) | 2 |

The original **61** same-store admission candidate tests (31 unit + 30 public
boundary) remain intact and passing in later revisions as well.

#### Historical public-boundary coverage (selected)

| Behaviour | Result |
|-----------|--------|
| Lifetime > 30s / exact 30s | Rejected / allowed |
| Exclusive `create` | Second create → `AlreadyExists` |
| `open` missing file | `NotFound` |
| Issue → admit → replay | Granted then `ReplayDetected` |
| Scope separation | Observe ↛ Control; StopOnly only StopOnly |
| Simultaneous two-connection consumption | Exactly one Granted |
| Clock rollback | `ClockFault` + latch |

#### Historical peer possession coverage (selected)

| Behaviour | Result |
|-----------|--------|
| One proof succeeds once | Replay → `AlreadyAccepted` |
| Exact grant digest binds signature and issuer key | Digest changes when either changes |
| Deadline exact bound | Valid at deadline−1ms; expired at deadline |
| Monotonic rewind / expiry | Fail closed; never revives |

#### Historical limitations (superseded where noted)

These were accurate for the 87-test revision. Items marked **superseded**
are implemented in the current candidate (see Current evidence above).

- **Same-store centralized proof only** *(historical)*. The current candidate
  separates issuer and receiver stores. *(Superseded: separate stores exist.)*
- **No durable replay/restart proof for challenges** *(historical)*.
  *(Superseded: durable `consumed_challenges` / `consumed_nonces` and fenced
  controller claims exist.)*
- **No real authenticated channel.** Still true. Channel binding is fixture
  input, not TLS or transport authentication.
- **No OS desktop-generation source.** Still true. Fixture inputs only.
- **No distributed transport, recovery, or authority cutover.** Still true.
- **Copied valid old DB rollback is not detectable** without an independent
  trusted anchor. Still true.
- **Not proved:** production callers (B03 not passed), listeners, media/file/UI
  scope expansion, real enrolled authority, user keys. Still true.

#### Historical security properties (retained)

1. Domain separation `HAL-AUTH-ADMISSION` || `0x00` || schema (and V2 tag)
2. Bounded total canonical decode; structural rejects
3. Raw signer `pub(crate)`; public issuance only via commit seam
4. Strict Ed25519 (`verify_strict`)
5. Immutable persisted trust; no epoch reopen; no migration/recovery API
6. Issuance/claim validate full binding inside one `IMMEDIATE` transaction
7. Fault latch with synced sidecar; missing/corrupt denies
8. Counts compared as `i64`; negative DB integers rejected
9. `ValidityClock` separate from `MonotonicLeaseClock`
10. Peer domain separation `HAL-AUTH-PEER-PROOF` distinct from admission
11. Manager signing key distinct from `IssuerSigningKey`
12. Challenge objects private; acceptance one-shot and not rewound

#### Historical coordinator reviews (retained)

- **Public-boundary review:** exclusive read-lock latch, format metadata
  deletion, and empty intent were reproduced and fixed; four regression tests
  retained.
- **Peer possession review:** exact grant digest, foreign-verifier clock,
  terminal rewind, post-expiry rewind, and mid-verify expiry were required and
  fixed; `tests/peer_review.rs` holds the six regressions. Verified-result
  sealing added (private fields + compile-fail checks).

---

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

V2 adds issuer/approved keys, endpoint/boot/worker identity, display
generation, operation intent, policy revision, and exact channel binding
(`HAL-AUTH-ADMISSION-V2`).

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

## Files (current)

- `src/types.rs` — IDs, nonce, timestamps, scope, receiver context types
- `src/keys.rs` — Issuer Ed25519; strict verify; crate-private raw sign
- `src/canonical.rs` / `src/canonical_v2.rs` — bounded encode/decode
- `src/grant.rs` — v1 signed credential
- `src/store.rs` / `src/admission.rs` — v1 same-store candidate
- `src/issuer_store.rs` — separate issuer journal
- `src/receiver_store.rs` — receiver leases, nonces, challenges, controllers
- `src/admission_v2.rs` — v2 issue/admit/renew with possession
- `src/ownership.rs` — controller claim state machine
- `src/peer.rs` — manager-key possession challenge/proof/verifier
- `tests/public_boundary.rs`, `tests/peer_possession.rs`, `tests/peer_review.rs`
- `tests/distributed_review.rs` — coordinator regressions (separate stores,
  renewal, expiry, controllers)

## Conclusion

This remains a **development candidate** of reusable bounded authority
semantics: separate issuer/receiver stores, durable replay/challenge/controller
state, strict signed binding, mandatory Manager possession, ≤30s leases, and
verified renewal that cannot revive expired authority. **167 runtime + 4
compile-fail doctests** pass locally; the `authority-proof` CI matrix covers
Ubuntu, macOS, and Windows natively. Production integration requires B03/RD03
approval and is out of scope. The canonical schema remains a candidate —
**nothing here freezes a production API**.
