# Authority-Lab Cryptographic Admission Proof Report

**Crate**: `modules/core/authority-lab`  
**Date**: 2026-10-10  
**License**: `Apache-2.0 OR MIT` (matches parent `modules/core`)  
**Status**: Development **candidate** only — B03 **not** passed. This is **not** a production freeze and **not** an approved schema. Coordinator review completed for the isolated candidate; production integration remains unproved.

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

## Test Results

**61/61 tests pass** (`cargo test --locked`).

| Suite | Tests | Command |
|-------|------:|---------|
| Unit (`src/**`) | 31 | `cargo test --locked --lib` |
| Public boundary (`tests/public_boundary.rs`) | 30 | `cargo test --locked --test public_boundary` |
| **Total** | **61** | `cargo test --locked` |

Checks this turn:

- `cargo fmt --all -- --check` — clean
- `cargo clippy --locked --all-targets -- -D warnings` — clean
- `cargo test --locked` — 61 passed

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

## Candid limitations (unavoidable)

- **Same-store centralized proof only.** `admit` requires a **local issued row** in the same store. This is **not** independent endpoint cryptographic admission and **not** distributed issuance/consumption.
- **No peer possession proof.** `ReceiverContext` identities are caller-supplied preauthenticated fixture inputs. No transport authentication or key-possession proof is performed or claimed.
- **No distributed transport, recovery, or authority cutover.** An independent approval / cutover mechanism is still **REQUIRED** and **unavailable** here.
- **No OS desktop-generation source.** Generation values are fixture inputs, not bound to a real OS session.
- **Copied valid old DB rollback is not detectable** without an independent trusted anchor. An immutable local row does **not** solve database replay/rollback of an entire valid file.
- **Restart latch residual.** If both the DB and the sidecar/directory are unwritable, the in-memory latch is process-local. A complete restart latch requires an independent trusted anchor and explicitly approved recovery, which this candidate does not implement. Production completion is **not** claimed.
- **No measured latency guarantee.** The 30s bound is a hard lifetime cap, not a performance claim.
- **Not proved:** production callers (B03 not passed), listeners, media/file/UI scope expansion, MFA-as-key, real enrolled authority, user keys.

## Canonical schema (candidate — not frozen)

```
DOMAIN_TAG (18 bytes) || 0x00 ||
schema (LP) || deployment (LP) ||
issuer_generation (u64 BE) || authority_revision (LP) ||
computer (LP) || incarnation (LP) || account (LP) || manager (LP) ||
scope_count (u32 BE) || [op_byte...] ||
desktop_generation (u64 BE) || nonce (32 bytes) ||
issued_at (u64 BE) || expires_at (u64 BE)
```

LP = `u32 BE length || bytes`. **Development candidate**, not an approved production freeze.

## Files

- `src/types.rs` — IDs, nonce, timestamps, scope, `ReceiverContext`
- `src/keys.rs` — Ed25519; strict verify; crate-private raw sign
- `src/canonical.rs` — bounded encode/decode
- `src/grant.rs` — signed credential; admission verification
- `src/store.rs` — `create`/`open`, trust init, issuance, claims, fault latch
- `src/admission.rs` — public `issue` / `admit`; 30s lifetime; clocks
- `tests/public_boundary.rs` — public-boundary proofs only

## Conclusion

Second-review corrections are applied in this independent development candidate: 30s lifetime, exclusive create vs non-healing open, mandatory fault health with cross-handle visibility, atomic full-binding claim/issuance, and automatic latch on real public storage faults. **61/61** tests pass. The coordinator additionally reproduced and corrected required-read, format-marker and unbounded-intent failures before publication. Production integration requires B03 approval and is out of scope. The entire canonical schema remains a candidate, not an approved production freeze.

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
