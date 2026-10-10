# Candidate authority laboratory

This crate proves a **bounded candidate** of separate issuance and receiver
consumption with durable replay, challenges, and controller claims, plus a
manager-key possession primitive. It is isolated from the app and server
production clients. **B03 and RD03 remain incomplete. This is not a
production freeze and not an approved schema.**

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## Current candidate surface

- **Separate stores.** `IssuerJournal` (issuer-only) and `ReceiverLeaseStore`
  (receiver-only). The receiver never opens the issuer DB.
- **Durable one-shot replay and challenges.** Capacity-capped
  `consumed_nonces` / `consumed_challenges`, preserved across restart.
- **Durable controller claims.** Exactly one non-released controller per
  endpoint (including Reserved and PendingRelease). Restart fences process
  authority. PendingRelease never auto-frees on mere time.
- **Bounded leases and renewal.** Hard 30s cap. Public renewal is
  `renew_with_possession` only (fresh signed grant + possession + lease-owner
  binding). Expired leases cannot be revived (exact deadline denies).
- **Sealed verified results.** Private fields; compile-fail doctests.

Credential lifetime is capped at 30 seconds. Required storage faults close the
gate; stop/release remains possible without audit persistence and is
generation-bound.

The peer possession primitive (`src/peer.rs`) is separate from issuance:
`PeerPossessionVerifier` constructs one-shot challenges with a fresh random
nonce and a domain-separated transcript binding deployment, issuer key and
generation, computer/incarnation, desktop generation, typed operation,
checked intent, exact grant digest, and opaque nonzero channel binding.
`ManagerSigningKey` is distinct from the issuer credential signer. Deadlines
use monotonic elapsed time. Channel binding is independently supplied fixture
input — not a proof of trusted transport.

## Evidence counts (2026-10-10)

| Suite | Tests |
|-------|------:|
| Unit | 86 |
| `distributed_review` | 28 |
| `peer_possession` | 17 |
| `peer_review` | 6 |
| `public_boundary` | 30 |
| **Runtime total** | **167** |
| Compile-fail doctests | **4** |
| **Total** | **171** |

Historical counts are retained in [PROOF_REPORT.md](PROOF_REPORT.md) as dated
evidence.

Fault-injection tests (read-only DB, real lock contention) use portable
`std::fs` permissions and native SQLite locks — no Unix-only APIs; the
read-only write-failure path is exercised on Windows via
`FILE_ATTRIBUTE_READONLY`.

## Limits (still true)

No real authenticated channel, OS session/desktop source, accounts, or
production integration is provided. Whole-DB rollback is not detectable
without an independent trusted anchor. Authority cutover/recovery remains
REQUIRED and unavailable. The schema remains a candidate — **no production
API is frozen**.
