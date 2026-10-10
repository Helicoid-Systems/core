# Candidate authority laboratory

This independent crate exercises a bounded Ed25519 credential, committed
issuance and atomic replay consumption in one local SQLite store. It also
proves a separate manager-key possession challenge against a receiver-issued
transcript. It is isolated from the app and server production clients. B03
and RD03 remain incomplete.

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Create a disposable fixture with `DurableStore::create`, then explicitly
initialize its immutable binding. `open` reads an existing store and never
recreates missing schema or trust state. Credential lifetime is capped at
30 seconds. Admission requires the local issuance row and independent fixture
receiver values, then atomically consumes the nonce once. Required storage
faults close the gate, including across ordinary file reopen.

The peer possession primitive (`src/peer.rs`) is separate from issuance:
`PeerPossessionVerifier` constructs one-shot challenges with a fresh random
nonce and a domain-separated transcript binding deployment, issuer key and
generation, computer/incarnation, desktop generation, typed operation,
checked intent, exact grant digest, and opaque nonzero channel binding.
`ManagerSigningKey` is distinct from the issuer credential signer. Deadlines
use monotonic elapsed time. Channel binding is independently supplied fixture
input — not a proof of trusted transport.

The [proof report](PROOF_REPORT.md) records 87 passing runtime tests,
two compile-fail checks and their limits.
This is a centralized laboratory proof plus a possession primitive: no real
authenticated channel, distributed receiver state, durable replay/restart
proof, real OS desktop generation, rollback anchor, approved recovery or
production integration is provided. The schema remains a candidate.
