# Candidate authority laboratory

This independent crate exercises a bounded Ed25519 credential, committed
issuance and atomic replay consumption in one local SQLite store. It is
isolated from the app and server production clients. B03 remains incomplete.

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Create a disposable fixture with `DurableStore::create`, then explicitly
initialize its immutable binding. `open` reads an existing store and never
recreates missing schema or trust state. Credential lifetime is capped at
30 seconds. Admission requires the local issuance row and independent fixture
receiver values, then atomically consumes the nonce once. Required storage
faults close the gate, including across ordinary file reopen.

The [proof report](PROOF_REPORT.md) records 61 passing tests and their limits.
This is a centralized laboratory proof: no peer possession, distributed
transport, real OS desktop generation, rollback anchor, approved recovery or
production integration is provided. The schema remains a candidate.
