# BUILD-REPORT — hs-core (`modules/core/**`)

Date: 10 October 2026 (review-fix revision)
Agent: core build agent
Owned path: `modules/core/**` only
Product identity: **Helicoid** / **Helicoid Systems**; native roles
**Helicoid Manager** / **Helicoid Computer** (D15 confirmed). Durable release
package and service identifiers still require B01.

## Windows native engine pipeline candidate, 12 October 2026

The bounded MiMo package (`ses_ffe5ed38a7197ffeHXifAvKzPG`) exports only `xiaomi/mimo-v2.6-pro` assistant turns. New Windows-only C harness and a C# helper link the frozen wrapper/lifetime check against the actual pinned DLL. A separate 90-minute Windows x64 job installs declared MSVC/.NET/Python/Rust tools, clones exact RustDesk/hbb_common pins, retains Cargo.lock, installs upstream vcpkg overlays at the frozen baseline, runs actual hs_native tests and both linked harnesses, and records PE/tool/hash evidence. Production connect/observation/channel-binding remain unavailable; selected stock relay adoption remains failed/closed.

Coordinator review repaired callback drain/timeouts that could otherwise close still-used handles, made header output explicitly LF (no ABI/header change), scoped LF Git checkout configuration to the CI job, initialized runner-dependent paths inside a runner step, and corrected pin parsing to honor the existing multiline inventory while still rejecting malformed/duplicate required pins. The exact retained patch, header, descriptor, wrappers and Mac harness are unchanged. No authority/core domain code or Cargo changes.

Fresh coordinator checks: native header/wrapper drift **PASS**; all four PowerShell AST parses **PASS**; .NET10 helper build **0 warnings/errors**; actual PowerShell source pins, patch application and patched-file hashes on the exact source **PASS**. Reapplication, lock/source drift, malformed/traversal manifests and duplicate pins each refuse for their intended reason. These are artifact/tool checks on this Mac. **Native Windows build, Rust/C/C# execution and PE inspection remain Not Verified at publication**; main keeps accepted core `067de35` until applicable native gates pass. Real media, input, public transport, installed acceptance and signed release are not established.

## Result

**VERIFIED** for the domain-library scope, including the coordinator review
findings: constructor-bypass deserialization and generation saturation are
fixed at the root, with failing-before/fresh-passing regression tests.

## Review findings addressed

| Finding | Root cause | Fix | Regression |
|---|---|---|---|
| `serde_json::from_str::<ComputerId>("\"\"")` returned `Ok` | `#[serde(transparent)]` derived `Deserialize` skipped constructors | Custom `Deserialize` on every bounded ID, `DisplayName`, `BoundedText`, `SearchQuery` calls the validating constructor | `review_regressions::empty_computer_id_deserialize_is_rejected` and related |
| `DesktopGeneration(u64::MAX).next()` saturated into the same generation | `saturating_add` reused current authority | `next() -> Option<Self>` (and `try_next`); exhaustion returns `None` / `Err`, never a reusable value | `generation_exhaustion_refuses_reuse`, `max_generation_minimize_still_tears_down_conservatively` |
| Action snapshot wire bypassed freeze invariants | Derived `Deserialize` filled private `target_ids` | `ActionSnapshot::from_parts` + custom `Deserialize` enforce non-empty bounded targets and valid deadline horizon | `action_snapshot_deserialize_rejects_zero_targets`, `..._rejects_invalid_horizon` |
| Out-of-scope action results accepted | No scope check on wire docs | `ActionSnapshotDoc` rejects results outside frozen targets (`ReasonCode::ComputerOutOfScope`) | `action_doc_rejects_out_of_scope_results`, `action_doc_wire_rejects_out_of_scope_results` |
| Unknown envelope schema versions accepted | No version gate | `SnapshotEnvelope` `Deserialize` rejects `schema_version != 1` | `envelope_rejects_unknown_schema_version` |
| Unbounded JSON body | No parse entry point | `snapshot::parse_snapshot_json` bounds `MAX_SNAPSHOT_JSON_BYTES` and is the only supported entry | `body_size_is_bounded_at_parse_entry` |
| Generation exhaustion during minimize/share teardown | Saturating counter | Minimize still tears down conservatively (`generation_fenced: None`); share branch/distribution stop independent of generation; new authority bound to an exhausted generation is refused | `max_generation_minimize_still_tears_down_conservatively`, `share_teardown_at_max_generation_is_conservative` |
| Schema not labeled as development format | Wording implied a settled protocol | Schema + README label it a **development snapshot format**, not settled media/auth protocol | Schema title/description; `snapshot` module docs |
| Product names / D18 / D21 stale | Report said naming/D18 awaited user | Updated to Helicoid / Helicoid Systems; D18 and D21 recorded as confirmed | README + this report |
| lib.rs consumer statement | Implied apps link Rust | States intended native consumers; apps do not link this crate yet | `src/lib.rs` header |
| No independent Rust CI | Missing | `.github/workflows/ci.yml` runs fmt/test/clippy with `--locked` from official `actions/checkout` and `dtolnay/rust-toolchain` | Workflow file present under owner tree |

## Modified files (this revision)

All under `modules/core/**`:

| Path | Change |
|---|---|
| `src/id.rs` | Validating `Deserialize` for bounded IDs/DisplayName/BoundedText; generation `next() -> Option` |
| `src/action.rs` | `ActionSnapshotParts`, `from_parts`, custom Serialize/Deserialize with freeze invariants |
| `src/inventory.rs` | Validating `Deserialize` for `SearchQuery` |
| `src/snapshot.rs` | Development-format labeling; envelope version gate; `parse_snapshot_json` / `to_snapshot_json`; in-scope result checks |
| `src/interaction.rs` | Generation exhaustion: minimize teardown without reusable fence; `bump_source_generation -> Result`; refuse new authority on exhausted desktop generation; `BeginInteraction.initial_generation` |
| `src/lib.rs` | Helicoid naming; intended native consumers; new exports |
| `schemas/hs-core-snapshot-v1.schema.json` | Development snapshot format label |
| `README.md` | Helicoid naming; D18/D21 confirmed; validation boundary; CI note |
| `tests/review_regressions.rs` | New: failing-before/fresh-passing review regressions |
| `tests/interaction_lifecycle.rs` | Updated for `initial_generation` field |
| `examples/repro_review.rs` | Coordinator reproducer converted to a fixed-behavior check |
| `.github/workflows/ci.yml` | New: independent fmt/test/clippy CI with lockfile |

No files outside `modules/core/**` were created or modified. No deletion, no
global install, no git init/commit/push.

## Commands and results

Toolchain: `rustc 1.99.0` / `cargo 1.99.0` at `/tmp/hs-toolchain`
(`CARGO_HOME=/tmp/hs-toolchain/cargo`, `RUSTUP_HOME=/tmp/hs-toolchain/rustup`,
dedicated `CARGO_TARGET_DIR=/tmp/hs-core-target`).

| Command | Exit | Result |
|---|---|---|
| `cargo fmt` | 0 | Formatted |
| `cargo fmt -- --check` | 0 | Clean |
| `cargo clippy --all-targets -- -D warnings` | 0 | Clean |
| `cargo test` | 0 | **79 passed, 0 failed** |

Test breakdown after the fix:

| Suite | Tests | Result |
|---|---|---|
| `src/*.rs` unit | 35 | ok |
| `tests/action_snapshots.rs` | 5 | ok |
| `tests/engine_and_console.rs` | 8 | ok |
| `tests/interaction_lifecycle.rs` | 10 | ok |
| `tests/inventory_selection.rs` | 6 | ok |
| `tests/review_regressions.rs` | 15 | ok |

### Original defects (was red, now green)

```
// before
serde_json::from_str::<ComputerId>("\"\"") == Ok("")   // constructor bypass
DesktopGeneration(u64::MAX).next() == Some(MAX)        // reusable authority

// after (review_regressions.rs + examples/repro_review.rs)
empty_computer_id_deserialize_is_rejected ... ok
generation_exhaustion_refuses_reuse ... ok
max_generation_minimize_still_tears_down_conservatively ... ok

$ cargo run --example repro_review
ok: empty ComputerId deserialize is rejected
ok: exhausted DesktopGeneration refuses reuse
repro_review: both review defects are fixed
```

## Confirmed product decisions reflected

- **D15**: Helicoid display name; Helicoid Systems company identity; native
  roles Helicoid Manager / Helicoid Computer. Durable package/service IDs
  remain B01 outputs (not invented here).
- **D18** (confirmed): reconnecting included eligible computers resume
  view-only after fresh admission; All mode includes newly authorized eligible
  inventory; explicit-ID inclusion and existing action snapshots never expand
  silently. Implemented in `inventory::OverviewState`.
- **D21** (confirmed): closing a file request refuses new submissions and
  retains completed files; replacement requires explicit confirmation. File
  request storage is a server responsibility; core supplies the immutable
  target-snapshot and result semantics that flow depends on.

## Explicitly not proved here (unverified gates)

Synthetic domain tests cannot substitute for platform evidence.

| Gate / scenario | Status | Why |
|---|---|---|
| E01 RustDesk adoption | **Pending** | `rustdesk_pending` records RD01–RD12 as all Pending. |
| E03 protocol / native ABI | **Not started** | No C ABI exported. Media/auth grant protocol remains unadopted. |
| E04 capture / input / attention on real OS | **Not run** | No capture, input injection, or permission probing in this crate. |
| E06 numeric limits / performance budgets | **Candidates only** | Bounds in `bounds.rs` are engineering candidates awaiting measurement. |
| V01–V04, V07–V11, V13–V31 | **Not run** | Require native apps, real endpoints, and OS effects. |
| V05, V06, V08, V12, V34, V37, V40, V41 | **Synthetic only** | Domain rules covered by unit/integration tests; no installed OS evidence. |
| V33 independent build/CI | **Partial** | Local `cargo build/test/clippy` succeeded alone. Workflow file added; no CI run log yet. |
| V39–V51 | **Not run** | Installer, recovery, security-floor, icon, and deployment proofs are outside this crate. |

## Remaining uncertainties

1. **B01 durable release package/service identifiers** — still required;
   `Cargo.toml` keeps `publish = false` and no invented repository URL.
2. **E06 frozen numeric bounds** — `bounds.rs` values remain labeled
   candidates.
3. **E03 reason-code wire mapping** — `ReasonCode::as_str` is the domain-local
   stable name, not a frozen transport enum.
4. **RustDesk feasibility** — RD01–RD12 all Pending against research snapshot
   `001b0e96173cea4e49f9f7a67bea95a177dd1de3` (inspected 9 October 2026, not
   an adopted pin).
5. **Custom crypto / grants** — intentionally absent.

## Design notes

- Ownership of `modules/core/**` is exclusive.
- Standard library first. Only `serde` / `serde_json` for the development
  snapshot interchange.
- No `unsafe`, no C ABI, no networking, no filesystem, no clock — timestamps
  are host-supplied `TimestampMs`.
- Every refusal carries a `ReasonCode`. Generation exhaustion is an honest
  `Option`/`Result`, never a saturating reuse.
- Untrusted JSON enters only through `snapshot::parse_snapshot_json`.
- `development-fixtures` is a named cargo feature; fixtures are labeled and
  are not production pixels.
