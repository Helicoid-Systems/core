# BUILD-REPORT — hs-core (`modules/core/**`)

Date: 10 October 2026 (review-fix revision)
Agent: core build agent
Owned path: `modules/core/**` only
Product identity: **Helicoid** / **Helicoid Systems**; native roles
**Helicoid Manager** / **Helicoid Computer** (D15 confirmed). Durable release
package and service identifiers still require B01.

## Retained exact tested-DLL lab bundle seam, 12 October 2026 (agent)

Historical [artifact 11754147189](https://github.com/Helicoid-Systems/core/actions/runs/38259987539/artifacts/11754147189) (acceptance at `e4fe20e40cda671535a20417a6a1bfa7eff6387d`) contains harness binaries and reports but **does not retain the tested `librustdesk.dll`**, so it cannot serve as a standalone inert lab test bundle. This revision closes that concrete packaging gap only; no product/media/transport adoption.

`build-windows-x64.ps1` gains a smallest post-success seam that copies the **exact** `librustdesk.dll` used by the C/C# harnesses into the owned output at the declared name beside the existing harness/runtime files (current relative layout; application-directory load; no DLL-search expansion) via `Copy-RetainedExactBytes`, which refuses directory/junction/link destinations before any copy and retains an identical regular file only after hash match. Import libraries are kept only as `librustdesk.dll.lib`/`librustdesk.lib`. The existing C and C# checks are re-run against the retained copy only (cargo target dir removed from `PATH`), producing required `harness-staged.txt`/`csharp-staged.txt`; original 32/133/85 reports are unchanged. The retained DLL is hashed before/after those runs.

`lab-bundle-receipt.json` (`hs-windows-lab-bundle-receipt/v1`) is a **bounded evidence/integrity record**, not a signed release/update manifest: lab source Git SHA, frozen upstream/hbb_common/Cargo.lock/vcpkg pins (vcpkg cross-checked to the workflow pin), `windows/x86_64` PE `8664`, ABI v2 / 27 exports set-equal to the retained header, SHA256+size for every member (256 MiB/member, 512 MiB total; only `pe/` and `csharp-lifetime-check/` subdirs), INERT UNSIGNED LAB claims with connect/observation/channel_binding **UNAVAILABLE**, and measured MSVC CRT / UCRT / .NET 10 prerequisites that are documented, never installed.

`check-windows-lab-bundle.ps1` fail-closes on missing receipt/DLL/staged reports, oversized/malformed receipt, path aliases, links/reparse, non-allowlist members, hash/size mismatch, non-x64 PE for native DLL / C harness EXE / C# apphost EXE (managed assembly may be AnyCPU), export/pin drift, and any signing or connect-available claim. Workflow success gate requires `librustdesk.dll`, `lab-bundle-receipt.json`, `harness-staged.txt`, `csharp-staged.txt` and runs the checker. Frozen patch/source pins/Cargo/header/descriptor/wrappers/harnesses/NativeDllGate are unchanged.

Local probes on Mac (PowerShell 7.6.6): scripts AST-parse; header/wrapper **PASS**; actionlint **PASS**; 29/29 cases green (real e4fe missing-DLL proof, path/receipt negatives, MissingStagedReports Required=true, 5 pure copy-helper conflict cases extracted from the real build script). **No synthetic PE/DLL fixtures and no local full-bundle positive acceptance.** Inventory `main_accepted_core_pin` renamed to `historical_main_pin_before_native_verification`; `accepted_base_core_pin=a8cbd2be948740030891be8a4f291c67adb687bf`. **Native Windows runtime remains Not Verified** until coordinator fresh full CI; no commit/push. Report: `/tmp/hs-production-20261012/engine-retained-windows-bundle-report.md`.

## Native Windows lifetime acceptance, 12 October 2026

Complete [native CI38259987539](https://github.com/Helicoid-Systems/core/actions/runs/38259987539) passes at exact code `e4fe20e40cda671535a20417a6a1bfa7eff6387d` on Windows Server2022. **32 Rust tests,133 linked C checks and85 C# lifetime checks** pass with zero failures. Actual x64 DLL build/27 exports/no Flutter-or-Sciter imports and16 frozen source hashes pass. Separate [core/authority/header CI38259987548](https://github.com/Helicoid-Systems/core/actions/runs/38259987548) passes all five jobs.

The coordinator independently inspects the downloaded [evidence archive](https://github.com/Helicoid-Systems/core/actions/runs/38259987539/artifacts/11754147189): published SHA256 `89f883cb7920c5fc886ea7c3c1cc249795d5fea93b9674b589f3620b197b0416`, ZIP integrity, both zero-failure harness reports, generated header bytes, exact27 exports and16 hashes matching the tested source. Harness executables are PE x64. The archive contains reports and harness binaries; the tested `librustdesk.dll` is not retained, so this is not an installable engine package.

This evidence-only revision preserves tested code. **Verified scope:** Windows inert ABI/lifetime, callbacks, close/drain and wrapper ownership. **Not Verified/unavailable:** installed Windows11/app linkage, admitted media/input/channel binding, public-route adoption, Intel runtime, signing and recovery/security review. Selected stock relay adoption remains Failed/Closed. Earlier entries below describe historical candidate states and failed runs.

## Native header checker encoding, 12 October 2026

[Native run 38248924582](https://github.com/Helicoid-Systems/core/actions/runs/38248924582) at `977c9f2` passes exact upstream/submodule/lock/patch/hash gates, then stops at retained source extraction in `check-header.py`. Unlike the generator and wrapper checker, that checker used the platform default text decoder. Extracting the same UTF-8 patch as CP1252 reproduces a different source hash. The checker now explicitly reads UTF-8 and writes UTF-8/LF temporary source; actual header bytes, exports and pin hashes remain unchanged. Fresh source/header and wrapper drift checks pass on Mac; actual Windows continuation is still required. Separate [core/authority CI 38248924476](https://github.com/Helicoid-Systems/core/actions/runs/38248924476) passes all platforms.

## Windows checkout line endings, 12 October 2026

[Native pipeline 38248418243](https://github.com/Helicoid-Systems/core/actions/runs/38248418243) at `d5601b8` stopped at the unchanged Cargo.lock hash gate. The actual Windows hash `580ba38e…` exactly matches CRLF conversion of the retained LF lock `b7ac324e…`; upstream attributes specify `* text=auto`. Disabling autocrlf alone leaves native checkout endings in effect. The coordinator reproduced both hashes through real Git checkout settings on disposable exact source, then configured both `core.autocrlf=false` and `core.eol=lf` only for CI Git commands. No source/lock/hash pin is changed or accepted after conversion. Fresh workflow validation passes; the next actual native run remains required. The separate domain/authority/header [CI 38248418152](https://github.com/Helicoid-Systems/core/actions/runs/38248418152) passes on this candidate, including all three authority platforms.

## Windows native engine pipeline candidate, 12 October 2026

The bounded MiMo package (`ses_ffe5ed38a7197ffeHXifAvKzPG`) exports only `xiaomi/mimo-v2.6-pro` assistant turns. New Windows-only C harness and a C# helper link the frozen wrapper/lifetime check against the actual pinned DLL. A separate 90-minute Windows x64 job installs declared MSVC/.NET/Python/Rust tools, clones exact RustDesk/hbb_common pins, retains Cargo.lock, installs upstream vcpkg overlays at the frozen baseline, runs actual hs_native tests and both linked harnesses, and records PE/tool/hash evidence. Production connect/observation/channel-binding remain unavailable; selected stock relay adoption remains failed/closed.

Coordinator review repaired callback drain/timeouts that could otherwise close still-used handles, made header output explicitly LF (no ABI/header change), scoped LF Git checkout configuration to the CI job, initialized runner-dependent paths inside a runner step, and corrected pin parsing to honor the existing multiline inventory while still rejecting malformed/duplicate required pins. The exact retained patch, header, descriptor, wrappers and Mac harness are unchanged. No authority/core domain code or Cargo changes.

Fresh coordinator checks: native header/wrapper drift **PASS**; all four PowerShell AST parses **PASS**; .NET10 helper build **0 warnings/errors**; actual PowerShell source pins, patch application and patched-file hashes on the exact source **PASS**. Reapplication, lock/source drift, malformed/traversal manifests and duplicate pins each refuse for their intended reason. These are artifact/tool checks on this Mac. **Native Windows build, Rust/C/C# execution and PE inspection remain Not Verified at publication**; main keeps accepted core `067de35` until applicable native gates pass. Real media, input, public transport, installed acceptance and signed release are not established.

## Windows .ps1 argument forwarding repair, 12 October 2026 (agent)

[Native run 38249512646](https://github.com/Helicoid-Systems/core/actions/runs/38249512646) at `e7c9d5f` passed exact source/submodule/lock pins, retained patch apply + all patched-file hashes, header/wrapper checks and actual pinned vcpkg manifest dependency installation, then failed before the Rust native build at `build-windows-x64.ps1` **check source pins** with `A positional parameter cannot be found that accepts argument 'D:\a\_temp\hs-engine-windows-ci\source'.` Log: `/tmp/hs-production-20261012/engine-e7c9-native-failed.log`.

Cause: `Invoke-Checked` splatted `@('-Upstream', $Upstream)` as a positional argument array into a PowerShell `.ps1`. Unlike a native exe argv, `'-Upstream'` was bound as a positional value for the mandatory `Upstream` parameter and the real path became an unbound extra positional. Repair: a distinct `Invoke-CheckedScript` helper uses a named hashtable splat (`@{ Upstream = $Upstream }`) for the two `.ps1` callees; `Invoke-Checked` argv arrays for cargo/python/cl/dotnet are unchanged, as are strict `Fail`/`$LASTEXITCODE` checks. No pin/hash/patch/header/wrapper/Cargo/ABI change.

Agent checks on Mac (PowerShell 7.6.6, real check scripts on `/tmp/hs-production-20261012/engine-source`): AST-isolated old wrapper reproduces the exact positional error; fixed wrapper green on exact pins and patched-file hashes; wrong HEAD, wrong Cargo.lock hash and wrong patched-file hash each still refuse; four-script AST parses pass; header/wrapper-contract drift checks pass; actionlint on `engine-windows.yml` passes. **Coordinator independent rerun required.** Native Windows 32-test / real C/C# harness / PE evidence remains **Not Verified** until CI passes. No commit/push.

The coordinator independently reproduced the old positional-binding failure,
passed both real pinned-source and patched-hash scripts through the fixed
helper, and verified refusals for a non-checkout and a real wrong-HEAD checkout.
All four PowerShell scripts parse; header/wrapper drift and Actionlint pass.
Sanitized export verifies all29 assistant records as `xiaomi/mimo-v2.6-pro`.
These portable script checks do not establish native Windows DLL execution.

## Windows C harness IPv6 SDK include repair, 12 October 2026 (agent)

[Native run 38253183124](https://github.com/Helicoid-Systems/core/actions/runs/38253183124) attempt2 at `1fb642c` passed exact pins/patch/header/wrapper/vcpkg, all 32 real hs_native Rust tests (`32 passed; 0 failed`), built the actual x64 DLL and verified all 27 `hs_exports` + PE imports, then failed first at MSVC C harness compile: `windows-harness.c(186): error C2065: 'PMIB_TCP6TABLE_OWNER_PID': undeclared identifier` (and the matching use at line 197). Log: `/tmp/hs-production-20261012/engine-1fb-native-attempt2.log`. Attempt1 HTTP 500 on a dependency step is not a code failure; prior native failures (CRLF checkout, header encoding, `.ps1` positional splat) remain historical.

Cause (Microsoft primary source, bounded download this turn): `shared/tcpmib.h` declares `MIB_TCP6TABLE_OWNER_PID` / `PMIB_TCP6TABLE_OWNER_PID` inside `#ifdef _WS2IPDEF_`. `um/WinSock2.h` includes `ws2def.h`, not `ws2ipdef.h`, so `winsock2.h` alone leaves the IPv6 owner types undeclared. `um/WS2tcpip.h` includes `winsock2.h` then `ws2ipdef.h`. `shared/Iprtrmib.h` includes `tcpmib.h`; `um/iphlpapi.h` includes `iprtrmib.h`. Microsoft Learn for `MIB_TCP6TABLE_OWNER_PID` documents include `Iphlpapi.h` and states `Tcpmib.h`/`Iprtrmib.h` must never be used directly.

Repair (smallest include change in `engine-lab/native/windows-harness.c` only): public `#include <ws2tcpip.h>` after `winsock2.h` and before `iphlpapi.h`; winsock2 still precedes windows.h. No direct tcpmib/iprtrmib include, no fake SDK guard/type. IPv6 retained (`PMIB_TCP6TABLE_OWNER_PID`, `AF_INET6`); query error/retry/allocation bounds, ABI, header, patch, frozen pins, wrappers, drivers, workflow and callback ownership unchanged.

Agent local checks on Mac (not MSVC): `check-header.py` **0**; `check-wrapper-contract.py` **0**; four PowerShell AST parses **0**; actionlint `engine-windows.yml` **0**. **MSVC C compile after the include repair and native Windows runtime remain Not Verified; actual Windows CI is the required red/green check.** No accepted main pin advance. Report: `/tmp/hs-production-20261012/engine-ipv6-sdk-header-report.md`.

Coordinator independently passes header/wrapper drift, four real PowerShell parses and Actionlint, confirms all frozen ABI/patch/wrapper/Mac harness bytes unchanged, and verifies 34 exported assistant model records as `xiaomi/mimo-v2.6-pro` (SHA256 `e390f40fa088b1162d0e6fd52f2d3f1ef70b7f764b2fa4fc4842da6f6d6efc02`). Microsoft SDK source independently confirms the include chain. These checks establish the reviewed source repair; actual native C/C# execution remains required.

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
