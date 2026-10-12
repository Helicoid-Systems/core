# engine-lab (RD02 laboratory)

Helicoid Systems engine laboratory for **RD02: UI-independent engine and
bridge harness**. Owned path: `modules/core/engine-lab/**` plus the isolated
upstream checkout at `/tmp/hs-engine-source/**`.

This lab is **not** a media bridge, **not** an authentication/grant protocol,
and **not** a wrapper around the RustDesk application. It does not authorize
real control. **B03 is not passed. Full RD02 is not passed.**

## Windows native candidate, 12 October 2026

A separate [Windows CI pipeline](../.github/workflows/engine-windows.yml) now builds the exact pinned upstream and retained patch with locked dependencies, then runs the native Rust tests and linked Windows C/C# lifetime checks. It checks PE architecture, all 27 exports, absent Flutter/Sciter imports and unchanged generated contracts. MiMo-V2.6-Pro supplied the bounded package; coordinator review corrected callback timeout cleanup, multiline pin parsing, canonical LF header generation and runner path initialization.

Fresh coordinator checks pass header/wrapper drift, four PowerShell syntax checks, C# compilation without warnings, and real PowerShell pin/patch/hash checks on exact source plus refusal of deliberate drift. **Windows build and runtime remain Not Verified until actual CI passes.** No engine binary is adopted or bundled into either native application; connect, observation and channel binding remain unavailable while the selected stock relay gate is failed/closed.

Native CI `38249512646` at `e7c9d5f` failed at **check source pins** because `Invoke-Checked` array-splatted `'-Upstream'` as a positional value into `check-source-pin.ps1` (PowerShell named parameters are not native argv). The driver now uses a separate `Invoke-CheckedScript` named-hashtable splat for those two `.ps1` calls; native cargo/python/cl/dotnet argv arrays are unchanged. Agent-proved on Mac with the real check scripts: old wrapper reproduces the positional error, fixed wrapper green on exact pins/hashes, and wrong HEAD/lock/patched hashes still refuse. **Coordinator independent rerun and actual Windows CI still required.**

Coordinator rerun independently reproduces the old error, passes both actual
check scripts through the fixed helper and rejects a non-checkout and a real
wrong-HEAD checkout. Four-script parses, header/wrapper checks and Actionlint
pass. Actual native Windows Rust/C/C# execution is still required.

## What this lab actually proves (and what it does not)

| Claim | Status |
| --- | --- |
| Real `crate::ui_session_interface::Session<NativeHandler>` construct/drop | **Proved** (inert) |
| `NativeHandler` is a real `InvokeUiSession` impl | **Proved** — UI/media/input callbacks refused; `get_rgba` returns null |
| Owned immutable frame handle from real `on_rgba(ImageRgb)` | **Proved** (fixture lifetime checks + C ABI) |
| Checked dimensions/stride/length/pixel bounds | **Proved** (`HS_STATUS_BOUNDS`) |
| Exact allocator release (`hs_frame_release`) | **Proved** (Rust allocator; never C `free`) |
| Latest-frame bounded buffering + late-frame disposal | **Proved** (≤16 slots; supersede counted) |
| Distinct layout + interaction admission fences (ABI v2) | **Proved** (nonzero, bounded, independently checked) |
| Viewer/cancellation generation separate from admission fences | **Proved** |
| Outstanding-buffer validity after close | **Proved** (Arc; fixture lifetime check) |
| Async close/cancel + bounded drain | **Proved** (non-blocking close; `drain(timeout_ms)`) |
| Free refused until drain completes | **Proved** (`HS_STATUS_STATE`) |
| Lifecycle callbacks with documented queue/thread rules | **Proved** (bounded queue; worker-thread docs; poll events retained when no callback) |
| Lifecycle registration is atomic vs close/drain | **Proved** (state→session→life lock order; concurrent register-vs-close/drain tests) |
| Request-close is idempotent under parallel close | **Proved** (exactly one generation bump / one CLOSING) |
| Swift + C# wrappers (exact descriptor, double-free safe, drain-aware) | **Proved** (Swift6 strict concurrency + lifetime checks; ABI gate; sizeof/offsets) |
| Generated-contract drift check | **Proved** (`check-wrapper-contract.py` order/type/width + negative drift) |
| Fail-closed TCP handshake helpers | **Helper-only** — NOT wired into `client::secure_connection` / `server::identity_handshake`; actual gate **NOT PROVED** |
| Channel binding from negotiated encryption state | **Unavailable** (missing seam documented; export stays UNAVAILABLE) |
| Disabled `server_keyboard/file/clipboard` defaults | **Proved** (C harness + Rust tests) |
| Prepared state is **inert**, not admitted / ready-to-view | **Proved** (naming + exports) |
| Prepare does not start hosting (process-local LISTEN sockets) | **Proved** (`lsof -a`, process-local; 0→0) |
| Connecting / observation before B03 | **Proved unavailable** (`HS_STATUS_UNAVAILABLE`) |
| Version string storage is stable (no per-call leak) | **Proved** (OnceLock; harness compares pointers) |
| Rust panic containment at the ABI | **Proved** (does **not** contain UB) |
| Generation exhaustion fails closed | **Proved** (no wrap; owned Session dropped) |
| Poisoned mutex fails closed | **Proved** (no recovery that admits work) |
| C header generated from implemented exports | **Proved** (`scripts/gen_header.py` + harness compile) |
| Repro scripts refuse wrong pins | **Proved** (HEAD / submodule / lock and patched-file SHA-256) |
| Windows native ABI execution | **NOT VERIFIED** (new native CI candidate awaiting execution) |
| Selected-route adoption gate | **FAILED** (stock licence_key/UUID pairing; no HS per-allocation authority) |
| Media frames, capture, input, grants, authority | **NOT implemented** — B03 not passed |
| Full RD02 Pass | **NOT PASSED** |

## Why `LoginConfigHandler::default()` is not used

`LoginConfigHandler` is `#[derive(Default)]`, but `PeerConfig::default()`
(and the `serde_field_bool!` wrapper defaults) call
`UserDefaultConfig::read` → `Config::load_` → `confy::load_path`, which
**reads the user's config file on disk**. That is config persistence and is
forbidden in this lab.

Instead, `src/client.rs` provides `LoginConfigHandler::inert_default()`
(behind feature `hs-native`): a pure in-memory constructor that never touches
`UserDefaultConfig` or disk. `hs_native::inert_session()` builds the real
`Session<NativeHandler>` from that constructor. No mock Session is used.

## What RD02 asks for (and what this lab covers)

| RD02 requirement | This lab |
| --- | --- |
| Dedicated native feature/handler at smallest viable seam | `src/hs_native.rs` behind feature `hs-native` |
| Explicit viewer initialization | `hs_viewer_prepare` — constructs real inert Session; separate from any hosting path |
| No required Flutter/Sciter runtime | Seam does not *call* Sciter/Flutter; dylib load commands have no sciter/flutter |
| No accidental endpoint hosting in a viewer | Prepare never calls `start_server`; process-local LISTEN count unchanged |
| Explicit versions | `hs_abi_version`, `hs_engine_version` (static storage) |
| Bounded validated inputs | Peer-id length/charset validation at the ABI |
| Panic containment | Rust `catch_unwind` only; **not** a UB catcher; `HS_STATUS_PANIC` |
| Context lifetime | `hs_engine_ctx_new` / `hs_viewer_prepare` / close / drain / free |
| Disabled server_* permission defaults | Read from real `Session` fields (false by default) |
| Connecting/observation gate | `hs_viewer_connect`, `hs_viewer_begin_observation` → `HS_STATUS_UNAVAILABLE` |
| Actual headers + C harness | **Generated** `native/hs_native.h` + `native/harness.c` |
| Classified upstream patches | `patches/0001-hs-native-bridge.patch` + inventory |

Intel macOS cross-compilation also passes against the finalized patch: the
real x86_64 library and C harness compile and link, with the current 27
`_hs_*` exports (ABI2 + laboratory proof hooks). Execution is unverified
because Rosetta is absent on this machine. The earlier 18-export Intel proof
in `inventory/intel-build-proof.md` is a **historical** record of the
pre-callback ABI1 source; do not treat it as current. Current Intel
compile/link evidence is recorded in the atomic-publication report.

**Not claimed:** real media frames, input/control APIs, channel-binding
bytes, route adoption, full RD02 Pass, Windows build, Intel runtime,
license/adoption compliance, RD03 authority. See `BUILD-REPORT.md` and
the current evidence in `inventory/coordinator-2026-10-11.json`.

## Layout

```
engine-lab/
  patches/0001-hs-native-bridge.patch   retained upstream patch
  native/hs_native.h                    GENERATED C ABI header
  native/harness.c                      C harness
  scripts/gen_header.py                 header generator (from hs_native.rs)
  scripts/apply-patch.sh                pin-enforcing patch apply
  scripts/build-macos-arm64.sh          --locked build + harness
  inventory/                            pins, prerequisites, evidence
  README.md
  BUILD-REPORT.md
```

## Reproduce

```sh
export CARGO_HOME=/tmp/hs-toolchain/cargo
export RUSTUP_HOME=/tmp/hs-toolchain/rustup
export PATH=/tmp/hs-toolchain/cargo/bin:/tmp/hs-toolchain/nasm/bin:/tmp/hs-toolchain/pkgconf/bin:$PATH
export VCPKG_ROOT=/tmp/hs-toolchain/vcpkg
export VCPKG_INSTALLED_ROOT=/tmp/hs-toolchain/vcpkg/installed
export CARGO_TARGET_DIR=/tmp/hs-engine-build

# Upstream checkout must match inventory/source-pin.txt exactly
# (upstream_commit, submodule_hbb_common, lockfile_sha256).
# apply-patch.sh refuses wrong pins instead of only printing them.
./scripts/apply-patch.sh /tmp/hs-engine-source
./scripts/build-macos-arm64.sh /tmp/hs-engine-source
```

`build-macos-arm64.sh` regenerates `native/hs_native.h` from
`src/hs_native.rs` before compiling the harness, so header and exports cannot
drift. All cargo commands use `--locked`. The lockfile is not modified.

`python3 scripts/check-header.py` checks the retained native source hash and
generated header without cloning upstream or building native dependencies.
Independent CI runs this drift check; it does not replace platform linkage.

## Scope boundary

- Owns only `modules/core/engine-lab/**` and the isolated `/tmp/hs-engine-source`.
- Does not modify already-verified `modules/core/src`, `tests`, `schemas`,
  or `Cargo.toml` (Helicoid's own; the scratch upstream Cargo.toml is patched
  only to add the `hs-native` feature).
- No git commit/push/fork/remote operations. Coordinator owns publication.
- No real capture, input, endpoint listeners, or network services.
- No license-compliance or adoption claim.

The exact pinned upstream license is retained in `UPSTREAM-LICENCE`.
See BUILD-REPORT for the coordinator review, clean patch reproduction and
remaining redistribution inventory. The engine library is not bundled in the apps.
