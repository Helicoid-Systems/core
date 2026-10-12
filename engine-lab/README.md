# engine-lab (RD02 laboratory)

Helicoid Systems engine laboratory for **RD02: UI-independent engine and
bridge harness**. Owned path: `modules/core/engine-lab/**` plus the isolated
upstream checkout at `/tmp/hs-engine-source/**`.

This lab is **not** a media bridge, **not** an authentication/grant protocol,
and **not** a wrapper around the RustDesk application. It does not authorize
real control. **B03 is not passed. Full RD02 is not passed.**

## Windows native lifetime acceptance, 12 October 2026

[Native CI38259987539](https://github.com/Helicoid-Systems/core/actions/runs/38259987539) passes at exact code `e4fe20e40cda671535a20417a6a1bfa7eff6387d` on Windows Server2022: all **32 real Rust bridge tests**, the linked Windows C harness (**133 checks**) and C# lifetime check (**85 checks**). It builds the actual x64 DLL, verifies all27 `hs_` exports and no Flutter/Sciter imports, and checks16 frozen source files before/after. Separate [core/authority/header CI38259987548](https://github.com/Helicoid-Systems/core/actions/runs/38259987548) passes all five jobs.

The coordinator downloads [artifact11754147189](https://github.com/Helicoid-Systems/core/actions/runs/38259987539/artifacts/11754147189), verifies ZIP integrity and published SHA256 `89f883cb7920c5fc886ea7c3c1cc249795d5fea93b9674b589f3620b197b0416`, independently checks both zero-failure harness reports, exact generated-header bytes, all27 exports and all16 source hashes against the tested revision. Archived harness executables are PE x64. That historical evidence archive contains harness binaries and reports; it does not retain the tested `librustdesk.dll` and is not an installable engine bundle.

## Retained inert unsigned lab bundle

To close that packaging gap, `build-windows-x64.ps1` now copies the **exact
tested** `librustdesk.dll` (the same bytes the C/C# harnesses loaded) into the
owned output directory beside the existing harness/runtime files, and writes
`lab-bundle-receipt.json`. The receipt is a **bounded versioned evidence /
integrity record only** — not a signed release/update manifest, not publisher
keys, and not authorization. It records lab source Git SHA, frozen
upstream/hbb_common/Cargo.lock/vcpkg pins, `windows/x86_64` (PE `8664`),
ABI v2 with the 27 expected exports (set-equal to the retained header names),
and SHA256+size for every retained member. Connect/observation/channel binding
remain **UNAVAILABLE**; no endpoint hosting is started; no product linkage or
release is claimed.

`scripts/check-windows-lab-bundle.ps1` independently fail-closes on a missing
receipt or retained DLL, oversized/malformed receipt, unsafe paths (backslash
alias, colon/ADS/drive, dot/empty/trailing-dot-space components, case-alias
duplicates, separator-boundary escape), links/reparse points, members outside
the explicit allowlist, wrong hash/size, non-x64 PE for the native DLL / C
harness EXE / C# apphost EXE (managed C# assembly may be AnyCPU), export-list
drift versus the retained header, vcpkg pin drift versus the frozen workflow
pin, and any signing/release/update or connect-available claim. Import
libraries are retained only at the declared exact filenames
(`librustdesk.dll.lib` / `librustdesk.lib`).

After copying, the existing C and C# checks are re-run against the retained
copy only (cargo target directory removed from `PATH`; `HS_NATIVE_DLL_DIR`
points at the bundle directory), with `harness-staged.txt` /
`csharp-staged.txt` kept separate from the original 32/133/85 reports and
**required** in the success gate (real native CI supplies those reports). The
retained DLL is hashed before and after those runs. Original runs and all
PE/frozen/header/drift gates are unchanged. Copy destinations refuse
directories/junctions/links before any `Copy-Item`. Member size is bounded
(256 MiB/member, 512 MiB total) and only `pe/` and `csharp-lifetime-check/`
subdirectories are walked. Missing receipt or retained DLL fails the artifact
success gate. **Local negative checks are honest: no synthetic PE/DLL fixtures
and no local full-bundle positive acceptance — fresh Windows CI owns that
proof.**

External prerequisites to execute the retained harnesses on a host are
recorded in the receipt and are **not** installed by these helpers: MSVC x64
C runtime (`VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `MSVCP140.dll`) and
Universal CRT for the native harness and DLL (actual PE imports), and the
.NET 10 runtime (`Microsoft.NETCore.App` 10.0.x) for the C# lifetime check.
`NativeDllGate` exact loader rules are unchanged: `HS_NATIVE_DLL_DIR` must
name the bundle directory; no ambient search or permissive fallback.

MiMo-V2.6-Pro bounded packages and coordinator review repaired callback cleanup, exact source/patch guards, line endings, source decoding, PowerShell script arguments and the IPv6 SDK include. Exported model metadata and independent portable checks are recorded in the candidate inventory. Earlier failed-run details remain in BUILD-REPORT.md.

**Verified:** Windows x64 inert ABI, owned lifetime and asynchronous callback/drain behavior. **Not Verified/unavailable:** installed Windows11, app linkage/bundling, real admitted media/input/channel binding, Intel runtime and signed release. No engine binary is adopted into either native product app. Connect/observation/channel binding remain unavailable while selected stock relay adoption is Failed/Closed. This is a bounded lifetime prerequisite, not full RD02 or B03 acceptance.

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
| Windows native ABI execution | **Verified prerequisite** (32 Rust /133 C /85 C# checks in native CI38259987539; installed Windows11 and product app linkage remain Not Verified) |
| Exact tested DLL retained in lab bundle | **Seam added** (inert unsigned receipt + staged re-validation; fresh native CI required to publish a bundle that contains the DLL) |
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
bytes, route adoption, full RD02 Pass, installed Windows acceptance, Intel runtime,
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
