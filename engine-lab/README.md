# engine-lab (RD02 laboratory)

Helicoid Systems engine laboratory for **RD02: UI-independent engine and
bridge harness**. Owned path: `modules/core/engine-lab/**` plus the isolated
upstream checkout at `/tmp/hs-engine-source/**`.

This lab is **not** a media bridge, **not** an authentication/grant protocol,
and **not** a wrapper around the RustDesk application. It does not authorize
real control. **B03 is not passed. Full RD02 is not passed.**

## What this lab actually proves (and what it does not)

| Claim | Status |
| --- | --- |
| Real `crate::ui_session_interface::Session<NativeHandler>` construct/drop | **Proved** (inert) |
| `NativeHandler` is a real `InvokeUiSession` impl | **Proved** — every UI/media/input callback refused; `get_rgba` returns null |
| Disabled `server_keyboard/file/clipboard` defaults from real Session fields | **Proved** (C harness + Rust tests) |
| Prepared state is **inert**, not admitted / ready-to-view | **Proved** (naming + exports) |
| Prepare does not start hosting (process-local LISTEN sockets) | **Proved** (`lsof -a`, process-local; 0→0) |
| Connecting / observation before B03 | **Proved unavailable** (`HS_STATUS_UNAVAILABLE`) |
| Version string storage is stable (no per-call leak) | **Proved** (OnceLock; harness compares pointers) |
| Rust panic containment at the ABI | **Proved** (does **not** contain UB) |
| Generation exhaustion fails closed | **Proved** (no wrap; close refused) |
| Poisoned mutex fails closed | **Proved** (no recovery that admits work) |
| C header generated from implemented exports | **Proved** (`scripts/gen_header.py` + harness compile) |
| Repro scripts refuse wrong pins | **Proved** (HEAD / submodule / lock and patched-file SHA-256) |
| Async cancellation / drain proof | **NOT claimed** — drain is a synchronous transition |
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

**Not claimed:** frame ownership, media frames, input/control APIs, async
cancellation proof, full RD02 Pass, Windows build, Intel Mac compile,
license/adoption compliance, RD03 authority. See `BUILD-REPORT.md`.

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
