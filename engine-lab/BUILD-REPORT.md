# BUILD-REPORT — engine-lab (RD02 laboratory)

Date: 10 October 2026
Agent: core MiMo-V2.5-Pro engine-lab
Owned path: `modules/core/engine-lab/**` + `/tmp/hs-engine-source/**`
Upstream pin: `001b0e96173cea4e49f9f7a67bea95a177dd1de3`
(hbb_common `229b904508364c8997aad0fb5af57effac859f60`)
Cargo.lock sha256: `b7ac324e15b5ae6f6ed7fd88bb8bc65633ca53b7cb1ad257600bdd6d719f234b`
Product: Helicoid / Helicoid Systems. No adoption or license claim.

## Result

**PARTIAL — inert Session construction seam VERIFIED on macOS arm64; full RD02 NOT PASSED.**

This report replaces the previous lab report, whose proof interpretation was
rejected. Corrections made in this turn are listed below.

## What this slice actually implements

Real `crate::ui_session_interface::Session<NativeHandler>` construction and
drop at the `hs-native` seam — the first legitimate engine integration step.
It is **not** remote initialization, **not** media, and **not** authority.

| Artifact | Location |
| --- | --- |
| Feature `hs-native` | scratch upstream `Cargo.toml` (additive) |
| `LoginConfigHandler::inert_default` | `src/client.rs` (pure in-memory; no config I/O) |
| `NativeHandler` + `inert_session` + C ABI | `src/hs_native.rs` |
| Module export | `src/lib.rs` (`#[cfg(feature = "hs-native")]`) |
| Retained patch | `patches/0001-hs-native-bridge.patch` (4 files) |
| **Generated** C ABI header | `native/hs_native.h` via `scripts/gen_header.py` |
| C harness | `native/harness.c` |
| Pin-enforcing apply script | `scripts/apply-patch.sh` |
| Build + harness entrypoint | `scripts/build-macos-arm64.sh` |
| Pins / prerequisites / evidence | `inventory/` |

### Classified upstream changes

| File | Change | Class |
| --- | --- | --- |
| `Cargo.toml` | Add feature `hs-native = []` | Additive feature flag; default features untouched; `Cargo.lock` unchanged |
| `src/lib.rs` | `#[cfg(feature = "hs-native")] pub mod hs_native` | Additive module export behind feature |
| `src/client.rs` | `LoginConfigHandler::inert_default` (~95 lines, behind `hs-native`) | Additive pure constructor; **avoids** `UserDefaultConfig`/disk reads that `Default` performs |
| `src/hs_native.rs` | **New** module: `NativeHandler` (`InvokeUiSession`), real `Session` ownership, C ABI | New isolated seam; does not call `initialize` / `io_loop` / `connect` / `start` / `core_main` / `start_server` / keyboard grab |

### Why not `Session::default()` / `LoginConfigHandler::default()`

Verified call chain (mapped, then deliberately avoided):

```
Session::<NativeHandler>::default()
  -> LoginConfigHandler::default()          // derive(Default)
    -> PeerConfig::default()                // field `config`
      -> ShowRemoteCursor::default() etc.   // serde_field_bool! wrappers
      -> PeerConfig::default_view_style()   // and friends
      -> UserDefaultConfig::read(key)
        -> USER_DEFAULT_CONFIG lazy_static
          -> UserDefaultConfig::load()
            -> Config::load_::<UserDefaultConfig>("_default")
              -> load_path() -> confy::load_path()   // READS USER CONFIG FILE
```

Also avoided: `LoginConfigHandler::initialize()` (loads peer config from disk
and may rewrite id/relay state). The lab instead uses `inert_default()`, which
constructs every field as a zero/false/empty in-memory value — including
`PeerConfig` as a struct literal with `ShowRemoteCursor { v: false }` etc., so
the config-reading `Default` helpers are never invoked.

## Commands and results (fresh this turn)

Toolchain: `rustc 1.99.0`, `cargo 1.99.0`, VCPKG_ROOT=/tmp/hs-toolchain/vcpkg
(pinned `9e593bb18ea69cc5095e012465dcd675a822ed0d`), NASM 2.16.03, pkgconf 3.0.3.
`CARGO_TARGET_DIR=/tmp/hs-engine-build` exported by the build script.

| Command | Exit | Result |
| --- | --- | --- |
| `cargo check --locked --lib --features hs-native` | 0 | Finished; 123 warnings (upstream pre-existing) |
| `cargo test --locked --lib --features hs-native hs_native` | 0 | **9 passed, 0 failed** |
| `cargo build --locked --lib --features hs-native` | 0 | Produced `liblibrustdesk.dylib` |
| `python3 scripts/gen_header.py …` | 0 | Wrote header (18 exports) |
| `cc -std=c11 -Wall -Wextra -Werror … harness.c` | 0 | Harness compiled (type-checks generated header) |
| `./hs-engine-harness` | 0 | **PASSED (0 failures)** — 45 checks |

### Rust unit tests (9/9 passed)

```
peer_id_bounds
inert_session_construct_drop_and_disabled_perms   // real Session construct/drop + 3 flags false
native_handler_get_rgba_is_null_and_never_publishes
prepare_constructs_real_session_and_reports_disabled_perms
explicit_prepare_does_not_start_hosting
panic_is_contained
generation_exhaustion_fails_closed
poisoned_state_mutex_fails_closed
exhausted_close_still_drops_prepared_session
```

### C harness evidence (real linked cdylib)

Retained at `inventory/harness-run.txt`. Summary:

```
ok   hs_abi_version == 1
ok   hs_engine_version pointer is stable (no leak)
ok   initial state is CREATED (no Session yet)
ok   Rust panic contained as HS_STATUS_PANIC
     process-local LISTEN sockets before prepare = 0
ok   hs_viewer_prepare constructs Session
ok   state is PREPARED (inert; not admitted / ready-to-view)
     process-local LISTEN sockets after prepare  = 0
ok   prepare did not add process-local TCP listeners
ok   server_keyboard_enabled is disabled by default
ok   server_file_transfer_enabled is disabled by default
ok   server_clipboard_enabled is disabled by default
ok   NativeHandler.get_rgba returns null (no fake media)
ok   hs_viewer_connect returns UNAVAILABLE (no network start)
ok   hs_viewer_begin_observation returns UNAVAILABLE (no stream)
ok   hs_viewer_request_close drops Session
ok   generation fence bumped on close
ok   hs_viewer_drain (synchronous transition; not async cancel proof)
=== PASSED (0 failures) ===
```

Note: process-local LISTEN count is 0→0 with `lsof -a -p <pid>`. The previous
lab used `lsof -p … -iTCP` **without** `-a`, so lsof OR-ed the predicates and
counted **system-global** listeners (25). That bug is fixed and the claim is
now process-local.

### Symbols actually exported

Retained at `inventory/hs-symbols.txt` (`nm -gU` on the real dylib) — 18
symbols matching the 18 generated header prototypes:

```
_hs_abi_version, _hs_debug_inject_panic, _hs_engine_ctx_free,
_hs_engine_ctx_new, _hs_engine_version, _hs_generation,
_hs_handler_rgba_ptr, _hs_panics_contained, _hs_server_clipboard_enabled,
_hs_server_file_transfer_enabled, _hs_server_keyboard_enabled,
_hs_validate_peer_id, _hs_viewer_begin_observation, _hs_viewer_connect,
_hs_viewer_drain, _hs_viewer_prepare, _hs_viewer_request_close,
_hs_viewer_state
```

### Runtime dependency inspection

`inventory/dylib-deps.txt` (`otool -L`): Apple system frameworks + libc++.
`inventory/dylib-no-sciter-flutter.txt`: **no sciter/flutter in dylib load
commands**. The `hs_native` seam does not *call* Sciter or Flutter at runtime.
(Upstream still compiles the Sciter `ui` module in the default feature set;
that is a remaining dependency gate, listed below.)

## Corrections to the previous lab report (coordinator rejections)

| Rejected claim | Correction in this turn |
| --- | --- |
| `hs_viewer_init` only saved a peer string / mutated an own enum | Replaced: `hs_viewer_prepare` constructs a **real** `Session<NativeHandler>` and owns it; drop runs the real destructor |
| "Async drain / cancellation proof" | Drain is documented and named as a **synchronous** state transition. No workers, no callbacks. Not an async cancellation proof |
| TCP test counted global listeners | `lsof -a -p <pid>` ANDs predicates → process-local count (0→0) |
| Header said "GENERATED" but was handwritten | `scripts/gen_header.py` parses `#[no_mangle]` exports from `hs_native.rs`; build script regenerates before compile |
| Version export leaked a `CString` per call | `OnceLock<CString>`; harness asserts pointer stability |
| False double-free detection claims | Removed. Free prerequisites explicit: pointer from `ctx_new`, free once, no use-after-free, no re-entry. Double-free is UB, not a status code |
| `catch_unwind` implied to contain UB | Explicitly documented: it contains Rust panics **only**; UB is not caught |
| Generation wrap on exhaustion | `try_update` + `checked_add`; exhaustion returns `HS_STATUS_EXHAUSTED` and refuses further work (tested) |
| Poisoned mutex recovered via `into_inner` and admitted work | Locks return `HS_STATUS_INTERNAL` on poison; no recovery path that admits work (tested) |
| State named `ViewerReady` / "ready-to-view" | State is `Prepared` and documented as **inert**, not admitted / ready-to-view |
| Implied viewer-ready media path | `get_rgba` returns null; connect/observation exports return `HS_STATUS_UNAVAILABLE` |

## RD02 pass criteria assessment

| Criterion | Status | Evidence |
| --- | --- | --- |
| Real UI-independent session construct/drop | **Verified (lab)** | `Session<NativeHandler>` via `inert_default`; Rust + C harness |
| Disabled server_keyboard/file/clipboard defaults | **Verified (lab)** | Read from real Session fields (false) |
| No required Flutter/Sciter runtime *for this seam* | **Verified (lab)** | Seam does not call them; dylib load commands clean |
| No accidental endpoint hosting in a viewer | **Verified (lab)** | Prepare never calls `start_server`; process-local LISTEN 0→0 |
| Explicit versions + stable storage | **Verified** | `hs_abi_version==1`, version pointer stable |
| Bounded validated inputs | **Verified** | Peer-id empty/oversized/control rejected at ABI |
| Panic containment (Rust only) | **Verified** | `HS_STATUS_PANIC`; process lives; documented non-UB-catcher |
| Fail-closed generation / poisoned lock | **Verified** | Exhaustion + poison tests |
| Connecting/observation gated before B03 | **Verified** | `HS_STATUS_UNAVAILABLE` |
| Headers + C harness | **Verified** | Generated header; harness compile + run |
| macOS arm64 build | **Verified** | Built and harness-run on this host |
| Classified upstream patches | **Verified** | Table above + retained patch |
| Frame ownership | **NOT DONE** | No frame API; needs media path (RD04) |
| Async cancellation / worker drain | **NOT DONE / NOT CLAIMED** | Drain is synchronous by design in this slice |
| macOS x86_64 build | **NOT RUN** | Intel compile not claimed |
| Windows x64 build | **NOT RUN** | Next CI; not claimed. User can run Windows downloads; not blocked by Mac-side work |
| Full RD02 Pass | **NOT PASSED** | Frame ownership, cross-arch, Sciter-optional graph outstanding |

## Explicitly not claimed / not proved

- **No media frames, capture, input, grants, or control APIs.** Do not treat
  this ABI as an authorization surface. B03 is not passed.
- **Prepared ≠ admitted.** A prepared context holds an inert real Session.
  It is not connected, not observing, not ready-to-view, and confers no
  authority.
- **No async cancellation proof.** Drain is a synchronous transition only.
- **No real capture / screens / input / remote authority** of any kind.
- **No license-compliance or adoption claim.** Research pin only.
- **No fork/publish.** Coordinator owns publication. No git commit/push.
- **Double-free / use-after-free are not detected.** Violating free
  prerequisites is undefined behaviour, not a returned status.
- **Sciter `ui` module still compiles** in the default upstream feature set.
  This seam does not *require* or *call* Sciter at runtime.

## Remaining exact gates (not Windows-runtime excuses)

1. **Frame ownership seam (RD02 remaining pass item).** Typed owned frame
   descriptor with explicit release, width/height/format/stride/length
   validation, generation fencing. Needs the media path (RD04/RD06).
2. **Make `sciter-rs` optional.** Actual blocked symbols:
   `src/ui.rs` (whole module), `src/client/file_trait.rs` (`sciter::Value` in
   `read_dir`), `src/platform/delegate.rs` (`sciter::Host`), `src/keyboard.rs`
   (`crate::ui::CUR_SESSION`). Need a trait-object seam before `sciter` can
   leave the dependency graph.
3. **macOS x86_64 + Windows x64 builds.** Same patch; Windows needs the
   WinUI/vcpkg toolchain in CI. Not claimed here.
4. **Remote init / media / authority (B03).** `hs_viewer_connect` and
   `hs_viewer_begin_observation` are explicit `UNAVAILABLE` stubs. Do not
   reuse this lab ABI as an authority surface.
5. **RD03 authority/route** is the next executable frontier after this
   construction seam; it owns admission, grants, and the conflict matrix.

## Files owned this turn

All under `modules/core/engine-lab/**` (plus scratch edits in
`/tmp/hs-engine-source` retained as the patch). Verified Helicoid
`modules/core/src|tests|schemas|Cargo.toml` were **not** altered.

| Path | Purpose |
| --- | --- |
| `patches/0001-hs-native-bridge.patch` | Retained upstream patch (4 files) |
| `native/hs_native.h` | **Generated** C ABI header |
| `native/harness.c` | C harness (real Session proof) |
| `scripts/gen_header.py` | Reproducible header generator |
| `scripts/apply-patch.sh` | Pin-enforcing apply (refuses wrong pins) |
| `scripts/build-macos-arm64.sh` | `--locked` build + harness; exports `CARGO_TARGET_DIR` |
| `inventory/source-pin.txt` | Upstream/submodule/lock pins |
| `inventory/native-prerequisites.txt` | Toolchain + vcpkg + commands |
| `inventory/flutter-gated-seams.md` | Flutter/Sciter-gated inventory |
| `inventory/hs-symbols.txt` | Real exported symbols |
| `inventory/dylib-deps.txt` | Real dylib load commands |
| `inventory/dylib-no-sciter-flutter.txt` | Absence of sciter/flutter |
| `inventory/harness-run.txt` | Full harness output |
| `README.md` | Lab overview + reproduce steps |
| `BUILD-REPORT.md` | This report |

## Coordinator review and reproduction

Fresh `scripts/build-macos-arm64.sh /tmp/hs-engine-source` passed source,
submodule, lock and patched-file hash checks, nine Rust tests, the actual
cdylib build and 45 C harness checks. Full RD02 remains incomplete.
A fresh isolated clone at the recorded source/submodule pins accepted the
retained patch; all four resulting file SHA-256 hashes matched. Wrong source
HEAD, wrong submodule HEAD and changed Cargo.lock were each refused.

The listener harness checks lsof exit status directly instead of a pipeline
whose wc exit could hide a missing lsof command. An unavailable listener check
fails the harness. Generation exhaustion closes and drops an owned inert
Session before refusing replacement work; teardown does not depend on another
successful increment. Observability counters saturate. The maximum peer-ID
macro comes from the actual Rust source constant.

`UPSTREAM-LICENCE` retains the exact license file from the pinned RustDesk
checkout. The derivative patch and linked laboratory library carry that
upstream licensing context; hs-core's own package metadata is not a license
for RustDesk. Dependency/codec redistribution review and final SPDX choices
remain RD01 work. No engine binary is distributed with either native app.
