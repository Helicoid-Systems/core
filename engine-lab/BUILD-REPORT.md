# BUILD-REPORT — engine-lab ABI2 lifetime prerequisites

Date: 11 October 2026
Agent: MiMo (xiaomi/mimo-v2.6-pro), bounded atomic publication task
Owned path: `modules/core/engine-lab/**` + `/tmp/hs-engine-source/**`
Upstream pin: `001b0e96173cea4e49f9f7a67bea95a177dd1de3`
(hbb_common `229b904508364c8997aad0fb5af57effac859f60`)
Cargo.lock sha256: `b7ac324e15b5ae6f6ed7fd88bb8bc65633ca53b7cb1ad257600bdd6d719f234b`
(unchanged; all builds use `--locked`)

## Result

**PARTIAL — every finding from
`engine-native-concurrency-review.md` and the additional source findings in
`engine-atomic-publication-task.md` is repaired and proved by linked
regressions on arm64. Windows native ABI and real media/control remain
NOT VERIFIED. Selected OSS route remains FAILED/CLOSED. Full RD02 NOT PASSED.**

## Defect repairs

### 1. Native `hs_viewer_set_lifecycle_cb` atomicity (`src/hs_native.rs`)

**Before:** `c.state()` obtained and released the state mutex *before*
`handler()` / life-queue mutation. Another thread could complete
`request_close`+`drain` between the check and publication, so a foreign root
could publish after close/drain. The "atomically" claim was false.

**Now:** the state guard is held through handler lookup and life-queue
mutation under a consistent lock order `state` → `session` → `life` (the same
order `request_close` / `prepare` use). `request_close` cannot interleave
between the Prepared check and `q.cb = cb` publication. Concurrent
register-vs-close/drain is covered by a real race test that asserts the
result status and that no root remains after drain.

### 2. Native `hs_viewer_request_close` delayed transition (`src/hs_native.rs`)

**Before:** state stayed `Created`/`Prepared` until *after* CLOSING queue,
cancellation, and session drop. Concurrent/re-entrant close could bump the
generation twice and enqueue duplicate CLOSING.

**Now:** under the initial state lock the call (a) bumps the generation,
(b) takes the session exactly once (`slot.take()`), (c) drops the session so
the destructor completes *before* `Closing`/`Closed` is published, then
(d) sets the new state. Cancellation and the CLOSING signal run outside the
state lock. Drain cannot observe quiescence mid-drop: `worker_done` still
requires observed cancellation, and cancellation happens after the drop.

`hs_viewer_drain` phase 3 now joins the worker **without** the state gate
(previously `join()` ran under the state lock — a latent deadlock against a
callback re-entering `request_close`).

### 3. Lifecycle delivery worker vs poll (`src/hs_native.rs`)

**Before:** the worker popped `LifeQueue` even when `cb = None` and silently
discarded events, racing `hs_viewer_poll_life`.

**Now:** the worker only pops when a callback is registered. Events queued
with no callback are retained for `hs_viewer_poll_life`.
`LifeQueue::pending()` counts only callback-delivery work (plus in-flight),
so retained poll events cannot hang close/drain. Poll and callback modes
hand off cleanly: clearing the callback returns the queue to poll retention.

### 4. Swift registration lifetime (`HsNativeWrapper.swift`)

**Before:** `Unmanaged.passRetained(box)` ran *before* `try pinnedCtx()`
outside any cleanup handler — a failed pin after free leaked each
registration. `unpinCtx()` ran *before* root publication. A publication that
lost a drain race left the root for a drain that had already completed.

**Now:**
- One pin lifetime covers retain + native call + root publication
  (`let ptr = try pinnedCtx()` first; `defer { unpinCtx() }` last).
- A failed pin never creates a retained root (post-free registration leaks
  nothing — tested).
- Failed native publication frees the unpublished root exactly once.
- Publication that observes `drained`/`freed` releases the root under proven
  quiescence (worker already joined) and throws `STATE` — it never silently
  leaves the root for a drain that already completed.
- No `do`/`catch` around the non-throwing C call.
- `init` validates `hs_abi_version() == 2` **before** `hs_engine_ctx_new`.

### 5. C# registration publication (`HsNativeWrapper.cs`)

**Before:** `HandlePin` (Monitor + `DangerousAddRef`) was disposed before
`reg.Published` / `_registrations.Add`. Drain/free could interleave
bookkeeping. Per-registration `ThunkHandle` re-rooted a static trampoline.

**Now:**
- Native call **and** registration publication run under the same wrapper
  gate (`lock (_gate)` + `HandlePin`). Drain's `_drained` write also needs
  `_gate`, so it cannot slip between accept and bookkeeping.
- The gate is released before the native drain wait (unchanged; required).
- Unpublished failure vs native-accepted root is explicit: the catch path
  frees `UserHandle` only when `!reg.Published`.
- Failed `DangerousAddRef` still releases the Monitor (`HandlePin` ctor).
- The static trampoline is permanently rooted; the redundant per-registration
  `ThunkHandle` is removed.
- Registrations are bounded to the real native limit
  (`MaxRegistrations = 1 + HS_MAX_LIFE_RETIRED = 9`).
- `hs_abi_version` is validated against `ExpectedAbiVersion = 2` before
  context allocation.

### 6. ABI + descriptor layout proof (not self-referential)

Constructing a managed/side descriptor does **not** prove native
marshalling. Linked checks now assert the real ABI:

| Check | Evidence |
| --- | --- |
| Linked `hs_abi_version == 2` | C harness, Swift, C# |
| C `sizeof(hs_frame_desc) == 48` | C harness `sizeof` |
| C `offsetof` viewer/layout/interaction/sequence = 24/28/32/40 | C harness |
| Swift `MemoryLayout` size/stride/offsets vs C-imported `hs_frame_desc` | `swift_lifetime_check` |
| C# `Marshal.SizeOf` == 48, `Marshal.OffsetOf` Sequence/ViewerGeneration/LayoutGeneration/InteractionGeneration = 40/24/28/32 | `csharp_lifetime_check` |

### 7. `check-wrapper-contract.py` real checks

**Before:** names/comments only; a block claimed to forbid mocks but only
`pass`ed; no C# type/order comparison; no negative test.

**Now:**
- Exact C `hs_frame_desc` (type, name, order) vs expected ABI contract.
- Exact C# `HsFrameDesc` type/order (`uint`/`ulong` sequence).
- Exact Swift `HsFrameDesc` type/order (`UInt32`/`UInt64` sequence).
- P/Invoke signature patterns for the bindings the wrappers need.
- Same-gate publication: `lock (_gate)` → native call → `_registrations.Add`
  ordering inside `SetLifecycleHandler` (method-body analysis, not a comment
  match).
- Real mock detector: strips comments, rejects mock implementation types.
- Negative drift test on **temp copies only**: mutating C# field type or
  order must fail; live artifacts are never permanently modified.
- Script failures propagate (no tail masking).

### 8. README Intel proof corrected

The claim of "the same 18 exports" referred to the old pre-callback ABI1
source. Current ABI2 + laboratory proof hooks export **27** `_hs_*` symbols.
README now states 27 and labels `inventory/intel-build-proof.md` as a
**historical** record, with current Intel compile/link in this report.

## Regression tests added

| Area | Test | Result |
| --- | --- | --- |
| Native parallel close | `parallel_close_requests_one_generation_bump_one_closing` (8 threads) | PASS |
| Native register-vs-close | `register_racing_close_drain_never_publishes_after_close` (16 iters) | PASS |
| Native poll retention | `polling_mode_retains_events_under_worker_scheduling` | PASS |
| Native poll/callback handoff | `callback_and_poll_modes_hand_off_cleanly` | PASS |
| Native close-vs-prepare | `close_racing_prepare_is_consistent` | PASS |
| C harness sizeof/offsetof | linked C ABI layout | PASS |
| C harness poll mode | events retained under worker scheduling | PASS |
| C harness parallel close | one generation bump / one CLOSING | PASS |
| C harness register-after-close | refused in CLOSING and after drain | PASS |
| C harness bounded roots | `HS_MAX_LIFE_RETIRED` enforced | PASS |
| Swift ABI + MemoryLayout | linked ABI2 + size/offsets vs C-imported type | PASS |
| Swift post-free registration | no retained-root leak | PASS |
| Swift parallel close | exactly one CLOSING | PASS |
| Swift register-vs-close (8 iters) | no orphan root after racing drain | PASS |
| Swift bounded roots | stop at `maxRegistrations` (9) | PASS |
| Swift polling mode | events retained | PASS |
| C# ABI + Marshal layout | size 48 / offsets 40,24,28,32 | PASS |
| C# post-free registration | refused, no leak | PASS |
| C# parallel close | exactly one CLOSING | PASS |
| C# register-vs-close (8 iters) | no orphan root after racing drain | PASS |
| C# bounded roots | stop at `MaxRegistrations` | PASS |
| C# polling mode | events retained; drain does not hang | PASS |
| C# forced GC + in-flight replacement | old completes, new gets next | PASS (pre-existing) |
| C# abandoned wrapper + delayed callback + forced GC | no UAF | PASS (pre-existing) |
| Swift6 strict concurrency | `-strict-concurrency=complete -warnings-as-errors` | PASS (0 warnings) |

No new exported fixture functions were added. `hs_debug_queue_life` remains
the pre-existing laboratory proof hook (not media, not authority).

## Commands and results (fresh this turn)

| Command | Exit | Result |
| --- | --- | --- |
| `python3 scripts/check-header.py` | 0 | patch source hash + generated header match (27 exports) |
| `sh scripts/check-source-pin.sh /tmp/hs-engine-source` | 0 | HEAD / submodule / lock pins OK |
| `shasum -a 256 -c inventory/patched-files.sha256` | 0 | all four patched files OK |
| `python3 scripts/check-wrapper-contract.py` | 0 | order/type/width + P/Invoke + ABI gate + same-gate + negative drift |
| `cargo test --locked --lib --features hs-native hs_native` | 0 | **32 passed, 0 failed** |
| `cc … harness.c` + run (arm64) | 0 | **PASSED (0 failures)** |
| `swiftc -strict-concurrency=complete -warnings-as-errors` + run | 0 | **PASSED (0 failures)** |
| `dotnet run` (exit preserved, no tail mask) | 0 | **PASSED (0 failures)** |
| `cargo build --locked --lib --features hs-native --target x86_64-apple-darwin` | 0 | Intel dylib, **27** `_hs_*` exports |
| `cc -arch x86_64 … harness.c <intel dylib>` | 0 | Mach-O x86_64 linked |
| Intel harness run | 127 | `bad CPU type` — Rosetta absent (expected) |

Patched-file SHA-256 (`inventory/patched-files.sha256`):

```
b0627b7e9c275ed6763060b2e2cac9c95c7920fe6dd3ea31889c1cbed2ebe254  Cargo.toml
154ca923835c11149a5d5c6f3d1147d42e04cc8a00342a5359139c16052305d3  src/client.rs
4b3d3a904e99db4eb764bdac3479c761a3070ed5b1387e6d39c10a795a0076c3  src/hs_native.rs
7142685502d5142f0f399a201c3af135a0dd5f520e890044d6307380027094d1  src/lib.rs
```

Profile: `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
CARGO_INCREMENTAL=0`. Header: 27 exports (ABI2 + `hs_debug_queue_life` /
`hs_debug_inject_panic` laboratory proof hooks — not media, not authority).

## Intel: current vs historical

| Artifact | Status |
| --- | --- |
| **Current** Intel compile+link of finalized patch | **VERIFIED** (this turn; 27 exports; harness Mach-O x86_64) |
| **Current** Intel execution | **NOT VERIFIED** (Rosetta absent; `bad CPU type`) |
| **Historical** 18-export Intel proof (`inventory/intel-build-proof.md`) | Retained as a pre-callback ABI1 record; **not** current |

## Source compilation vs linked/runtime vs real media

| Layer | Status | Evidence |
| --- | --- | --- |
| Source compilation (arm64, `--locked`) | **VERIFIED** | cargo check/build/test exit 0 |
| Rust unit tests (32) | **VERIFIED** | 32/32 passed |
| Linked C harness | **VERIFIED** | PASSED (0 failures) |
| Swift6 strict concurrency + lifetime | **VERIFIED** | PASSED (0 failures, warnings-as-errors) |
| C# wrapper (GCHandle/GC/abandonment/layout) | **VERIFIED** | PASSED (0 failures) |
| Generated-contract drift + negative | **VERIFIED** | `check-wrapper-contract.py` exit 0 |
| Intel compile/link (current patch) | **VERIFIED** | build 0, link 0, 27 exports |
| Intel execution | **NOT VERIFIED** | Rosetta absent |
| Windows native ABI execution | **NOT VERIFIED** | no Windows host/CI |
| Actual `client::secure_connection` enforcement | **NOT PROVED** | helpers not wired |
| Actual `server::identity_handshake` enforcement | **NOT PROVED** | helpers not wired |
| Channel binding from negotiated keys | **NOT AVAILABLE** | missing seam documented |
| Real media / control | **NOT IMPLEMENTED** | connect/observation UNAVAILABLE |
| Route adoption (OSS relay) | **FAILED / CLOSED** | stock licence_key/UUID pairing |
| Full RD02 / RD03 | **NOT PASSED** | admission, authority, adoption outstanding |

## Explicit non-claims

- Atomicity/registration repairs are **not** a secure route or media claim.
- `hs_debug_queue_life` / `hs_debug_inject_panic` are laboratory proof hooks
  only — not media, not authority, not fixture media grants.
- Helper-only handshake tests are **not** a secure route pass.
- Prepared ≠ admitted. No authority surface.
- No live media, capture, input, grants, or control.
- No hbbr deployment, no public routing, no alternate transport.
- Windows native ABI execution not verified.
- Intel execution not verified (compile/link only).
- No git commit/push. Coordinator owns publication.

## Coordinator verification and remaining lifetime limitation

The coordinator independently reproduced the arm64 check/test/build, all
32 Rust tests, linked C harness, strict Swift and C# lifetime checks, header
and negative wrapper drift checks, and the current Intel compile/link. The
sanitized session export contains only `xiaomi/mimo-v2.6-pro`. The checks
are recorded in `inventory/coordinator-2026-10-11.json`.

An abandoned undrained managed context intentionally retains its context and
registration roots to prevent use-after-free. Normal explicit close/drain/free
releases roots. This safe leak remains a resource-management limitation and
does not establish a production callback-lifetime or sustained-load gate.

## Remaining gates

1. **Wire the fail-closed helpers into `client::secure_connection` and
   `server::identity_handshake`** and prove the actual transport/relay/
   admission gate (RD03).
2. **Sealed HS endpoint admission adapter** — production source for
   layout/interaction fences (currently fixture-only).
3. **Channel binding from negotiated encryption state** once a real secured
   `Stream` is admitted.
4. **Windows native ABI execution** — native CI or actual host.
5. **Intel/Rosetta execution** if a Rosetta-capable host becomes available.
6. **Real media path (RD04)** and full RD02/RD03.

## Files owned this turn

Under `modules/core/engine-lab/**`:

- `native/wrappers/HsNativeWrapper.swift` — pin lifetime, ABI gate, post-drain
  release-under-quiescence
- `native/wrappers/HsNativeWrapper.cs` — same-gate publication, bounded roots,
  static trampoline only, ABI gate
- `native/wrappers/swift_lifetime_check.swift` — ABI/layout/race/bound/poll
  regressions
- `native/wrappers/csharp_lifetime_check.cs` — Marshal layout/ABI/race/bound/
  poll regressions
- `native/harness.c` — sizeof/offsetof, poll retention, parallel close,
  register-after-close, bounded roots
- `scripts/check-wrapper-contract.py` — order/type/width, P/Invoke, same-gate,
  real mock detector, negative drift on temp copies
- `scripts/check-wrappers.sh` — Swift6 `-strict-concurrency=complete
  -warnings-as-errors`
- `patches/0001-hs-native-bridge.patch` — refreshed `hs_native.rs` section
- `inventory/patched-files.sha256` — updated `src/hs_native.rs` hash
- `inventory/hs-symbols.txt` — current 27 exports
- `README.md` — Intel claim corrected; atomicity claims added

Plus scratch upstream `/tmp/hs-engine-source/src/hs_native.rs` and this report
under `/tmp/hs-production-20261010/`. Source/dependency pins unchanged. No
other worker's paths were touched. No commits, no pushes.

---

# Historical engine-lab baseline (10 October 2026)

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
| Frame ownership | **Verified (fixture + ABI)** | owned handle, checked bounds, exact release, latest-slot, gen/seq, late disposal, outstanding-after-close |
| Async cancellation / worker drain | **Verified (bounded)** | non-blocking close, `drain(timeout_ms)`, free-after-drain |
| macOS x86_64 build | **Cross-check only** | `cargo check --target x86_64-apple-darwin` exit 0; no execution |
| Windows x64 build | **NOT RUN** | Next CI; not claimed |
| Full RD02 Pass | **NOT PASSED** | Real media, channel binding, route adoption, cross-arch outstanding |

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

1. **Frame ownership seam (RD02 remaining pass item).** Owned frame
   handle/descriptors, checked geometry, exact release, latest-frame
   buffering, generation/sequence, late-frame disposal, outstanding-after-close
   are implemented and proved (fixture lifetime checks + C ABI). Real media
   end-to-end still needs RD04.
2. **Async close/cancel/drain.** Implemented: non-blocking close, bounded
   `drain(timeout_ms)`, free refused until drained. Lifecycle callback
   contract documented (bounded queue, worker-thread rules).
3. **Channel binding from negotiated encryption state.** Export stays
   `UNAVAILABLE`; missing seam documented (need `Stream::is_secured()` +
   `Encrypt` key material bound to HS admission).
4. **Selected-route adoption gate FAILED.** Stock global `licence_key`/UUID
   pairing in rustdesk-server 1.1.16 does not establish Helicoid
   per-allocation authority. Media/control enablement stopped. No hbbr
   deployment.
5. **Make `sciter-rs` optional.** Actual blocked symbols:
   `src/ui.rs` (whole module), `src/client/file_trait.rs` (`sciter::Value` in
   `read_dir`), `src/platform/delegate.rs` (`sciter::Host`), `src/keyboard.rs`
   (`crate::ui::CUR_SESSION`). Need a trait-object seam before `sciter` can
   leave the dependency graph.
6. **macOS x86_64 + Windows x64 builds.** Intel cross-check compiles
   (`cargo check --target x86_64-apple-darwin`); execution unverified
   (Rosetta absent). Windows needs the WinUI/vcpkg toolchain in CI.
7. **Remote init / media / authority (B03).** `hs_viewer_connect` and
   `hs_viewer_begin_observation` are explicit `UNAVAILABLE` stubs. Do not
   reuse this lab ABI as an authority surface.
8. **RD03 authority/route** is the next executable frontier after this
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

## Intel macOS cross-compilation, 10 October 2026

A separate MiMo task built the same reviewed patch from a fresh exact-pinned
checkout for `x86_64-apple-darwin`. Locked library check/build and the actual C
harness compile/link pass. The coordinator independently checked all four
patched-file hashes, source/submodule/lock pins, Mach-O architecture, 18 ABI
exports and dynamic dependencies. No Sciter/Flutter runtime dependency appears.

Intel test/harness execution is NOT VERIFIED: Rosetta is absent; the actual
execution attempt fails with Bad CPU type. No compatibility or full RD02 claim
follows from compilation. Exact commands/results are retained in
`inventory/intel-build-proof.md` and companion Intel evidence files.

The offline retained-patch source/hash and generated-header drift check now
runs in CI, separately from native compilation and harness execution.
