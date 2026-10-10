# Useful behavior currently gated behind Flutter / not exposed by hs_native

Inspected at upstream pin 001b0e96173cea4e49f9f7a67bea95a177dd1de3.
This is a source inventory for RD02 planning. It is NOT an implemented bridge
and NOT an authorization to expose these surfaces.

## Flutter-gated (`feature = "flutter"`) seams

| Seam | File | Notes |
| --- | --- | --- |
| `session_add` / `session_add_existed` / `session_start_` | `src/flutter.rs` | Session construction and start; currently reached through flutter_ffi |
| `session_add_sync` / `session_start_with_displays` | `src/flutter_ffi.rs` | Display-bound session start |
| `cursor_shapes` map | `src/ui_session_interface.rs` (`#[cfg(feature = "flutter")]`) | Per-session cursor shape cache |
| Texture render key | `src/flutter_ffi.rs` | Flutter texture registration |
| Connection manager IPC start | `src/flutter.rs` (`start_ipc`, `start_listen`) | CM UI bridge |
| Option/relay helpers | `src/ui_interface.rs` | Many `#[cfg(feature = "flutter")]` blocks |

## Sciter-gated (`not(feature = "flutter")` on desktop)

| Seam | File | Notes |
| --- | --- | --- |
| `pub mod ui` (Sciter host) | `src/ui.rs`, `src/ui/*` | Sciter window, event handler, chatbox |
| `sciter::Value` in file transfer | `src/client/file_trait.rs` | `read_dir` returns `sciter::Value` |
| `platform/delegate.rs` | uses `sciter::{Host, make_args}` | macOS delegate tied to Sciter host |

## Startup / hosting that must NOT run on viewer init

| Path | File | Behavior |
| --- | --- | --- |
| `crate::start_server` | `src/server.rs` | Starts IPC + TCP listeners |
| `core_main()` | `src/core_main.rs` | Spawns `start_server` unless `--no-server`; starts GUI |
| `start_os_service` | `src/platform` | OS service entry (endpoint hosting) |

## What hs_native proves instead

`src/hs_native.rs` is a deliberately narrow laboratory seam:

- explicit `hs_viewer_init` with bounded peer-id validation
- context lifetime (new / init / request-close / drain / free)
- panic containment at the ABI boundary
- generation fence on close for late-callback lifetime
- **no** media frames, capture, input, grants, or control
- **no** call into `start_server` / `core_main` / listeners

Future work that needs the Flutter-gated session machinery must land as a
separate reviewed seam (RD03+) with its own lifetime and authority contract.
Do not wrap `flutter_ffi` or the RustDesk application entrypoints.
