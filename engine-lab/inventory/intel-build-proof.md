# Intel macOS engine proof — reviewed inert hs-native seam

Date: 10 October 2026
Agent: isolated Intel engine proof (next to reviewed arm64 inert seam)
Owned paths: `modules/core/engine-lab/inventory/intel-*.txt|md`, `/tmp/hs-engine-intel-*`,
  `/tmp/hs-toolchain/vcpkg/installed/x64-osx` only.
Upstream pin: `001b0e96173cea4e49f9f7a67bea95a177dd1de3`
hbb_common: `229b904508364c8997aad0fb5af57effac859f60`
Cargo.lock sha256: `b7ac324e15b5ae6f6ed7fd88bb8bc65633ca53b7cb1ad257600bdd6d719f234b`
Product: Helicoid. Research laboratory snapshot. No adoption, license, or remote claim.

## Result

**PARTIAL — compile/check/build/link of the reviewed inert seam VERIFIED for
Intel macOS (x86_64-apple-darwin). Test/harness RUN NOT VERIFIED (Rosetta
absent). Full RD02 / B03 NOT PASSED.**

This is an independent Intel cross-compile proof next to the reviewed arm64
inert seam. It is **not** a remote, media, input, control, or interop proof.

## Distinction: check / build / link / run

| Stage | Command (abridged) | Exit | Evidence |
| --- | --- | --- | --- |
| check | `cargo check --locked --lib --features hs-native --target x86_64-apple-darwin` | **0** | Finished in 1m 35s; 123 upstream warnings (same class as arm64) |
| build (test bin) | `cargo test --locked --lib --features hs-native hs_native --target x86_64-apple-darwin` | **compile+link OK**; run **101** | Test binary produced; `could not execute process … Bad CPU type in executable (os error 86)` |
| build (cdylib) | `cargo build --locked --lib --features hs-native --target x86_64-apple-darwin` | **0** | `liblibrustdesk.dylib` (5 094 352 B) + `liblibrustdesk.a` |
| link (C harness) | `cc -std=c11 -Wall -Wextra -Werror -arch x86_64 … harness.c <intel dylib>` | **0** | `Mach-O 64-bit executable x86_64`; `otool -L` shows Intel dylib |
| run (tests) | execute `librustdesk-… hs_native` | **NOT RUN** | Bad CPU type — Rosetta absent |
| run (harness) | `/tmp/hs-engine-intel-harness` | **NOT RUN** (127) | `bad CPU type in executable` |

`arch -x86_64 /usr/bin/true` → exit 1 `Bad CPU type` (read-only probe; Rosetta
was **not** installed, per constraints).

## Exact commands and exits

Environment (all isolated; no Homebrew/global/Xcode/shell-config changes):

```
export CARGO_HOME=/tmp/hs-toolchain/cargo
export RUSTUP_HOME=/tmp/hs-toolchain/rustup
export VCPKG_ROOT=/tmp/hs-toolchain/vcpkg
export VCPKG_INSTALLED_ROOT=/tmp/hs-toolchain/vcpkg/installed
export VCPKG_BINARY_SOURCES=clear
export CARGO_TARGET_DIR=/tmp/hs-engine-intel-build
export PATH=/tmp/hs-toolchain/cargo/bin:/tmp/hs-toolchain/nasm/bin:/tmp/hs-toolchain/pkgconf/bin:$PATH
```

### 1. Fresh clone + pins (no dirty copy)

```
git clone --shared /tmp/hs-engine-source /tmp/hs-engine-intel-src          # exit 0
git -C /tmp/hs-engine-intel-src checkout 001b0e96173cea4e49f9f7a67bea95a177dd1de3   # exit 0
git clone --shared /tmp/hs-engine-source/libs/hbb_common \
          /tmp/hs-engine-intel-src/libs/hbb_common                          # exit 0
git -C /tmp/hs-engine-intel-src/libs/hbb_common checkout 229b904508364c8997aad0fb5af57effac859f60
sh scripts/check-source-pin.sh /tmp/hs-engine-intel-src                     # exit 0
sh scripts/apply-patch.sh /tmp/hs-engine-intel-src                          # exit 0
cd /tmp/hs-engine-intel-src && shasum -a 256 -c inventory/patched-files.sha256  # exit 0 (4 OK)
shasum -a 256 Cargo.lock
# b7ac324e15b5ae6f6ed7fd88bb8bc65633ca53b7cb1ad257600bdd6d719f234b
```

`/tmp/hs-engine-source` (arm64 patched tree) was not modified.

### 2. x64-osx vcpkg dependencies (isolated)

```
/tmp/hs-toolchain/vcpkg/vcpkg install aom:x64-osx libjpeg-turbo:x64-osx \
  libvpx:x64-osx libyuv:x64-osx opus:x64-osx \
  --overlay-ports=/tmp/hs-engine-intel-src/res/vcpkg \
  --x-install-root=/tmp/hs-toolchain/vcpkg/installed          # exit 0 (~1.2 min)
```

Installed x64-osx: aom 3.14.1, libjpeg-turbo 3.2.0, libvpx 1.15.2,
libyuv 1857, opus 1.5.2 — matches the known arm64 versions.
arm64-osx install left untouched.

### 3. Intel compile / build / link

```
cargo check  --locked --lib --features hs-native --target x86_64-apple-darwin  # exit 0
cargo test   --locked --lib --features hs-native hs_native --target x86_64-apple-darwin
#   compile+link of test binary OK; execute failed: Bad CPU type (os error 86)  # run exit 101
cargo build  --locked --lib --features hs-native --target x86_64-apple-darwin  # exit 0
python3 scripts/gen_header.py <src/hs_native.rs> /tmp/hs-engine-intel-evidence/hs_native.generated.h
#   exit 0; cmp identical to retained native/hs_native.h; retained header not mutated
cc -std=c11 -Wall -Wextra -Werror -arch x86_64 -I native \
   -o /tmp/hs-engine-intel-harness native/harness.c \
   /tmp/hs-engine-intel-build/x86_64-apple-darwin/debug/liblibrustdesk.dylib \
   -Wl,-rpath,/tmp/hs-engine-intel-build/x86_64-apple-darwin/debug           # exit 0
/tmp/hs-engine-intel-harness   # NOT RUN — bad CPU type (no Rosetta)
```

## Mach-O / export verification

See `intel-macho-verify.txt`. Summary:

- `liblibrustdesk.dylib` is `MH_MAGIC_64 X86_64 DYLIB` (true Intel, not universal).
- `LC_VERSION_MIN_MACOSX 10.12 / sdk 27.0`; no `LC_BUILD_VERSION`.
- 21 `LC_LOAD_DYLIB` — system frameworks only; **no sciter, no flutter**.
- 18 `_hs_*` text exports; names identical to the reviewed arm64 dylib.
- Generated header (scratch) **byte-identical** to retained `native/hs_native.h`
  (sha256 `cc998cc6cb104849bfbf21a775a284cd5791cc11fcec077028ea9a37adafaa25`).

## Source / toolchain integrity

| Item | Value |
| --- | --- |
| upstream HEAD | `001b0e96173cea4e49f9f7a67bea95a177dd1de3` |
| hbb_common HEAD | `229b904508364c8997aad0fb5af57effac859f60` |
| Cargo.lock sha256 | `b7ac324e15b5ae6f6ed7fd88bb8bc65633ca53b7cb1ad257600bdd6d719f234b` |
| patched-files.sha256 | 4/4 OK after apply |
| rustc / cargo | 1.99.0 / 1.99.0 |
| Intel std | present (`x86_64-apple-darwin` target installed) |
| vcpkg pin | `9e593bb18ea69cc5095e012465dcd675a822ed0d` |

## What is claimed / what is not

**Claimed (this turn):**
- Real Intel `x86_64-apple-darwin` **check** and **cdylib/staticlib build** of the
  reviewed inert `hs-native` seam with `--locked` and the retained patch.
- Real Intel **link** of the retained C harness against the Intel dylib.
- Mach-O arch, load-command, and `_hs_*` export verification for the Intel dylib.
- Header generator reproducibility on the Intel tree without mutating the retained header.

**Not claimed / not passed:**
- **Full RD02 not passed. B03 not passed.**
- Test/harness **execution** (Rosetta absent; binaries compiled and linked only).
- No owned-frames proof, no async-cancellation proof.
- No Windows proof.
- No media, no app interop, no remote-control, no input, no capture claim.
- `Prepared` remains inert (real Session owned); it is not admitted or ready-to-view.

## Out of scope (enforced)

No existing `engine-lab`/workflow edits (root owns reports/publication).
No core source/Cargo edits, no other repos, `/tmp/hs-engine-source` untouched,
no root plans/assets, no user config, no global installs, no commit/push,
no listener/capture/input/service/identities/production changes, no secrets.
