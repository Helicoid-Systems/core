#!/bin/sh
# Build the hs-native laboratory library on macOS arm64 and run the C harness.
#
# Usage:
#   ./scripts/build-macos-arm64.sh <path-to-patched-upstream-checkout>
#
# Prerequisites (isolated; no global installs):
#   CARGO_HOME=/tmp/hs-toolchain/cargo
#   RUSTUP_HOME=/tmp/hs-toolchain/rustup
#   PATH=/tmp/hs-toolchain/cargo/bin:/tmp/hs-toolchain/nasm/bin:/tmp/hs-toolchain/pkgconf/bin:$PATH
#   VCPKG_ROOT=/tmp/hs-toolchain/vcpkg
#   VCPKG_INSTALLED_ROOT=/tmp/hs-toolchain/vcpkg/installed
#
# Exports CARGO_TARGET_DIR (default /tmp/hs-engine-build) for every cargo
# invocation and for locating the produced cdylib. Builds with --locked
# against the upstream Cargo.lock. Does not update the lock.
#
# Regenerates native/hs_native.h from src/hs_native.rs via scripts/gen_header.py
# before compiling the harness, so header and exports cannot drift.

set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <path-to-patched-upstream-checkout>" >&2
    exit 2
fi

UPSTREAM="$1"
HERE=$(cd "$(dirname "$0")/.." && pwd)

# Isolated toolchain. Never touch the user's HOME or global installs.
export CARGO_HOME="${CARGO_HOME:-/tmp/hs-toolchain/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/tmp/hs-toolchain/rustup}"
export VCPKG_ROOT="${VCPKG_ROOT:-/tmp/hs-toolchain/vcpkg}"
export VCPKG_INSTALLED_ROOT="${VCPKG_INSTALLED_ROOT:-/tmp/hs-toolchain/vcpkg/installed}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/hs-engine-build}"
export PATH="${CARGO_HOME}/bin:/tmp/hs-toolchain/nasm/bin:/tmp/hs-toolchain/pkgconf/bin:${PATH}"

OUT_BIN="${HARNESS_OUT:-/tmp/hs-engine-harness}"
sh "$HERE/scripts/check-source-pin.sh" "$UPSTREAM"
(cd "$UPSTREAM" && shasum -a 256 -c "$HERE/inventory/patched-files.sha256")

echo "==> regenerate C header from hs_native.rs exports"
python3 "$HERE/scripts/gen_header.py" \
    "$UPSTREAM/src/hs_native.rs" \
    "$HERE/native/hs_native.h"

echo "==> cargo check --locked --lib --features hs-native"
cargo check --locked --lib --features hs-native --manifest-path "$UPSTREAM/Cargo.toml"

echo "==> cargo test --locked --lib --features hs-native hs_native"
cargo test --locked --lib --features hs-native hs_native --manifest-path "$UPSTREAM/Cargo.toml"

echo "==> cargo build --locked --lib --features hs-native"
cargo build --locked --lib --features hs-native --manifest-path "$UPSTREAM/Cargo.toml"

DYLIB="$CARGO_TARGET_DIR/debug/liblibrustdesk.dylib"
if [ ! -f "$DYLIB" ]; then
    echo "error: expected cdylib at $DYLIB" >&2
    exit 1
fi

echo "==> compile C harness (also type-checks the generated header)"
cc -std=c11 -Wall -Wextra -Werror \
    -I"$HERE/native" \
    -o "$OUT_BIN" \
    "$HERE/native/harness.c" \
    "$DYLIB" \
    -Wl,-rpath,"$CARGO_TARGET_DIR/debug"

echo "==> run C harness"
"$OUT_BIN"

echo "==> retained evidence under inventory/"
nm -gU "$DYLIB" | grep ' _hs_' | sort > "$HERE/inventory/hs-symbols.txt"
otool -L "$DYLIB" > "$HERE/inventory/dylib-deps.txt"
if grep -qiE 'sciter|flutter' "$HERE/inventory/dylib-deps.txt"; then
    echo "note: sciter/flutter appears in load commands" >&2
else
    echo "no sciter/flutter in dylib load commands" > "$HERE/inventory/dylib-no-sciter-flutter.txt"
fi

echo "done."
