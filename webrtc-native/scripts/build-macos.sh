#!/bin/sh
# Bounded macOS build of the E01 WebRTC bridge + harness against the pinned
# Google checkout. Uses depot_tools GN/Ninja only. No system mutation.
#
# Usage:
#   ./scripts/build-macos.sh <webrtc-upstream-root> <out-name> [target_cpu]
set -eu
ROOT="${1:?usage: build-macos.sh <webrtc-upstream-root> <out-name> [target_cpu]}"
OUT="${2:?out name required}"
CPU="${3:-arm64}"

HERE=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/webrtc-checkout/src"
DEPOT="$ROOT/depot_tools"
NATIVE="$HERE/native"
BUILD_DIR="$SRC/hs_native_build"

if [ ! -d "$SRC" ]; then
    echo "error: pinned checkout not found at $SRC" >&2
    exit 1
fi
if [ ! -d "$DEPOT" ]; then
    echo "error: depot_tools not found at $DEPOT" >&2
    exit 1
fi

# Prefer the checkout's pinned CIPD gn/ninja over depot_tools shims.
GNBIN=""
NINJABIN=""
if [ -x "$SRC/buildtools/mac/gn" ]; then
    GNBIN="$SRC/buildtools/mac/gn"
elif [ -x "$SRC/buildtools/mac_arm64/gn" ]; then
    GNBIN="$SRC/buildtools/mac_arm64/gn"
fi
if [ -x "$SRC/third_party/ninja/ninja" ]; then
    NINJABIN="$SRC/third_party/ninja/ninja"
fi
if [ -z "$GNBIN" ] || [ -z "$NINJABIN" ]; then
    echo "error: pinned gn/ninja not found in checkout" >&2
    exit 1
fi

python3 "$HERE/scripts/gen_header.py" \
    "$NATIVE/hs_webrtc_bridge.cpp" "$NATIVE/hs_webrtc.h"
[ $? -eq 0 ] || { echo "error: gen_header.py failed" >&2; exit 1; }

# Deterministic pin verification + GN target staging/registration.
python3 "$HERE/scripts/setup-gn-target.py" "$ROOT"
[ $? -eq 0 ] || { echo "error: setup-gn-target.sh failed" >&2; exit 1; }

# Real invoked compiler provenance (Chromium clang from the checkout), plus
# host metadata recorded separately.
CHROMIUM_CLANG="$SRC/third_party/llvm-build/Release+Asserts/bin/clang++"
if [ ! -x "$CHROMIUM_CLANG" ]; then
    echo "error: pinned Chromium clang++ missing at $CHROMIUM_CLANG" >&2
    exit 1
fi
CLANG_VER=$("$CHROMIUM_CLANG" --version | head -1)
LLVM_COMMIT=$(echo "$CLANG_VER" | sed -n 's/.*\([0-9a-f]\{40\}\).*/\1/p')
LLVM_SUB=$(sed -n "s/^CLANG_REVISION = '\([^']*\)'/\1/p" "$SRC/tools/clang/scripts/update.py" | head -1)
{
    echo "webrtc_src_commit=$(git -C "$SRC" rev-parse HEAD)"
    echo "depot_tools_commit=$(git -C "$DEPOT" rev-parse HEAD)"
    echo "target_cpu=$CPU"
    echo "invoked_compiler_path=$CHROMIUM_CLANG"
    echo "invoked_compiler_version=$CLANG_VER"
    echo "llvm_commit=$LLVM_COMMIT"
    echo "llvm_package_version=$LLVM_SUB"
    echo "gn_bin=$GNBIN"
    echo "gn_version=$("$GNBIN" --version | head -1)"
    echo "ninja_bin=$NINJABIN"
    echo "ninja_version=$("$NINJABIN" --version)"
    echo "macos_sdk=$(xcrun --show-sdk-version 2>/dev/null || true)"
    echo "gn_args=is_debug=false is_component_build=false symbol_level=0 target_cpu=$CPU"
    echo "host_metadata_clang=$(clang++ --version | head -1)"
} > "$HERE/inventory/build-provenance-$OUT.txt"

export PATH="$DEPOT:$PATH"

if [ "$CPU" = "x86_64" ]; then
    ARGS="is_debug=false is_component_build=false symbol_level=0 target_cpu=\"x64\""
else
    ARGS="is_debug=false is_component_build=false symbol_level=0 target_cpu=\"$CPU\""
fi

"$GNBIN" gen "$SRC/out/$OUT" --root="$SRC" --args="$ARGS"
[ $? -eq 0 ] || { echo "error: gn gen failed" >&2; exit 1; }
"$NINJABIN" -C "$SRC/out/$OUT" hs_native_build:hs_webrtc_harness hs_native_build:hs_webrtc_shared
[ $? -eq 0 ] || { echo "error: ninja build failed" >&2; exit 1; }

# Expected checked-in GN output names (fail closed if missing).
HARNESS_BIN=$(find "$SRC/out/$OUT" -name 'hs_webrtc_harness' -type f | head -1)
DYLIB=$(find "$SRC/out/$OUT" -name 'libhs_webrtc_shared.dylib' -type f | head -1)
[ -n "$HARNESS_BIN" ] || { echo "error: hs_webrtc_harness missing" >&2; exit 1; }
[ -n "$DYLIB" ] || { echo "error: libhs_webrtc_shared.dylib missing" >&2; exit 1; }
echo "built harness=$HARNESS_BIN"
echo "built dylib=$DYLIB"
{
  echo "harness_path=$HARNESS_BIN"
  shasum -a 256 "$HARNESS_BIN"
  echo "dylib_path=$DYLIB"
  shasum -a 256 "$DYLIB"
} > "$HERE/inventory/built-artifacts-$OUT.txt"

if [ "$CPU" = "arm64" ] || [ "$CPU" = "arm64e" ]; then
    echo "==> running $HARNESS_BIN"
    "$HARNESS_BIN"
    [ $? -eq 0 ] || { echo "error: harness failed" >&2; exit 1; }
fi
