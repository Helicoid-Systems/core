#!/bin/sh
# Compile and run the Swift wrapper runtime check against libhs_webrtc_shared.
# Usage: ./scripts/run-swift-runtime.sh <webrtc-upstream-root> <out-name>
set -eu
ROOT="${1:?usage: run-swift-runtime.sh <webrtc-upstream-root> <out-name>}"
OUT="${2:-out-arm64}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/webrtc-checkout/src"
DYLIB="$SRC/out/$OUT/libhs_webrtc_shared.dylib"
RT=$(dirname "$(find "$SRC/third_party/llvm-build" -name 'libclang_rt.asan_osx_dynamic.dylib' 2>/dev/null | head -1)")
export DYLD_LIBRARY_PATH="$SRC/out/$OUT${DYLIB:+${RT:+:$RT}}"
BIN="${SWIFT_RUNTIME_OUT:-/tmp/hs-webrtc-swift-runtime}"
swiftc -O \
  -import-objc-header "$HERE/native/hs_webrtc.h" \
  -L "$SRC/out/$OUT" -lhs_webrtc_shared \
  -Xlinker -rpath -Xlinker "$SRC/out/$OUT" \
  -o "$BIN" \
  "$HERE/native/wrappers/HsWebRtcWrapper.swift" \
  "$HERE/native/runtime/swift_runtime_check.swift"
echo "==> running $BIN"
"$BIN"
