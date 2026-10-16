#!/bin/sh
# Build and run the C# wrapper runtime check against hs_webrtc_shared.
# Uses the present .NET SDK when available; fails closed otherwise.
# Usage: ./scripts/run-csharp-runtime.sh <webrtc-upstream-root> <out-name>
set -eu
ROOT="${1:?usage: run-csharp-runtime.sh <webrtc-upstream-root> <out-name>}"
OUT="${2:-out-arm64}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/webrtc-checkout/src"
if [ -x /tmp/hs-toolchain/dotnet/dotnet ]; then
    export PATH="/tmp/hs-toolchain/dotnet:$PATH"
    export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-/tmp/hs-toolchain/dotnet-home}"
elif ! command -v dotnet >/dev/null 2>&1; then
    echo "error: dotnet not found (checked /tmp/hs-toolchain/dotnet/dotnet and PATH)" >&2
    exit 1
fi
export DYLD_LIBRARY_PATH="$SRC/out/$OUT${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export DYLD_FALLBACK_LIBRARY_PATH="$SRC/out/$OUT"
PROJ="$HERE/native/runtime/csharp_runtime_check.csproj"
echo "==> dotnet build/run $PROJ"
dotnet build "$PROJ" -c Release -v q
dotnet run --project "$PROJ" -c Release --no-build
