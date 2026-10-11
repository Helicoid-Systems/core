#!/bin/sh
# Compile and run the Swift and C# wrapper lifetime checks against the real
# generated C ABI (linked cdylib). Host-dependent: skips what this host cannot
# compile. Windows native ABI execution stays Not Verified.
#
# Usage:
#   ./scripts/check-wrappers.sh <path-to-engine-build-dir>
#
# Expects <build>/debug/liblibrustdesk.dylib (or .so) and native/hs_native.h.

set -eu

BUILD="${1:-/tmp/hs-engine-build}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
WRAP="$HERE/native/wrappers"
OUT="${WRAPPER_OUT:-/tmp/hs-production-20261010}"
ABI="$HERE/native/hs_native.h"
LIB=""

if [ -f "$BUILD/debug/liblibrustdesk.dylib" ]; then
    LIB="$BUILD/debug/liblibrustdesk.dylib"
elif [ -f "$BUILD/debug/liblibrustdesk.so" ]; then
    LIB="$BUILD/debug/liblibrustdesk.so"
else
    echo "error: no hs_native cdylib under $BUILD/debug" >&2
    exit 1
fi

echo "==> wrapper contract drift check"
python3 "$HERE/scripts/check-wrapper-contract.py"

echo "==> Swift wrapper compile + lifetime check (strict Swift6 concurrency)"
if command -v swiftc >/dev/null 2>&1; then
    # Strict concurrency complete + warnings-as-errors. A Swift6 warning is a
    # hard failure here; there is no soft-concurrency escape hatch.
    swiftc -O \
        -strict-concurrency=complete \
        -warnings-as-errors \
        -import-objc-header "$ABI" \
        "$LIB" \
        -Xlinker -rpath -Xlinker "$(dirname "$LIB")" \
        -o "$OUT/swift-lifetime-check" \
        "$WRAP/HsNativeWrapper.swift" \
        "$WRAP/swift_lifetime_check.swift"
    "$OUT/swift-lifetime-check"
else
    echo "skip: swiftc unavailable on this host"
fi

echo "==> C# wrapper compile + lifetime check"
if command -v dotnet >/dev/null 2>&1; then
    PROJ="$OUT/csharp-lifetime-check"
    rm -rf "$PROJ"
    mkdir -p "$PROJ"
    cat > "$PROJ/csharp-lifetime-check.csproj" << EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>disable</Nullable>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <AssemblyName>csharp-lifetime-check</AssemblyName>
    <RootNamespace>Helicoid.EngineLab.Check</RootNamespace>
  </PropertyGroup>
</Project>
EOF
    cp "$WRAP/HsNativeWrapper.cs" "$PROJ/"
    cp "$WRAP/csharp_lifetime_check.cs" "$PROJ/"
    ln -sf "$LIB" "$PROJ/liblibrustdesk.dylib"
    ln -sf "$LIB" "$PROJ/librustdesk.dylib"
    # Capture full output and preserve the real exit code. Do NOT pipe through
    # tail (that masks the pipeline exit under /bin/sh set -e).
    CSHARP_LOG="$OUT/csharp-lifetime-check.log"
    set +e
    (cd "$PROJ" && dotnet run -c Release --nologo) > "$CSHARP_LOG" 2>&1
    CSHARP_RC=$?
    set -e
    tail -40 "$CSHARP_LOG"
    if [ "$CSHARP_RC" -ne 0 ]; then
        echo "error: C# lifetime check failed (exit $CSHARP_RC); full log: $CSHARP_LOG" >&2
        exit "$CSHARP_RC"
    fi
else
    echo "skip: dotnet unavailable on this host"
fi

echo "done."
