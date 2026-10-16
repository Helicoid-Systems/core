# Bounded Windows x64 build of the E01 WebRTC bridge + shared library + harness.
# Uses only the checkout's pinned CIPD gn/ninja (no system fallback). Records
# actual invoked compiler provenance. Validates every external program exit.
param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][string]$Out,
    [string]$Cpu = "x64"
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $PSScriptRoot
$Src = Join-Path $Root "webrtc-checkout/src"
$Native = Join-Path $Here "native"

if (-not (Test-Path $Src)) { throw "pinned checkout not found at $Src" }

python (Join-Path $Here "scripts/gen_header.py") (Join-Path $Native "hs_webrtc_bridge.cpp") (Join-Path $Native "hs_webrtc.h")
if ($LASTEXITCODE -ne 0) { throw "gen_header.py failed" }

# Deterministic pin verification + GN target staging/registration via the
# portable Python owner (no dependency on which bash is on PATH; WSL
# System32 bash is not used).
python (Join-Path $Here "scripts/setup-gn-target.py") $Root
if ($LASTEXITCODE -ne 0) { throw "setup-gn-target.py failed" }

# Pinned CIPD gn/ninja only. No silent system fallback.
$Gn = Join-Path $Src "buildtools/win/gn.exe"
if (-not (Test-Path $Gn)) { $Gn = Join-Path $Src "buildtools/win/gn" }
$Ninja = Join-Path $Src "third_party/ninja/ninja.exe"
if (-not (Test-Path $Ninja)) { $Ninja = Join-Path $Src "third_party/ninja/ninja" }
if (-not (Test-Path $Gn)) { throw "pinned gn missing at buildtools/win (no system fallback)" }
if (-not (Test-Path $Ninja)) { throw "pinned ninja missing at third_party/ninja (no system fallback)" }

# Real invoked compiler (clang-cl from the checkout) - fail closed if absent.
$ChromiumClang = Join-Path $Src "third_party/llvm-build/Release+Asserts/bin/clang-cl.exe"
if (-not (Test-Path $ChromiumClang)) {
    $ChromiumClang = Join-Path $Src "third_party/llvm-build/Release+Asserts/bin/clang++.exe"
}
if (-not (Test-Path $ChromiumClang)) { throw "pinned Chromium clang-cl missing" }
$ClangVer = & $ChromiumClang --version 2>&1 | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw "compiler --version failed" }

& $Gn gen (Join-Path $Src "out/$Out") --root=$Src --args="is_debug=false is_component_build=false symbol_level=0 target_cpu=`"$Cpu`""
if ($LASTEXITCODE -ne 0) { throw "gn gen failed" }
& $Ninja -C (Join-Path $Src "out/$Out") hs_native_build:hs_webrtc_harness hs_native_build:hs_webrtc_shared
if ($LASTEXITCODE -ne 0) { throw "ninja build failed" }

$Harness = Get-ChildItem -Recurse (Join-Path $Src "out/$Out") -Filter hs_webrtc_harness.exe | Select-Object -First 1
$Dll = Get-ChildItem -Recurse (Join-Path $Src "out/$Out") -Filter hs_webrtc_shared.dll | Select-Object -First 1
if (-not $Harness) { throw "hs_webrtc_harness.exe missing" }
if (-not $Dll) { throw "hs_webrtc_shared.dll missing" }

$Prov = Join-Path $Here "inventory/build-provenance-$Out.txt"
@(
    "webrtc_src_commit=$(git -C $Src rev-parse HEAD)"
    "depot_tools_commit=$(git -C (Join-Path $Root 'depot_tools') rev-parse HEAD)"
    "target_cpu=$Cpu"
    "invoked_compiler_path=$ChromiumClang"
    "invoked_compiler_version=$ClangVer"
    "gn_bin=$Gn"
    "gn_version=$(& $Gn --version | Select-Object -First 1)"
    "ninja_bin=$Ninja"
    "ninja_version=$(& $Ninja --version)"
    "gn_args=is_debug=false is_component_build=false symbol_level=0 target_cpu=$Cpu"
    "harness_path=$($Harness.FullName)"
    "harness_sha256=$((Get-FileHash $Harness.FullName -Algorithm SHA256).Hash.ToLower())"
    "dll_path=$($Dll.FullName)"
    "dll_sha256=$((Get-FileHash $Dll.FullName -Algorithm SHA256).Hash.ToLower())"
) | Set-Content -Encoding ascii $Prov

Write-Host "built harness=$($Harness.FullName)"
Write-Host "built dll=$($Dll.FullName)"
