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
$Depot = Join-Path $Root "depot_tools"
$Inventory = Join-Path $Here "inventory"

if ($Out -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw "Out must be a simple build directory name"
}
if ($Cpu -notin @("x64", "arm64")) {
    throw "Cpu must be x64 or arm64"
}

# Build runs in a fresh process: select hosted VS/Windows SDK while retaining
# checkout Chromium clang-cl, and prevent depot_tools self-update.
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = "0"
$env:DEPOT_TOOLS_UPDATE = "0"

$MissingPrerequisites = @()
if (-not (Test-Path $Src -PathType Container)) {
    $MissingPrerequisites += "pinned checkout directory $Src"
}
if (-not (Test-Path $Depot -PathType Container)) {
    $MissingPrerequisites += "pinned depot_tools directory $Depot"
}
if (-not (Test-Path (Join-Path $Native "hs_webrtc_bridge.cpp") -PathType Leaf)) {
    $MissingPrerequisites += "native bridge source $(Join-Path $Native 'hs_webrtc_bridge.cpp')"
}
if (-not (Test-Path $Inventory -PathType Container)) {
    $MissingPrerequisites += "native artifact inventory directory $Inventory"
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    $MissingPrerequisites += "Python command required by the pinned GN staging scripts"
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    $MissingPrerequisites += "Git command required for pin and build provenance"
}

# Refuse an incomplete gclient sync before regenerating the ABI header or
# staging the GN target. Report the whole missing set in one invocation.
foreach ($RelativePath in @(
    "build/config/gclient_args.gni",
    "tools/clang/scripts/update.py",
    "third_party/libyuv/include/libyuv/convert_argb.h",
    "third_party/abseil-cpp/absl/functional/any_invocable.h"
)) {
    $RequiredPath = Join-Path $Src $RelativePath
    if (-not (Test-Path $RequiredPath -PathType Leaf)) {
        $MissingPrerequisites += "pinned checkout input $RequiredPath"
    }
}

# Pinned CIPD gn/ninja only. No silent system fallback.
$Gn = Join-Path $Src "buildtools/win/gn.exe"
if (-not (Test-Path $Gn)) { $Gn = Join-Path $Src "buildtools/win/gn" }
$Ninja = Join-Path $Src "third_party/ninja/ninja.exe"
if (-not (Test-Path $Ninja)) { $Ninja = Join-Path $Src "third_party/ninja/ninja" }
if (-not (Test-Path $Gn -PathType Leaf)) {
    $MissingPrerequisites += "pinned gn at buildtools/win (no system fallback)"
}
if (-not (Test-Path $Ninja -PathType Leaf)) {
    $MissingPrerequisites += "pinned ninja at third_party/ninja (no system fallback)"
}

# Real invoked compiler (clang-cl from the checkout) - fail closed if absent.
$ChromiumClang = Join-Path $Src "third_party/llvm-build/Release+Asserts/bin/clang-cl.exe"
if (-not (Test-Path $ChromiumClang)) {
    $ChromiumClang = Join-Path $Src "third_party/llvm-build/Release+Asserts/bin/clang++.exe"
}
if (-not (Test-Path $ChromiumClang -PathType Leaf)) {
    $MissingPrerequisites += "pinned Chromium clang-cl"
}

# Consume and independently recheck the SDK record before invoking generators.
# Expected pins are policy; observed fields and installed files are host facts.
$SdkPrereqPath = Join-Path $Here "inventory/win-sdk-prereq.txt"
if (-not (Test-Path $SdkPrereqPath)) {
    $MissingPrerequisites += "validated Windows SDK prerequisite record $SdkPrereqPath (run install-win-sdk.ps1 first)"
}
$SdkPrereq = @{}
if (Test-Path $SdkPrereqPath -PathType Leaf) {
    foreach ($line in Get-Content $SdkPrereqPath) {
        if ($line -match '^([^#=]+)=(.*)$') {
            $SdkPrereq[$Matches[1]] = $Matches[2]
        }
    }
}

$SdkPinsPath = Join-Path $Here "inventory/win-sdk-pins.json"
$SdkPins = $null
if (-not (Test-Path $SdkPinsPath -PathType Leaf)) {
    $MissingPrerequisites += "Windows SDK pin manifest $SdkPinsPath"
} else {
    try {
        $SdkPins = Get-Content $SdkPinsPath -Raw | ConvertFrom-Json
    } catch {
        $MissingPrerequisites += "valid Windows SDK pin manifest $SdkPinsPath"
    }
}

if ($SdkPrereq["outcome"] -notin @("existing-complete", "installed-or-repaired")) {
    $MissingPrerequisites += "complete Windows SDK prerequisite record (outcome='$($SdkPrereq["outcome"])')"
}
if (-not $SdkPrereq["expected_sdk_version_folder"] -or
    -not $SdkPrereq["expected_servicing_version"] -or
    -not $SdkPrereq["observed_servicing_version"] -or
    $SdkPrereq["observed_servicing_version"] -ne $SdkPrereq["expected_servicing_version"]) {
    $MissingPrerequisites += "matching expected and observed Windows SDK servicing versions"
}
if ($SdkPrereq["observed_preflight_empty"] -ne "0" -or
    $SdkPrereq["observed_preflight_missing"] -ne "0") {
    $MissingPrerequisites += "Windows SDK preflight files present and non-empty"
}
if ($null -ne $SdkPins) {
    if ($SdkPins.sdk_version_folder -ne $SdkPrereq["expected_sdk_version_folder"] -or
        $SdkPins.servicing_version -ne $SdkPrereq["expected_servicing_version"]) {
        $MissingPrerequisites += "Windows SDK prerequisite record matching the checked-in pin manifest"
    }
    $SdkRelativePaths = @($SdkPins.preflight_relative_paths)
    if ($SdkRelativePaths.Count -eq 0) {
        $MissingPrerequisites += "non-empty Windows SDK preflight path list in the pin manifest"
    }
    $KitsRoot = [string]$SdkPrereq["observed_kits_root"]
    if ([string]::IsNullOrWhiteSpace($KitsRoot) -or -not (Test-Path $KitsRoot -PathType Container)) {
        $MissingPrerequisites += "observed Windows Kits root from the prerequisite record"
    } else {
        foreach ($RelativePath in $SdkRelativePaths) {
            $RequiredSdkFile = Join-Path $KitsRoot $RelativePath
            if (-not (Test-Path $RequiredSdkFile -PathType Leaf) -or
                (Get-Item $RequiredSdkFile -ErrorAction SilentlyContinue).Length -le 0) {
                $MissingPrerequisites += "installed Windows SDK file $RequiredSdkFile"
            }
        }
    }
}

if ($MissingPrerequisites.Count -gt 0) {
    Write-Host "Windows WebRTC build preflight failed; no generated header or GN target was changed:"
    foreach ($MissingPrerequisite in $MissingPrerequisites) {
        Write-Host "  missing or invalid: $MissingPrerequisite"
    }
    throw "resolve the complete prerequisite set, then rerun build-windows.ps1"
}

python (Join-Path $Here "scripts/setup-gn-target.py") $Root --check-only
if ($LASTEXITCODE -ne 0) { throw "setup-gn-target.py preflight failed" }

$ClangVer = & $ChromiumClang --version 2>&1 | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw "compiler --version failed" }

python (Join-Path $Here "scripts/gen_header.py") (Join-Path $Native "hs_webrtc_bridge.cpp") (Join-Path $Native "hs_webrtc.h")
if ($LASTEXITCODE -ne 0) { throw "gen_header.py failed" }

# Deterministic pin verification + GN target staging/registration via the
# portable Python owner (no dependency on which bash is on PATH; WSL
# System32 bash is not used).
python (Join-Path $Here "scripts/setup-gn-target.py") $Root
if ($LASTEXITCODE -ne 0) { throw "setup-gn-target.py failed" }

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
    "win_sdk_expected_version_folder=$($SdkPrereq["expected_sdk_version_folder"])"
    "win_sdk_expected_servicing_version=$($SdkPrereq["expected_servicing_version"])"
    "win_sdk_observed_servicing_version=$($SdkPrereq["observed_servicing_version"])"
    "win_sdk_observed_servicing_source=$($SdkPrereq["observed_servicing_source"])"
    "win_sdk_observed_kits_root=$($SdkPrereq["observed_kits_root"])"
    "win_sdk_observed_preflight_present=$($SdkPrereq["observed_preflight_present"])"
    "win_sdk_installer_checked=$($SdkPrereq["installer_checked"])"
    "win_sdk_installer_executed=$($SdkPrereq["installer_executed"])"
    "win_sdk_installer_sha256_observed=$($SdkPrereq["installer_sha256_observed"])"
    "win_sdk_installer_authenticode=$($SdkPrereq["installer_authenticode"])"
    "win_sdk_prereq_outcome=$($SdkPrereq["outcome"])"
    "harness_path=$($Harness.FullName)"
    "harness_sha256=$((Get-FileHash $Harness.FullName -Algorithm SHA256).Hash.ToLower())"
    "dll_path=$($Dll.FullName)"
    "dll_sha256=$((Get-FileHash $Dll.FullName -Algorithm SHA256).Hash.ToLower())"
) | Set-Content -Encoding ascii $Prov

# Retain actual produced binaries into inventory immediately after a successful
# build so a later harness failure cannot drop them from the artifact upload.
$Inv = $Inventory
Copy-Item -Force $Harness.FullName (Join-Path $Inv "hs_webrtc_harness.exe")
Copy-Item -Force $Dll.FullName (Join-Path $Inv "hs_webrtc_shared.dll")
foreach ($required in @("hs_webrtc_harness.exe", "hs_webrtc_shared.dll", "build-provenance-$Out.txt")) {
    $p = Join-Path $Inv $required
    if (-not (Test-Path $p) -or (Get-Item $p).Length -le 0) {
        throw "expected build artifact missing or empty after retain: $p"
    }
}

Write-Host "built harness=$($Harness.FullName)"
Write-Host "built dll=$($Dll.FullName)"
Write-Host "retained inventory binaries hs_webrtc_harness.exe hs_webrtc_shared.dll"
