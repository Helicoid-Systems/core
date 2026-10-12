#!/usr/bin/env pwsh
# build-windows-x64.ps1 — Windows x64 native ABI build + harness pipeline.
#
# Builds the REAL pinned RustDesk hs-native library (no Flutter/Sciter product
# UI), runs all actual hs_native tests, then links and executes the Windows C
# lifetime harness and the C# wrapper lifetime check against the real DLL.
#
# Prerequisites (CI-owned; no global ambient installs):
#   - VS 2022 Build Tools (MSVC) already on PATH (cl.exe) via vcvars64
#   - Rust toolchain with x86_64-pc-windows-msvc
#   - VCPKG_ROOT pointing at vcpkg pinned to 9e593bb18ea69cc5095e012465dcd675a822ed0d
#   - python on PATH (header generator / contract checks)
#   - dotnet SDK 10 on PATH (C# lifetime check)
#
# Usage:
#   ./scripts/build-windows-x64.ps1 -Upstream <path-to-patched-upstream> `
#       [-TargetDir <cargo-target>] [-OutDir <harness-out>] [-VcpkgTriplet x64-windows-static]
#
# Every native command exit code is checked. Missing tools fail the run.
# Frozen lab files (header/wrappers/patch/inventory/Mac scripts) are hashed
# before and after and must not change. Header generation writes only into
# the owned output directory and byte-compares against the retained header.

param(
    [Parameter(Mandatory = $true)]
    [string]$Upstream,
    [string]$TargetDir = '',
    [string]$OutDir = '',
    [string]$VcpkgTriplet = 'x64-windows-static'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lab = Split-Path -Parent $here

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

function Invoke-Checked {
    param([string]$FilePath, [string[]]$Arguments, [string]$Label)
    Write-Output "==> $Label"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$Label failed with exit $LASTEXITCODE"
    }
}

function Invoke-CheckedToFile {
    param([string]$FilePath, [string[]]$Arguments, [string]$Label, [string]$LogPath)
    Write-Output "==> $Label"
    $out = & $FilePath @Arguments 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { "$_" } | Set-Content -LiteralPath $LogPath -Encoding utf8
    $out | ForEach-Object { "$_" } | Write-Output
    if ($code -ne 0) {
        Fail "$Label failed with exit $code (log: $LogPath)"
    }
}

function Require-Tool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Fail "required tool absent: $name"
    }
    return $cmd.Source
}

# --- path safety -----------------------------------------------------------
if ($Upstream -match '[\0]' -or $Upstream -match '(^|[/\\])\.\.([/\\]|$)') {
    Fail "unsafe upstream path: $Upstream"
}
if (-not (Test-Path -LiteralPath $Upstream -PathType Container)) {
    Fail "upstream path not found: $Upstream"
}
$Upstream = (Resolve-Path -LiteralPath $Upstream).Path

# --- tool presence ---------------------------------------------------------
Require-Tool 'git' | Out-Null
Require-Tool 'python' | Out-Null
Require-Tool 'cargo' | Out-Null
Require-Tool 'rustc' | Out-Null
$cl = Require-Tool 'cl'
$dotnet = Require-Tool 'dotnet'

if (-not $TargetDir) {
    $TargetDir = Join-Path ([System.IO.Path]::GetTempPath()) 'hs-engine-windows-build'
}
if (-not $OutDir) {
    $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) 'hs-engine-windows-harness'
}
New-Item -ItemType Directory -Force -Path $TargetDir, $OutDir | Out-Null
$TargetDir = (Resolve-Path -LiteralPath $TargetDir).Path
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

$env:CARGO_TARGET_DIR = $TargetDir
$env:CARGO_PROFILE_DEV_DEBUG = '0'
$env:CARGO_PROFILE_TEST_DEBUG = '0'
$env:CARGO_INCREMENTAL = '0'

if (-not $env:VCPKG_ROOT) { Fail 'VCPKG_ROOT is required' }
$env:VCPKG_INSTALLED_ROOT = Join-Path $env:VCPKG_ROOT 'installed'
$env:VCPKG_DEFAULT_HOST_TRIPLET = $VcpkgTriplet

# --- hash frozen lab files before any work ---------------------------------
$frozenRel = @(
    'native/hs_native.h',
    'native/harness.c',
    'native/wrappers/HsNativeWrapper.cs',
    'native/wrappers/HsNativeWrapper.swift',
    'native/wrappers/csharp_lifetime_check.cs',
    'native/wrappers/swift_lifetime_check.swift',
    'patches/0001-hs-native-bridge.patch',
    'inventory/source-pin.txt',
    'inventory/patched-files.sha256',
    'scripts/apply-patch.sh',
    'scripts/build-macos-arm64.sh',
    'scripts/check-source-pin.sh',
    'scripts/check-header.py',
    'scripts/check-wrapper-contract.py',
    'scripts/check-wrappers.sh',
    'scripts/gen_header.py'
)

function Hash-Frozen([string]$OutFile) {
    $rows = foreach ($rel in $frozenRel) {
        $p = Join-Path $lab $rel
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            Fail "frozen file missing: $rel"
        }
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        "$h  $rel"
    }
    $rows | Set-Content -LiteralPath $OutFile -Encoding utf8
    return ($rows -join "`n")
}

Write-Output '==> hash frozen lab files (before)'
$frozenBefore = Hash-Frozen (Join-Path $OutDir 'frozen-hashes-before.txt')

# --- pins + patch + locked file hashes -------------------------------------
Invoke-Checked (Join-Path $here 'check-source-pin.ps1') @('-Upstream', $Upstream) 'check source pins'
Invoke-Checked (Join-Path $here 'check-patched-files.ps1') @('-Upstream', $Upstream) 'verify patched-files.sha256'

# --- pins record for evidence ----------------------------------------------
@(
    "upstream=$Upstream",
    "rustc=$(rustc -V 2>&1)",
    "cargo=$(cargo -V 2>&1)",
    "python=$((Get-Command python).Source)",
    "dotnet=$(dotnet --version 2>&1)",
    "cl=$cl",
    "vcpkg_root=$env:VCPKG_ROOT",
    "vcpkg_triplet=$VcpkgTriplet",
    "target_dir=$TargetDir",
    "out_dir=$OutDir"
) | Set-Content -LiteralPath (Join-Path $OutDir 'pins.txt') -Encoding utf8

# --- generate C header into OWNED output only; byte-compare ----------------
$generatedHeader = Join-Path $OutDir 'hs_native.generated.h'
$retainedHeader = Join-Path (Join-Path $lab 'native') 'hs_native.h'
Write-Output '==> generate C header from hs_native.rs into owned output'
Invoke-Checked 'python' @(
    (Join-Path $here 'gen_header.py'),
    (Join-Path (Join-Path $Upstream 'src') 'hs_native.rs'),
    $generatedHeader
) 'gen_header.py (owned output)'

$genBytes = [System.IO.File]::ReadAllBytes($generatedHeader)
$retBytes = [System.IO.File]::ReadAllBytes($retainedHeader)
if ($genBytes.Length -ne $retBytes.Length) {
    Fail "generated header length drift: generated=$($genBytes.Length) retained=$($retBytes.Length)"
}
for ($i = 0; $i -lt $genBytes.Length; $i++) {
    if ($genBytes[$i] -ne $retBytes[$i]) {
        Fail "generated header byte drift at offset $i (generated header must match retained native/hs_native.h)"
    }
}
Write-Output "generated header matches retained native/hs_native.h ($($genBytes.Length) bytes)"

Invoke-Checked 'python' @((Join-Path $here 'check-header.py')) 'check-header.py'
Invoke-Checked 'python' @((Join-Path $here 'check-wrapper-contract.py')) 'check-wrapper-contract.py'

# --- cargo: check / test / build (locked; never update the lock) ------------
$manifest = Join-Path $Upstream 'Cargo.toml'
Invoke-CheckedToFile 'cargo' @('check', '--locked', '--lib', '--features', 'hs-native', '--manifest-path', $manifest) 'cargo check --locked --lib --features hs-native' (Join-Path $OutDir 'rust-check.txt')
Invoke-CheckedToFile 'cargo' @('test',  '--locked', '--lib', '--features', 'hs-native', 'hs_native', '--manifest-path', $manifest) 'cargo test --locked --lib --features hs-native hs_native' (Join-Path $OutDir 'rust-tests.txt')
$rustTests = Get-Content -LiteralPath (Join-Path $OutDir 'rust-tests.txt') -Raw
if ($rustTests -notmatch 'test result: ok\. 32 passed; 0 failed; 0 ignored;') {
    Fail 'expected all 32 retained hs_native tests to execute and pass without ignores'
}
Invoke-CheckedToFile 'cargo' @('build', '--locked', '--lib', '--features', 'hs-native', '--manifest-path', $manifest) 'cargo build --locked --lib --features hs-native' (Join-Path $OutDir 'rust-build.txt')

# --- locate the real cdylib ------------------------------------------------
$dll = Join-Path (Join-Path $TargetDir 'debug') 'librustdesk.dll'
if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) {
    Fail "expected cdylib at $dll"
}

# --- PE architecture / import / export evidence ----------------------------
$dumpbin = $null
$dumpbinKind = $null
if (Get-Command 'dumpbin' -ErrorAction SilentlyContinue) {
    $dumpbin = (Get-Command 'dumpbin').Source
    $dumpbinKind = 'dumpbin'
} elseif (Get-Command 'llvm-readobj' -ErrorAction SilentlyContinue) {
    $dumpbin = (Get-Command 'llvm-readobj').Source
    $dumpbinKind = 'llvm-readobj'
} else {
    Fail 'dumpbin or llvm-readobj required for PE evidence (install VS Build Tools / LLVM)'
}

Write-Output "==> PE evidence via $dumpbin ($dumpbinKind)"
$peDir = Join-Path $OutDir 'pe'
New-Item -ItemType Directory -Force -Path $peDir | Out-Null

if ($dumpbinKind -eq 'dumpbin') {
    Invoke-CheckedToFile $dumpbin @('/headers', $dll) 'dumpbin /headers' (Join-Path $peDir 'headers.txt')
    Invoke-CheckedToFile $dumpbin @('/imports', $dll) 'dumpbin /imports' (Join-Path $peDir 'imports.txt')
    Invoke-CheckedToFile $dumpbin @('/exports', $dll) 'dumpbin /exports' (Join-Path $peDir 'exports.txt')
} else {
    Invoke-CheckedToFile $dumpbin @('--file-headers', $dll) 'llvm-readobj file-headers' (Join-Path $peDir 'headers.txt')
    Invoke-CheckedToFile $dumpbin @('--coff-imports', $dll) 'llvm-readobj coff-imports' (Join-Path $peDir 'imports.txt')
    Invoke-CheckedToFile $dumpbin @('--coff-exports', $dll) 'llvm-readobj coff-exports' (Join-Path $peDir 'exports.txt')
}

$imports = Get-Content -LiteralPath (Join-Path $peDir 'imports.txt') -Raw
if ($imports -match '(?i)sciter|flutter') {
    Fail 'Sciter/Flutter appears in PE imports; product UI runtime is required — refusing'
}
Write-Output 'no sciter/flutter in PE imports'

# PE x64 machine (8664) MUST be present. A missing 8664 marker is a hard fail.
$headers = Get-Content -LiteralPath (Join-Path $peDir 'headers.txt') -Raw
if ($headers -match '(?i)\b14C\b') {
    Fail 'PE machine type is i386 (14C); expected x64 (8664)'
}
if ($headers -notmatch '8664') {
    Fail 'PE headers lack the x64 machine marker 8664; refusing to trust architecture'
}
Write-Output 'PE machine is x64 (8664)'

# --- verify exactly the retained 27 hs_ exports ----------------------------
# Expected set comes from the retained generated header (source of truth).
$expectedExports = [System.Collections.Generic.List[string]]::new()
foreach ($line in Get-Content -LiteralPath $retainedHeader) {
    if ($line -match '^\s*(?:uint32_t|const char\s*\*)\s+(hs_\w+)\s*\(') {
        $name = $Matches[1]
        if (-not $expectedExports.Contains($name)) {
            $expectedExports.Add($name)
        }
    }
}
if ($expectedExports.Count -ne 27) {
    Fail "retained header export count is $($expectedExports.Count), expected 27"
}

# Actual hs_ exports from PE export table.
$exportsRaw = Get-Content -LiteralPath (Join-Path $peDir 'exports.txt') -Raw
$actualExports = [System.Collections.Generic.List[string]]::new()
foreach ($m in [System.Text.RegularExpressions.Regex]::Matches($exportsRaw, '\b(hs_\w+)\b')) {
    $name = $m.Groups[1].Value
    if (-not $actualExports.Contains($name)) {
        $actualExports.Add($name)
    }
}
if ($actualExports.Count -eq 0) {
    Fail 'no hs_ exports found in PE export table'
}

$missing = @($expectedExports | Where-Object { $actualExports -notcontains $_ })
$extra = @($actualExports | Where-Object { $expectedExports -notcontains $_ })
if ($missing.Count -gt 0) {
    Fail "missing hs exports in DLL: $($missing -join ', ')"
}
if ($extra.Count -gt 0) {
    Fail "extra hs exports in DLL not in retained header: $($extra -join ', ')"
}
Write-Output "hs exports OK: exactly $($expectedExports.Count) match the retained header"
$expectedExports | Set-Content -LiteralPath (Join-Path $peDir 'hs-exports-expected.txt') -Encoding utf8
$actualExports | Set-Content -LiteralPath (Join-Path $peDir 'hs-exports-actual.txt') -Encoding utf8

# --- compile + run Windows C harness --------------------------------------
$harnessSrc = Join-Path (Join-Path $lab 'native') 'windows-harness.c'
if (-not (Test-Path -LiteralPath $harnessSrc -PathType Leaf)) {
    Fail "windows harness source missing: $harnessSrc"
}
$harnessExe = Join-Path $OutDir 'windows-harness.exe'
$libDir = Join-Path $TargetDir 'debug'

# Exact cargo MSVC cdylib import library names only — no "first .lib".
$importLib = $null
$importCandidates = @(
    (Join-Path $libDir 'librustdesk.dll.lib'),
    (Join-Path $libDir 'librustdesk.lib')
)
foreach ($cand in $importCandidates) {
    if (Test-Path -LiteralPath $cand -PathType Leaf) {
        $importLib = $cand
        break
    }
}
if (-not $importLib) {
    Fail "exact import library not found (librustdesk.dll.lib or librustdesk.lib) under $libDir; refusing arbitrary .lib"
}

Write-Output '==> compile Windows C harness (also type-checks the generated header)'
Invoke-Checked $cl @(
    '/nologo', '/std:c11', '/W3', '/Zi',
    "/I$(Join-Path $lab 'native')",
    $harnessSrc,
    "/Fe:$harnessExe",
    "/Fo:$OutDir\windows-harness.obj",
    $importLib,
    'iphlpapi.lib', 'ws2_32.lib'
) 'cl windows-harness.c'

# Prefer the exact DLL directory for the harness process.
$env:PATH = "$libDir;$env:PATH"
Write-Output '==> run Windows C harness'
$harnessOut = & $harnessExe 2>&1
$harnessCode = $LASTEXITCODE
$harnessOut | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $OutDir 'harness.txt') -Encoding utf8
$harnessOut | ForEach-Object { "$_" } | Write-Output
if ($harnessCode -ne 0) {
    Fail "Windows C harness failed with exit $harnessCode (log: $(Join-Path $OutDir 'harness.txt'))"
}

# --- C# lifetime check against the real DLL --------------------------------
Write-Output '==> C# wrapper lifetime check (own native DLL search path)'
$csProj = Join-Path (Join-Path (Join-Path $lab 'native') 'csharp-check') 'csharp-check.csproj'
if (-not (Test-Path -LiteralPath $csProj -PathType Leaf)) {
    Fail "csharp-check project missing: $csProj"
}
$env:HS_NATIVE_DLL_DIR = $libDir
$env:HS_NATIVE_DEP_DIRS = $libDir
if ($env:VCPKG_ROOT) {
    $vcpkgBin = Join-Path (Join-Path (Join-Path $env:VCPKG_ROOT 'installed') $VcpkgTriplet) 'bin'
    if (Test-Path -LiteralPath $vcpkgBin -PathType Container) {
        $env:HS_NATIVE_DEP_DIRS = "$libDir$([System.IO.Path]::PathSeparator)$vcpkgBin"
    }
}

$csOut = Join-Path $OutDir 'csharp-lifetime-check'
New-Item -ItemType Directory -Force -Path $csOut | Out-Null
Invoke-CheckedToFile $dotnet @('build', $csProj, '-c', 'Release', '--nologo', "-p:OutputPath=$csOut\") 'dotnet build csharp-check' (Join-Path $OutDir 'csharp-build.txt')

$csExe = Join-Path $csOut 'csharp-lifetime-check.exe'
$csDll = Join-Path $csOut 'csharp-lifetime-check.dll'
$csharpLog = Join-Path $OutDir 'csharp.txt'
if (Test-Path -LiteralPath $csExe -PathType Leaf) {
    $out = & $csExe 2>&1
    $code = $LASTEXITCODE
} elseif (Test-Path -LiteralPath $csDll -PathType Leaf) {
    $out = & $dotnet $csDll 2>&1
    $code = $LASTEXITCODE
} else {
    Fail "csharp-lifetime-check output missing under $csOut"
}
$out | ForEach-Object { "$_" } | Set-Content -LiteralPath $csharpLog -Encoding utf8
$out | ForEach-Object { "$_" } | Write-Output
if ($code -ne 0) {
    Fail "C# lifetime check failed with exit $code (log: $csharpLog)"
}

# --- frozen hashes after; must be unchanged --------------------------------
Write-Output '==> hash frozen lab files (after)'
$frozenAfter = Hash-Frozen (Join-Path $OutDir 'frozen-hashes-after.txt')
if ($frozenBefore -ne $frozenAfter) {
    Fail 'frozen lab files changed during the build (header/wrappers/patch/inventory/Mac scripts are immutable)'
}
Write-Output 'frozen lab files unchanged'

# --- evidence completeness (no fabricated runtime) -------------------------
$requiredEvidence = @(
    'frozen-hashes-before.txt',
    'frozen-hashes-after.txt',
    'pins.txt',
    'rust-check.txt',
    'rust-tests.txt',
    'rust-build.txt',
    'harness.txt',
    'csharp.txt',
    'pe/headers.txt',
    'pe/imports.txt',
    'pe/exports.txt',
    'pe/hs-exports-expected.txt',
    'pe/hs-exports-actual.txt'
)
foreach ($rel in $requiredEvidence) {
    $p = Join-Path $OutDir $rel
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        Fail "required evidence missing: $rel"
    }
    if ((Get-Item -LiteralPath $p).Length -eq 0 -and $rel -notmatch 'hs-exports') {
        Fail "required evidence is empty: $rel"
    }
}
Write-Output "evidence complete under $OutDir"

Write-Output 'done.'
exit 0
