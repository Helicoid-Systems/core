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

# PowerShell .ps1 callees bind named parameters; an array splat would pass
# '-Upstream' as a literal positional value. Use a hashtable splat instead.
# Native commands (cargo/python/cl/dotnet) keep Invoke-Checked argv arrays.
function Invoke-CheckedScript {
    param([string]$FilePath, [hashtable]$NamedArguments, [string]$Label)
    Write-Output "==> $Label"
    & $FilePath @NamedArguments
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
Invoke-CheckedScript (Join-Path $here 'check-source-pin.ps1') @{ Upstream = $Upstream } 'check source pins'
Invoke-CheckedScript (Join-Path $here 'check-patched-files.ps1') @{ Upstream = $Upstream } 'verify patched-files.sha256'

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

# ===========================================================================
# Inert unsigned lab bundle seam (post-success).
# Retains the EXACT tested librustdesk.dll beside the existing harness/runtime
# files and writes a bounded versioned integrity receipt. This is evidence
# only: not a signed release/update manifest, not authorization, no product
# adoption. Connect/observation/channel binding remain UNAVAILABLE.
# ===========================================================================

# Scoped copy helper: refuse directory/junction/link destinations BEFORE any
# Copy-Item (which would otherwise copy INTO an existing directory). An
# existing regular file may be retained only when bytes are identical.
function Copy-RetainedExactBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        Fail "$Label source missing: $Source"
    }
    $srcHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    $srcSize = (Get-Item -LiteralPath $Source).Length
    if (Test-Path -LiteralPath $Destination) {
        $destItem = Get-Item -LiteralPath $Destination -Force
        if ($destItem.PSIsContainer) {
            Fail "$Label refusing copy into existing directory/junction at destination: $Destination"
        }
        if ($destItem.LinkType -or ($destItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Fail "$Label refusing copy onto link/reparse point: $Destination"
        }
        $dstHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($dstHash -ne $srcHash) {
            Fail "$Label conflicting file at destination (different bytes): $Destination"
        }
        return @{ Sha256 = $srcHash; Size = $srcSize; Copied = $false }
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $copiedHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($copiedHash -ne $srcHash) {
        Fail "$Label hash mismatch after copy: source=$srcHash retained=$copiedHash"
    }
    if ((Get-Item -LiteralPath $Destination).Length -ne $srcSize) {
        Fail "$Label size mismatch after copy"
    }
    return @{ Sha256 = $srcHash; Size = $srcSize; Copied = $true }
}

# Owned output directory itself must not be a link/reparse point.
$outDirItem = Get-Item -LiteralPath $OutDir -Force
if ($outDirItem.LinkType -or ($outDirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    Fail "owned output directory is a link/reparse point: $OutDir"
}

# --- retain exact tested DLL at the declared exact name ---------------------
Write-Output '==> retain exact tested DLL into owned output (inert unsigned lab bundle)'
$dllHash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
$dllSize = (Get-Item -LiteralPath $dll).Length
$retainedDll = Join-Path $OutDir 'librustdesk.dll'
$dllCopy = Copy-RetainedExactBytes -Source $dll -Destination $retainedDll -Label 'librustdesk.dll'
Write-Output "retained librustdesk.dll ($($dllCopy.Size) bytes, sha256 $($dllCopy.Sha256), copied=$($dllCopy.Copied))"

# Import library only at the declared exact filename (already resolved above).
if ($importLib) {
    $importLibName = Split-Path -Leaf $importLib
    if ($importLibName -notin @('librustdesk.dll.lib', 'librustdesk.lib')) {
        Fail "refusing undeclared import library name: $importLibName"
    }
    $importLibDest = Join-Path $OutDir $importLibName
    $importCopy = Copy-RetainedExactBytes -Source $importLib -Destination $importLibDest -Label "import-library $importLibName"
    Write-Output "retained import library $importLibName (sha256 $($importCopy.Sha256))"
}

# --- validate staged bundle against the retained copy -----------------------
# Explicit copied-DLL directory only: OutDir is the sole native search root.
# The cargo target directory is removed from PATH so the harnesses cannot fall
# back to the source target DLL. Hash before/after proves the same retained
# bytes were used. Original 32/133/85 runs above are unchanged.
Write-Output '==> staged bundle validation (C harness against retained DLL only)'
$retainedHashBefore = (Get-FileHash -LiteralPath $retainedDll -Algorithm SHA256).Hash.ToLowerInvariant()
$savedPath = $env:PATH
# Keep OS tool directories; drop the cargo target dir and any PATH entry that
# could resolve a different librustdesk.dll.
$env:PATH = (@($savedPath -split [System.IO.Path]::PathSeparator |
        Where-Object { $_ -and ($_ -ne $libDir) -and ($_ -ne (Join-Path $TargetDir 'debug')) }) -join [System.IO.Path]::PathSeparator)
$env:HS_NATIVE_DLL_DIR = $OutDir
$env:HS_NATIVE_DEP_DIRS = $OutDir
try {
    Push-Location $OutDir
    try {
        $stagedHarnessOut = & (Join-Path $OutDir 'windows-harness.exe') 2>&1
        $stagedHarnessCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    $env:PATH = $savedPath
}
$stagedHarnessOut | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $OutDir 'harness-staged.txt') -Encoding utf8
$stagedHarnessOut | ForEach-Object { "$_" } | Write-Output
if ($stagedHarnessCode -ne 0) {
    Fail "staged C harness failed against retained DLL with exit $stagedHarnessCode (log: $(Join-Path $OutDir 'harness-staged.txt'))"
}

Write-Output '==> staged bundle validation (C# lifetime check against retained DLL only)'
$env:HS_NATIVE_DLL_DIR = $OutDir
$env:HS_NATIVE_DEP_DIRS = $OutDir
if (Test-Path -LiteralPath $csExe -PathType Leaf) {
    $stagedCsOut = & $csExe 2>&1
    $stagedCsCode = $LASTEXITCODE
} elseif (Test-Path -LiteralPath $csDll -PathType Leaf) {
    $stagedCsOut = & $dotnet $csDll 2>&1
    $stagedCsCode = $LASTEXITCODE
} else {
    Fail "csharp-lifetime-check output missing under $csOut for staged validation"
}
$stagedCsOut | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $OutDir 'csharp-staged.txt') -Encoding utf8
$stagedCsOut | ForEach-Object { "$_" } | Write-Output
if ($stagedCsCode -ne 0) {
    Fail "staged C# lifetime check failed against retained DLL with exit $stagedCsCode (log: $(Join-Path $OutDir 'csharp-staged.txt'))"
}

$retainedHashAfter = (Get-FileHash -LiteralPath $retainedDll -Algorithm SHA256).Hash.ToLowerInvariant()
if ($retainedHashBefore -ne $retainedHashAfter) {
    Fail "retained DLL changed during staged validation (before=$retainedHashBefore after=$retainedHashAfter)"
}
if ($retainedHashAfter -ne $dllHash) {
    Fail "retained DLL does not match the exact tested DLL after staged validation"
}

# --- lab bundle receipt (evidence/integrity only; unsigned) -----------------
Write-Output '==> write lab bundle receipt (inert unsigned lab bundle)'
$vcpkgCommit = "$env:VCPKG_COMMIT_ID".Trim().ToLowerInvariant()
if ($vcpkgCommit -notmatch '^[0-9a-f]{40}$') {
    Fail "VCPKG_COMMIT_ID (frozen vcpkg pin, 40-char hex) is required for the lab bundle receipt (got '$env:VCPKG_COMMIT_ID')"
}

Push-Location $lab
try {
    $labShaOut = git rev-parse HEAD 2>&1
    $labShaCode = $LASTEXITCODE
    $labSha = "$labShaOut".Trim().ToLowerInvariant()
} finally {
    Pop-Location
}
if ($labShaCode -ne 0 -or $labSha -notmatch '^[0-9a-f]{40}$') {
    Fail "failed to resolve lab source git sha (exit $labShaCode): $labSha"
}

$pinFile = Join-Path (Join-Path $lab 'inventory') 'source-pin.txt'
$pinText = Get-Content -LiteralPath $pinFile -Raw -ErrorAction Stop
$sourcePins = @{}
foreach ($pinLine in ($pinText -split "`r?`n")) {
    $pt = $pinLine.Trim()
    if ($pt -match '^(upstream_commit|submodule_hbb_common|lockfile_sha256):\s*(\S+)\s*$') {
        $sourcePins[$Matches[1]] = $Matches[2]
    }
}
foreach ($reqPin in @('upstream_commit', 'submodule_hbb_common', 'lockfile_sha256')) {
    if (-not $sourcePins.ContainsKey($reqPin)) {
        Fail "inventory/source-pin.txt missing required pin: $reqPin"
    }
}

# Explicit allowlist (mirrors check-windows-lab-bundle.ps1): refuse any
# unclassifiable member (no recursive dumps, no arbitrary role names).
$bundleRoles = @{
    'librustdesk.dll'                                       = 'exact-tested-dll'
    'librustdesk.dll.lib'                                   = 'import-library'
    'librustdesk.lib'                                       = 'import-library'
    'hs_native.generated.h'                                 = 'generated-header'
    'windows-harness.exe'                                   = 'test-binary'
    'windows-harness.obj'                                   = 'compile-sidecar'
    'windows-harness.ilk'                                   = 'compile-sidecar'
    'windows-harness.pdb'                                   = 'compile-sidecar'
    'csharp-lifetime-check/csharp-lifetime-check.exe'       = 'csharp-apphost'
    'csharp-lifetime-check/csharp-lifetime-check.dll'       = 'csharp-assembly'
    'csharp-lifetime-check/csharp-lifetime-check.deps.json' = 'csharp-runtime-companion'
    'csharp-lifetime-check/csharp-lifetime-check.runtimeconfig.json' = 'csharp-runtime-companion'
    'csharp-lifetime-check/csharp-lifetime-check.pdb'       = 'compile-sidecar'
    'harness.txt'                                           = 'report'
    'harness-staged.txt'                                    = 'report'
    'csharp.txt'                                            = 'report'
    'csharp-staged.txt'                                     = 'report'
    'csharp-build.txt'                                      = 'report'
    'rust-check.txt'                                        = 'report'
    'rust-tests.txt'                                        = 'report'
    'rust-build.txt'                                        = 'report'
    'frozen-hashes-before.txt'                              = 'report'
    'frozen-hashes-after.txt'                               = 'report'
    'pins.txt'                                              = 'report'
    'pe/headers.txt'                                        = 'pe-evidence'
    'pe/imports.txt'                                        = 'pe-evidence'
    'pe/exports.txt'                                        = 'pe-evidence'
    'pe/hs-exports-expected.txt'                            = 'pe-evidence'
    'pe/hs-exports-actual.txt'                              = 'pe-evidence'
}

# Bounded owned-directory walk (mirrors the checker): only pe and
# csharp-lifetime-check subdirs; no arbitrary whole-tree recursion.
$allowedBundleSubdirs = @('pe', 'csharp-lifetime-check')
$MaxMemberBytes = 268435456   # 256 MiB
$MaxTotalBytes = 536870912    # 512 MiB
$bundleFiles = [System.Collections.Generic.List[object]]::new()
$bundleTotal = [int64]0
$bundleEntries = [System.Collections.Generic.List[object]]::new()
foreach ($entry in Get-ChildItem -LiteralPath $OutDir -Force) {
    if ($entry.LinkType -or ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Fail "link/reparse point in owned output refused: $($entry.Name)"
    }
    if ($entry.PSIsContainer) {
        if ($allowedBundleSubdirs -notcontains $entry.Name) {
            Fail "unexpected directory in owned output (only $($allowedBundleSubdirs -join ', ') allowed): $($entry.Name)"
        }
        foreach ($child in Get-ChildItem -LiteralPath $entry.FullName -Force) {
            if ($child.LinkType -or ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                Fail "link/reparse point in owned output refused: $($entry.Name)/$($child.Name)"
            }
            if ($child.PSIsContainer) {
                Fail "unexpected nested directory in owned output: $($entry.Name)/$($child.Name)"
            }
            $bundleEntries.Add([pscustomobject]@{
                    Rel = "$($entry.Name)/$($child.Name)"
                    Full = $child.FullName
                    Length = [int64]$child.Length
                })
        }
        continue
    }
    $bundleEntries.Add([pscustomobject]@{
            Rel = $entry.Name
            Full = $entry.FullName
            Length = [int64]$entry.Length
        })
}
foreach ($fi in $bundleEntries) {
    $rel = $fi.Rel
    if ($rel -eq 'lab-bundle-receipt.json') {
        continue
    }
    if (-not $bundleRoles.ContainsKey($rel)) {
        Fail "refusing unclassifiable lab bundle member (not in bounded role map): $rel"
    }
    if ($fi.Length -gt $MaxMemberBytes) {
        Fail "member size exceeds bounded maximum ($($fi.Length) > $MaxMemberBytes): $rel"
    }
    $bundleTotal += $fi.Length
    if ($bundleTotal -gt $MaxTotalBytes) {
        Fail "bundle size exceeds bounded total ($bundleTotal > $MaxTotalBytes)"
    }
    $bundleFiles.Add([ordered]@{
            path   = $rel
            role   = $bundleRoles[$rel]
            sha256 = (Get-FileHash -LiteralPath $fi.Full -Algorithm SHA256).Hash.ToLowerInvariant()
            size   = $fi.Length
        })
}
if ($bundleFiles.Count -eq 0) {
    Fail 'lab bundle has no members to record'
}

$receipt = [ordered]@{
    format           = 'hs-windows-lab-bundle-receipt/v1'
    kind             = 'inert-unsigned-lab-bundle'
    generated_utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    lab_source_git_sha = $labSha
    disposition      = [ordered]@{
        signed            = $false
        release_manifest  = $false
        update_manifest   = $false
        authorization     = $false
        note              = 'Evidence/integrity receipt only. SHA256 values are not signatures, not publisher keys, and not authorization to install, update, or operate anything.'
    }
    pins             = [ordered]@{
        upstream_commit    = $sourcePins['upstream_commit']
        hbb_common_commit  = $sourcePins['submodule_hbb_common']
        lockfile_sha256    = $sourcePins['lockfile_sha256']
        vcpkg_commit_id    = $vcpkgCommit
    }
    architecture     = [ordered]@{
        os        = 'windows'
        arch      = 'x86_64'
        pe_machine = '8664'
    }
    abi              = [ordered]@{
        version              = 2
        expected_export_count = 27
        expected_exports     = @($expectedExports)
    }
    claims           = [ordered]@{
        bundle_role       = 'INERT UNSIGNED LAB bundle'
        connect           = 'UNAVAILABLE'
        observation       = 'UNAVAILABLE'
        channel_binding   = 'UNAVAILABLE'
        endpoint_hosting  = 'not started by this bundle'
        product_adoption  = $false
        media_input       = 'NOT implemented / NOT adopted'
        note              = 'Retains the exact tested DLL for inert lab replay only. No release, no signing, no endpoint hosting, no product linkage.'
    }
    external_prerequisites = [ordered]@{
        note = 'Not installed or downloaded by this helper. The host must already provide these external runtime prerequisites to execute the retained harnesses.'
        native_harness = @(
            'Windows x64 (x86_64) operating system',
            'MSVC x64 C runtime: VCRUNTIME140.dll, VCRUNTIME140_1.dll, MSVCP140.dll (actual PE imports of the retained DLL and linked harness)',
            'Universal CRT (api-ms-win-crt-*; Windows 10+ / UCRT)',
            'OS system libraries already shipped with Windows (kernel32, iphlpapi, ws2_32, ...)',
            'librustdesk.dll is loaded from this bundle directory (exact application-directory path); no ambient DLL search expansion'
        )
        csharp_lifetime_check = @(
            '.NET 10 runtime (Microsoft.NETCore.App 10.0.x) as targeted by csharp-lifetime-check.runtimeconfig.json',
            'MSVC x64 C runtime and Universal CRT as above for the retained native DLL',
            'HS_NATIVE_DLL_DIR must point at this bundle directory (exact librustdesk.dll path; NativeDllGate exact loader rules unchanged)'
        )
    }
    files            = $bundleFiles
}

$receiptPath = Join-Path $OutDir 'lab-bundle-receipt.json'
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
Write-Output "wrote lab bundle receipt ($($bundleFiles.Count) members): $receiptPath"

# --- independent lab bundle gate --------------------------------------------
Invoke-CheckedScript (Join-Path $here 'check-windows-lab-bundle.ps1') @{ BundleDir = $OutDir } 'check-windows-lab-bundle.ps1'

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
    'harness-staged.txt',
    'csharp-staged.txt',
    'pe/headers.txt',
    'pe/imports.txt',
    'pe/exports.txt',
    'pe/hs-exports-expected.txt',
    'pe/hs-exports-actual.txt',
    'librustdesk.dll',
    'lab-bundle-receipt.json'
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
