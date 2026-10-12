#!/usr/bin/env pwsh
# check-source-pin.ps1 — Windows counterpart of check-source-pin.sh.
# Verifies recorded source/submodule/lock pins without applying changes.
# Malformed/duplicate required pins, unsafe paths, and git failures hard-fail. Retained inventory/source-pin.txt is the source of truth.
param(
    [Parameter(Mandatory = $true)]
    [string]$Upstream
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lab = Split-Path -Parent $here
$pinPath = Join-Path $lab 'inventory/source-pin.txt'
$patchPath = Join-Path $lab 'patches/0001-hs-native-bridge.patch'

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

# --- path safety -----------------------------------------------------------
if ($Upstream -match '[\0]' -or $Upstream -match '(^|[/\\])\.\.([/\\]|$)') {
    Fail "unsafe upstream path: $Upstream"
}
if (-not (Test-Path -LiteralPath $Upstream -PathType Container)) {
    Fail "upstream path not found: $Upstream"
}
$Upstream = (Resolve-Path -LiteralPath $Upstream).Path

if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
    Fail "patch not found: $patchPath"
}
if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) {
    Fail "pin file not found: $pinPath"
}

# --- parse authoritative pins; preserve unrelated inventory prose/lists -----
$pinText = Get-Content -LiteralPath $pinPath -Raw -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($pinText)) {
    Fail "inventory/source-pin.txt is empty"
}

$pins = @{}
foreach ($line in ($pinText -split "`r?`n")) {
    $t = $line.Trim()
    # This inventory also records multiline notes and patch_files lists.
    # Only these three fields are pins; malformed/duplicate pins still fail.
    if ($t -notmatch '^(upstream_commit|submodule_hbb_common|lockfile_sha256)\b') {
        continue
    }
    if ($t -notmatch '^(upstream_commit|submodule_hbb_common|lockfile_sha256):\s*(\S+)\s*$') {
        Fail "malformed pin in inventory/source-pin.txt: $line"
    }
    $key = $Matches[1]
    $val = $Matches[2]
    if ($pins.ContainsKey($key)) {
        Fail "duplicate pin in inventory/source-pin.txt: $key"
    }
    $pins[$key] = $val
}

foreach ($req in @('upstream_commit', 'submodule_hbb_common', 'lockfile_sha256')) {
    if (-not $pins.ContainsKey($req)) {
        Fail "inventory/source-pin.txt missing required key: $req"
    }
}

$expectedHead = $pins['upstream_commit']
$expectedSub = $pins['submodule_hbb_common']
$expectedLock = $pins['lockfile_sha256']

if ($expectedHead -notmatch '^[0-9a-f]{40}$') {
    Fail "upstream_commit is not a full 40-char hex sha: $expectedHead"
}
if ($expectedSub -notmatch '^[0-9a-f]{40}$') {
    Fail "submodule_hbb_common is not a full 40-char hex sha: $expectedSub"
}
if ($expectedLock -notmatch '^[0-9a-f]{64}$') {
    Fail "lockfile_sha256 is not a 64-char hex sha256: $expectedLock"
}

# --- git: check exit codes BEFORE dereferencing output ----------------------
function Git-Out([string[]]$GitArgs, [string]$Label) {
    $out = & git @GitArgs 2>$null
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Fail "$Label failed (git exit $code)"
    }
    if ($null -eq $out) {
        Fail "$Label produced no output"
    }
    # Join in case git wrote multiple lines; pin checks expect one sha line.
    $text = ($out | Out-String).Trim()
    if ($text.Length -eq 0) {
        Fail "$Label produced empty output"
    }
    return $text
}

$probe = Git-Out @('-C', $Upstream, 'rev-parse', '--is-inside-work-tree') 'rev-parse --is-inside-work-tree'
if ($probe -ne 'true') {
    Fail "upstream is not a git checkout: $Upstream"
}

$actualHead = Git-Out @('-C', $Upstream, 'rev-parse', 'HEAD') 'rev-parse HEAD'
if ($actualHead -notmatch '^[0-9a-f]{40}$') {
    Fail "upstream HEAD is not a full sha: $actualHead"
}
if ($actualHead -ne $expectedHead) {
    Fail "wrong upstream HEAD`n  expected: $expectedHead`n  actual:   $actualHead"
}

$subPath = Join-Path (Join-Path $Upstream 'libs') 'hbb_common'
if (-not (Test-Path -LiteralPath $subPath -PathType Container)) {
    Fail "hbb_common submodule path missing: $subPath"
}
$actualSub = Git-Out @('-C', $subPath, 'rev-parse', 'HEAD') 'rev-parse hbb_common HEAD'
if ($actualSub -notmatch '^[0-9a-f]{40}$') {
    Fail "hbb_common HEAD is not a full sha: $actualSub"
}
if ($actualSub -ne $expectedSub) {
    Fail "wrong hbb_common submodule pin`n  expected: $expectedSub`n  actual:   $actualSub"
}

$lockFile = Join-Path $Upstream 'Cargo.lock'
if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
    Fail "Cargo.lock missing at $lockFile"
}
try {
    $actualLock = (Get-FileHash -LiteralPath $lockFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
} catch {
    Fail "failed to hash Cargo.lock: $_"
}
if ($actualLock -notmatch '^[0-9a-f]{64}$') {
    Fail "Cargo.lock hash is not 64-char hex: $actualLock"
}
if ($actualLock -ne $expectedLock) {
    Fail "Cargo.lock hash mismatch (lock must be unchanged)`n  expected: $expectedLock`n  actual:   $actualLock"
}

Write-Output "pins OK: HEAD=$actualHead hbb_common=$actualSub lock=$actualLock"
exit 0
