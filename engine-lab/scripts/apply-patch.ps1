#!/usr/bin/env pwsh
# apply-patch.ps1 — Windows counterpart of apply-patch.sh.
# Applies the retained RD02 hs-native bridge patch to a clean upstream checkout
# AFTER enforcing the exact recorded pins. Wrong pins are refused (exit 1).
# git failures are checked before any output is dereferenced.
# This script does not fetch, clone, commit, or push.
param(
    [Parameter(Mandatory = $true)]
    [string]$Upstream
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lab = Split-Path -Parent $here
$patch = Join-Path $lab 'patches/0001-hs-native-bridge.patch'

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

if ($Upstream -match '[\0]' -or $Upstream -match '(^|[/\\])\.\.([/\\]|$)') {
    Fail "unsafe upstream path: $Upstream"
}
if (-not (Test-Path -LiteralPath $Upstream -PathType Container)) {
    Fail "upstream path not found: $Upstream"
}
$Upstream = (Resolve-Path -LiteralPath $Upstream).Path

if (-not (Test-Path -LiteralPath $patch -PathType Leaf)) {
    Fail "patch not found: $patch"
}

& (Join-Path $here 'check-source-pin.ps1') -Upstream $Upstream
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

# --check first so we do not leave a half-applied tree.
& git -C $Upstream apply --check -- $patch
if ($LASTEXITCODE -ne 0) {
    Fail "patch does not apply cleanly (already applied? wrong tree?) git exit $LASTEXITCODE"
}
& git -C $Upstream apply -- $patch
if ($LASTEXITCODE -ne 0) {
    Fail "git apply failed (exit $LASTEXITCODE)"
}

Write-Output "applied: $patch"
Write-Output 'next: scripts/build-windows-x64.ps1 <upstream>'
exit 0
