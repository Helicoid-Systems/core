#!/usr/bin/env pwsh
# check-patched-files.ps1 — verify inventory/patched-files.sha256 against a
# patched upstream checkout. Refuses any drift, malformed manifest lines,
# unsafe relative paths, and silent skips. Never updates the lock.
# Retained inventory/patched-files.sha256 is the source of truth.
param(
    [Parameter(Mandatory = $true)]
    [string]$Upstream
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lab = Split-Path -Parent $here
$manifest = Join-Path $lab 'inventory/patched-files.sha256'

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

if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    Fail "patched-files manifest missing: $manifest"
}

$lines = @(Get-Content -LiteralPath $manifest -ErrorAction Stop)
if ($lines.Count -eq 0) {
    Fail "patched-files manifest is empty: $manifest"
}

$checked = 0
$lineNo = 0
foreach ($line in $lines) {
    $lineNo++
    $t = $line.Trim()
    if ($t.Length -eq 0) {
        continue
    }
    if ($t.StartsWith('#')) {
        continue
    }
    # Strict sha256sum format: "<64 hex>  <relative path>" (two spaces or ' *').
    if ($t -notmatch '^([0-9a-fA-F]{64})[ \t]+[*]?(.+)$') {
        Fail "malformed manifest line ${lineNo}: $line"
    }
    $expected = $Matches[1].ToLowerInvariant()
    $rel = $Matches[2].Trim()

    # Reject unsafe relative paths (absolute, drive-relative, traversal).
    if ($rel -match '^[a-zA-Z]:' -or $rel.StartsWith('/') -or $rel.StartsWith('\')) {
        Fail "unsafe absolute path in manifest line ${lineNo}: $rel"
    }
    if ($rel -match '(^|[/\\])\.\.([/\\]|$)') {
        Fail "unsafe path traversal in manifest line ${lineNo}: $rel"
    }
    if ($rel -match '[\0]') {
        Fail "NUL in manifest path line ${lineNo}"
    }

    $file = Join-Path $Upstream $rel
    $full = [System.IO.Path]::GetFullPath($file)
    if (-not $full.StartsWith($Upstream, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail "manifest path escapes upstream tree line ${lineNo}: $rel"
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Fail "patched file missing: $rel"
    }
    try {
        $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        Fail "failed to hash $rel`: $_"
    }
    if ($actual -ne $expected) {
        Fail "patched file hash mismatch: $rel`n  expected: $expected`n  actual:   $actual"
    }
    $checked++
}

if ($checked -eq 0) {
    Fail "no hash entries parsed from $manifest"
}
Write-Output "patched-files.sha256 OK ($checked files)"
exit 0
