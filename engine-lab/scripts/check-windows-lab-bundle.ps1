#!/usr/bin/env pwsh
# check-windows-lab-bundle.ps1 — validate a staged INERT UNSIGNED lab bundle.
#
# The bundle is the owned build output directory that retains the exact tested
# librustdesk.dll beside the existing harness/runtime files, plus a bounded
# versioned receipt (lab-bundle-receipt.json). This checker is an integrity /
# evidence gate only: it is NOT a signed release/update manifest checker and
# does not authorize anything.
#
# Fails closed on: missing receipt or retained DLL, malformed or oversized
# receipt, unsafe paths (backslash alias, colon/ADS/drive, dot/empty/
# trailing-dot-space components, case-alias duplicates, separator-boundary
# escape), links/reparse points, unknown members outside the explicit
# allowlist, wrong hash/size, non-x64 PE for the native DLL / C harness EXE /
# C# apphost EXE, export-list drift versus the retained header, vcpkg pin
# drift versus the frozen workflow pin, or any signing/release/update claim.
#
# External runtime prerequisites (MSVC x64 CRT + UCRT, .NET 10) are recorded
# in the receipt for the host to provide; this helper never installs them.

param(
    [Parameter(Mandatory = $true)]
    [string]$BundleDir,
    # One canonical bare filename. No separators, drive, ADS, or aliases.
    [string]$ReceiptName = 'lab-bundle-receipt.json'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lab = Split-Path -Parent $here

# Bounded parse limits (real gates, not advisory).
$script:MaxReceiptBytes = 262144          # 256 KiB receipt text
$script:MaxMembers      = 64
$script:MaxPathChars    = 200
$script:MaxNameChars    = 128
$script:MaxMemberBytes  = 268435456       # 256 MiB per member
$script:MaxTotalBytes   = 536870912       # 512 MiB declared+observed total
# Owned subdirectories only; no arbitrary whole-tree recursion.
$script:AllowedSubdirs  = @('pe', 'csharp-lifetime-check')

function Fail([string]$msg) {
    # Non-terminating write so `exit 1` always runs and $LASTEXITCODE is exact.
    Write-Error $msg -ErrorAction Continue
    exit 1
}

# --- canonical bare filename ------------------------------------------------
function Test-CanonicalFileName([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    if ($name.Length -gt $script:MaxNameChars) { return $false }
    if ($name -match '[\0]') { return $false }
    # Single component only: no separators of any kind.
    if ($name -match '[/\\]') { return $false }
    # Drive / ADS / colon alias.
    if ($name -match ':') { return $false }
    # Absolute or rooted.
    if ($name.StartsWith('.') -or $name.StartsWith(' ')) { return $false }
    # Dot / empty / trailing dot-space components are impossible in one
    # component, but trailing dot/space is a Windows path alias.
    if ($name -match '[\. ]$') { return $false }
    if ($name -eq '.' -or $name -eq '..') { return $false }
    # Reserved device names are never the canonical receipt.
    return $true
}

if (-not (Test-CanonicalFileName $ReceiptName)) {
    Fail "ReceiptName must be one canonical bare filename (got '$ReceiptName')"
}

# --- path safety -----------------------------------------------------------
if ($BundleDir -match '[\0]' -or $BundleDir -match '(^|[/\\])\.\.([/\\]|$)') {
    Fail "unsafe bundle path: $BundleDir"
}
if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
    Fail "bundle directory not found: $BundleDir"
}
$BundleDir = (Resolve-Path -LiteralPath $BundleDir).Path
# Containment prefix including trailing separator (separator boundary).
$bundlePrefix = $BundleDir.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

$receiptPath = Join-Path $BundleDir $ReceiptName
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    Fail "lab bundle receipt missing: $ReceiptName"
}

# Reject links/reparse on the receipt before reading it.
$receiptItem = Get-Item -LiteralPath $receiptPath -Force
if ($receiptItem.LinkType -or ($receiptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    Fail "lab bundle receipt is a link/reparse point; refusing to read: $ReceiptName"
}
if ($receiptItem.Length -gt $script:MaxReceiptBytes) {
    Fail "lab bundle receipt exceeds bounded size ($($receiptItem.Length) > $($script:MaxReceiptBytes) bytes)"
}

# --- receipt parse (bounded) ------------------------------------------------
try {
    $receiptText = [System.IO.File]::ReadAllText($receiptPath, [System.Text.Encoding]::UTF8)
} catch {
    Fail "failed to read lab bundle receipt: $($_.Exception.Message)"
}
if ($receiptText.Length -gt $script:MaxReceiptBytes) {
    Fail "lab bundle receipt text exceeds bounded size"
}
try {
    $receipt = $receiptText | ConvertFrom-Json -ErrorAction Stop
} catch {
    Fail "lab bundle receipt is not valid JSON: $($_.Exception.Message)"
}

$format = [string]$receipt.format
if ($format -ne 'hs-windows-lab-bundle-receipt/v1') {
    Fail "unsupported receipt format: '$format' (expected hs-windows-lab-bundle-receipt/v1)"
}

$kind = [string]$receipt.kind
if ($kind -ne 'inert-unsigned-lab-bundle') {
    Fail "receipt kind must be inert-unsigned-lab-bundle (got '$kind')"
}

# Evidence/integrity receipt only. Reject any release/update/signing claim.
$disp = $receipt.disposition
if (-not $disp) { Fail 'receipt.disposition is required' }
foreach ($flag in @('signed', 'release_manifest', 'update_manifest', 'authorization')) {
    if ($disp.$flag -ne $false) {
        Fail "receipt.disposition.$flag must be false (this is not a signed release/update manifest)"
    }
}

$claims = $receipt.claims
if (-not $claims) { Fail 'receipt.claims is required' }
if ($claims.bundle_role -ne 'INERT UNSIGNED LAB bundle') {
    Fail "receipt.claims.bundle_role must be 'INERT UNSIGNED LAB bundle'"
}
foreach ($k in @('connect', 'observation', 'channel_binding')) {
    if ($claims.$k -ne 'UNAVAILABLE') {
        Fail "receipt.claims.$k must be UNAVAILABLE (got '$($claims.$k)')"
    }
}

# --- architecture / ABI bounds --------------------------------------------
$arch = $receipt.architecture
if (-not $arch) { Fail 'receipt.architecture is required' }
if ($arch.os -ne 'windows' -or $arch.arch -ne 'x86_64') {
    Fail "receipt.architecture must be windows/x86_64 (got $($arch.os)/$($arch.arch))"
}
if ($arch.pe_machine -ne '8664') {
    Fail "receipt.architecture.pe_machine must be 8664 (got '$($arch.pe_machine)')"
}

$abi = $receipt.abi
if (-not $abi) { Fail 'receipt.abi is required' }
if ([int]$abi.version -ne 2) {
    Fail "receipt.abi.version must be 2 (got '$($abi.version)')"
}
if ([int]$abi.expected_export_count -ne 27) {
    Fail "receipt.abi.expected_export_count must be 27 (got '$($abi.expected_export_count)')"
}

# expected_exports must equal the retained header names exactly and uniquely.
$headerPath = Join-Path (Join-Path $lab 'native') 'hs_native.h'
if (-not (Test-Path -LiteralPath $headerPath -PathType Leaf)) {
    Fail "retained generated header missing: $headerPath"
}
$headerText = [System.IO.File]::ReadAllText($headerPath, [System.Text.Encoding]::UTF8)
$headerExports = [System.Collections.Generic.List[string]]::new()
$seenExport = @{}
foreach ($hline in ($headerText -split "`r?`n")) {
    if ($hline -match '^\s*(?:uint32_t|const char\s*\*)\s+(hs_\w+)\s*\(') {
        $hname = $Matches[1]
        if ($seenExport.ContainsKey($hname)) {
            Fail "duplicate export declaration in retained header: $hname"
        }
        $seenExport[$hname] = $true
        $headerExports.Add($hname)
    }
}
if ($headerExports.Count -ne 27) {
    Fail "retained header export count is $($headerExports.Count), expected 27"
}

$exportNames = @($abi.expected_exports)
if ($exportNames.Count -ne 27) {
    Fail "receipt.abi.expected_exports must list 27 names (got $($exportNames.Count))"
}
$receiptExportSet = @{}
foreach ($en in $exportNames) {
    $ens = [string]$en
    if ($ens -notmatch '^hs_[a-z0-9_]+$' -or $ens.Length -gt $script:MaxNameChars) {
        Fail "invalid export name in receipt: '$ens'"
    }
    if ($receiptExportSet.ContainsKey($ens)) {
        Fail "duplicate export name in receipt.abi.expected_exports: $ens"
    }
    $receiptExportSet[$ens] = $true
}
foreach ($hname in $headerExports) {
    if (-not $receiptExportSet.ContainsKey($hname)) {
        Fail "receipt.abi.expected_exports missing retained header export: $hname"
    }
}
foreach ($ens in $receiptExportSet.Keys) {
    if (-not $headerExports.Contains($ens)) {
        Fail "receipt.abi.expected_exports has name not in retained header: $ens"
    }
}

# --- frozen pins (cross-checked, not shape-only) ----------------------------
$pins = $receipt.pins
if (-not $pins) { Fail 'receipt.pins is required' }
foreach ($pk in @('upstream_commit', 'hbb_common_commit', 'vcpkg_commit_id')) {
    $v = [string]$pins.$pk
    if ($v -notmatch '^[0-9a-f]{40}$') {
        Fail "receipt.pins.$pk must be a 40-char hex sha (got '$v')"
    }
}
$lock = [string]$pins.lockfile_sha256
if ($lock -notmatch '^[0-9a-f]{64}$') {
    Fail "receipt.pins.lockfile_sha256 must be a 64-char hex sha256 (got '$lock')"
}

# Cross-check frozen pins against retained inventory/source-pin.txt.
$pinFile = Join-Path (Join-Path $lab 'inventory') 'source-pin.txt'
if (-not (Test-Path -LiteralPath $pinFile -PathType Leaf)) {
    Fail "inventory/source-pin.txt missing: $pinFile"
}
$pinText = [System.IO.File]::ReadAllText($pinFile, [System.Text.Encoding]::UTF8)
$inv = @{}
foreach ($line in ($pinText -split "`r?`n")) {
    $t = $line.Trim()
    if ($t -match '^(upstream_commit|submodule_hbb_common|lockfile_sha256):\s*(\S+)\s*$') {
        $key = $Matches[1]
        if ($inv.ContainsKey($key)) {
            Fail "duplicate pin in inventory/source-pin.txt: $key"
        }
        $inv[$key] = $Matches[2]
    }
}
if ($pins.upstream_commit -ne $inv['upstream_commit']) {
    Fail "receipt upstream_commit does not match inventory/source-pin.txt"
}
if ($pins.hbb_common_commit -ne $inv['submodule_hbb_common']) {
    Fail "receipt hbb_common_commit does not match inventory/source-pin.txt"
}
if ($pins.lockfile_sha256 -ne $inv['lockfile_sha256']) {
    Fail "receipt lockfile_sha256 does not match inventory/source-pin.txt"
}

# vcpkg pin must match the frozen workflow pin, not merely hex shape.
$workflowPath = Join-Path $lab '../.github/workflows/engine-windows.yml'
if (-not (Test-Path -LiteralPath $workflowPath -PathType Leaf)) {
    Fail "workflow with frozen vcpkg pin missing: $workflowPath"
}
$wfText = [System.IO.File]::ReadAllText($workflowPath, [System.Text.Encoding]::UTF8)
if ($wfText -notmatch 'VCPKG_COMMIT_ID:\s*"([0-9a-fA-F]{40})"') {
    Fail 'frozen VCPKG_COMMIT_ID pin not found in engine-windows.yml'
}
$frozenVcpkg = $Matches[1].ToLowerInvariant()
if ($pins.vcpkg_commit_id -ne $frozenVcpkg) {
    Fail "receipt vcpkg_commit_id '$($pins.vcpkg_commit_id)' does not match frozen workflow pin '$frozenVcpkg'"
}

$labSha = [string]$receipt.lab_source_git_sha
if ($labSha -notmatch '^[0-9a-f]{40}$') {
    Fail "receipt.lab_source_git_sha must be a 40-char hex sha (got '$labSha')"
}

# --- explicit member allowlist (no arbitrary role names) --------------------
# Required members and explicitly optional members only. Anything else fails.
$memberAllowlist = [ordered]@{
    'librustdesk.dll' = @{ Required = $true;  Role = 'exact-tested-dll' }
    'hs_native.generated.h' = @{ Required = $true;  Role = 'generated-header' }
    'windows-harness.exe' = @{ Required = $true;  Role = 'test-binary' }
    'csharp-lifetime-check/csharp-lifetime-check.exe' = @{ Required = $true;  Role = 'csharp-apphost' }
    'csharp-lifetime-check/csharp-lifetime-check.dll' = @{ Required = $true;  Role = 'csharp-assembly' }
    'csharp-lifetime-check/csharp-lifetime-check.deps.json' = @{ Required = $true;  Role = 'csharp-runtime-companion' }
    'csharp-lifetime-check/csharp-lifetime-check.runtimeconfig.json' = @{ Required = $true;  Role = 'csharp-runtime-companion' }
    'harness.txt' = @{ Required = $true;  Role = 'report' }
    'csharp.txt' = @{ Required = $true;  Role = 'report' }
    'rust-check.txt' = @{ Required = $true;  Role = 'report' }
    'rust-tests.txt' = @{ Required = $true;  Role = 'report' }
    'rust-build.txt' = @{ Required = $true;  Role = 'report' }
    'frozen-hashes-before.txt' = @{ Required = $true;  Role = 'report' }
    'frozen-hashes-after.txt' = @{ Required = $true;  Role = 'report' }
    'pins.txt' = @{ Required = $true;  Role = 'report' }
    'pe/headers.txt' = @{ Required = $true;  Role = 'pe-evidence' }
    'pe/imports.txt' = @{ Required = $true;  Role = 'pe-evidence' }
    'pe/exports.txt' = @{ Required = $true;  Role = 'pe-evidence' }
    'pe/hs-exports-expected.txt' = @{ Required = $true;  Role = 'pe-evidence' }
    'pe/hs-exports-actual.txt' = @{ Required = $true;  Role = 'pe-evidence' }
    'harness-staged.txt' = @{ Required = $true;  Role = 'report' }
    'csharp-staged.txt' = @{ Required = $true;  Role = 'report' }
    'librustdesk.dll.lib' = @{ Required = $false; Role = 'import-library' }
    'librustdesk.lib' = @{ Required = $false; Role = 'import-library' }
    'windows-harness.obj' = @{ Required = $false; Role = 'compile-sidecar' }
    'windows-harness.ilk' = @{ Required = $false; Role = 'compile-sidecar' }
    'windows-harness.pdb' = @{ Required = $false; Role = 'compile-sidecar' }
    'csharp-lifetime-check/csharp-lifetime-check.pdb' = @{ Required = $false; Role = 'compile-sidecar' }
    'csharp-build.txt' = @{ Required = $false; Role = 'report' }
}

$files = @($receipt.files)
if ($files.Count -eq 0) {
    Fail 'receipt.files must list retained members'
}
if ($files.Count -gt $script:MaxMembers) {
    Fail "receipt.files exceeds bounded member count ($($files.Count) > $($script:MaxMembers))"
}

# --- strict relative path validation ---------------------------------------
function Get-SafeRelativePath([string]$rel) {
    if ([string]::IsNullOrWhiteSpace($rel)) { Fail 'empty path in receipt.files' }
    if ($rel.Length -gt $script:MaxPathChars) {
        Fail "path exceeds bounded length: $rel"
    }
    if ($rel -match '[\0]') { Fail "NUL in receipt path: $rel" }
    # Canonical receipt paths use forward slashes only; reject backslash aliases.
    if ($rel -match '\\') {
        Fail "backslash path alias rejected (use canonical '/' form): $rel"
    }
    # Drive letters / ADS / colon alias.
    if ($rel -match ':') {
        Fail "colon/drive/ADS path rejected: $rel"
    }
    # Absolute or rooted.
    if ($rel.StartsWith('/') -or $rel.StartsWith('~')) {
        Fail "unsafe absolute path in receipt.files: $rel"
    }
    $parts = $rel.Split('/')
    if ($parts.Count -eq 0) { Fail "empty path in receipt.files: $rel" }
    foreach ($part in $parts) {
        if ($part.Length -eq 0) {
            Fail "empty path component rejected: $rel"
        }
        if ($part -eq '.' -or $part -eq '..') {
            Fail "dot path component rejected: $rel"
        }
        # Windows strips trailing dots/spaces; treat as alias and reject.
        if ($part -match '[\. ]$') {
            Fail "trailing dot/space path component rejected: $rel"
        }
        if ($part -match '^[\. ]') {
            Fail "leading dot/space path component rejected: $rel"
        }
    }
    return $rel
}

function Test-NoReparsePath([string]$bundleRoot, [string]$rel) {
    # Reject links/reparse on any existing ancestor inside the bundle before
    # reading or hashing the member.
    $acc = $bundleRoot
    $parts = $rel.Split('/')
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $acc = Join-Path $acc $parts[$i]
        if (-not (Test-Path -LiteralPath $acc)) {
            return  # missing handled by the caller
        }
        $item = Get-Item -LiteralPath $acc -Force
        if ($item.LinkType -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Fail "link/reparse point in bundle path refused: $rel (at $($parts[$i]))"
        }
    }
}

$listed = @{}
$listedLower = @{}
$script:declaredTotal = [int64]0
$script:observedTotal = [int64]0
foreach ($f in $files) {
    if (-not $f) { Fail 'null entry in receipt.files' }
    $rel = Get-SafeRelativePath ([string]$f.path)

    # Case-insensitive uniqueness (Windows path alias).
    $relLower = $rel.ToLowerInvariant()
    if ($listedLower.ContainsKey($relLower)) {
        Fail "duplicate/case-alias path in receipt.files: $rel"
    }

    if (-not $memberAllowlist.Contains($rel)) {
        Fail "member outside explicit allowlist refused: $rel"
    }

    $expectedRole = $memberAllowlist[$rel].Role
    $role = [string]$f.role
    if ($role -ne $expectedRole) {
        Fail "role mismatch for $rel`: got '$role', expected '$expectedRole'"
    }

    $expectedHash = ([string]$f.sha256).ToLowerInvariant()
    if ($expectedHash -notmatch '^[0-9a-f]{64}$') {
        Fail "invalid sha256 for $rel`: '$($f.sha256)'"
    }
    if ($null -eq $f.size -or [string]::IsNullOrWhiteSpace([string]$f.size)) {
        Fail "missing size for $rel"
    }
    try {
        $expectedSize = [int64]$f.size
    } catch {
        Fail "invalid size for $rel`: '$($f.size)'"
    }
    if ($expectedSize -lt 0) {
        Fail "negative size for $rel"
    }
    if ($expectedSize -gt $script:MaxMemberBytes) {
        Fail "member size exceeds bounded maximum ($expectedSize > $($script:MaxMemberBytes)): $rel"
    }
    $script:declaredTotal += $expectedSize
    if ($script:declaredTotal -gt $script:MaxTotalBytes) {
        Fail "declared bundle size exceeds bounded total ($($script:declaredTotal) > $($script:MaxTotalBytes))"
    }

    # Containment with separator boundary (not bare StartsWith).
    $full = Join-Path $BundleDir ($rel.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $resolved = [System.IO.Path]::GetFullPath($full)
    if (-not ($resolved.StartsWith($bundlePrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
        Fail "receipt path escapes bundle directory: $rel"
    }

    Test-NoReparsePath $BundleDir $rel

    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Fail "retained bundle member missing: $rel"
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.LinkType -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Fail "bundle member is a link/reparse point refused: $rel"
    }
    if ($item.Length -ne $expectedSize) {
        Fail "size mismatch for $rel`: expected $expectedSize actual $($item.Length)"
    }
    if ($item.Length -gt $script:MaxMemberBytes) {
        Fail "observed member size exceeds bounded maximum ($($item.Length) > $($script:MaxMemberBytes)): $rel"
    }
    $script:observedTotal += $item.Length
    if ($script:observedTotal -gt $script:MaxTotalBytes) {
        Fail "observed bundle size exceeds bounded total ($($script:observedTotal) > $($script:MaxTotalBytes))"
    }
    try {
        $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        Fail "failed to hash $rel`: $_"
    }
    if ($actualHash -ne $expectedHash) {
        Fail "hash mismatch for $rel`n  expected: $expectedHash`n  actual:   $actualHash"
    }
    $listed[$rel] = @{
        Path = $rel
        Role = $expectedRole
        Sha256 = $actualHash
        Size = $expectedSize
        Full = $resolved
    }
    $listedLower[$relLower] = $true
}

# --- bounded owned-directory membership walk (before required / PE) --------
# Allow only owned subdirs (pe, csharp-lifetime-check). No arbitrary whole-tree
# recursion. Unknown directories and links/reparse fail before descent.
function Get-BundleMembers {
    $found = [System.Collections.Generic.List[string]]::new()
    $top = Get-ChildItem -LiteralPath $BundleDir -Force
    foreach ($entry in $top) {
        if ($entry.LinkType -or ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Fail "link/reparse point in bundle refused: $($entry.Name)"
        }
        if ($entry.PSIsContainer) {
            if ($script:AllowedSubdirs -notcontains $entry.Name) {
                Fail "unexpected directory in lab bundle (only $($script:AllowedSubdirs -join ', ') allowed): $($entry.Name)"
            }
            $sub = Get-ChildItem -LiteralPath $entry.FullName -Force
            foreach ($child in $sub) {
                if ($child.LinkType -or ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    Fail "link/reparse point in bundle refused: $($entry.Name)/$($child.Name)"
                }
                if ($child.PSIsContainer) {
                    Fail "unexpected nested directory in lab bundle: $($entry.Name)/$($child.Name)"
                }
                $found.Add("$($entry.Name)/$($child.Name)")
            }
            continue
        }
        $found.Add($entry.Name)
    }
    return $found
}

# Membership consistency completes before required/PE gates so unlisted or
# unknown paths fail on their own gate (local archive probes stay honest).
$bundleMembers = Get-BundleMembers
if (@($bundleMembers).Count -gt $script:MaxMembers + 1) {
    Fail "bundle file enumeration exceeds bounded count ($(@($bundleMembers).Count))"
}
foreach ($rel in $bundleMembers) {
    if ($rel -eq $ReceiptName) {
        continue
    }
    if (-not $listed.ContainsKey($rel)) {
        Fail "unlisted file in lab bundle: $rel"
    }
}

# Required allowlist members must be present and listed (includes staged
# harness/csharp reports; real native CI supplies those reports).
foreach ($req in $memberAllowlist.Keys) {
    $entry = $memberAllowlist[$req]
    if (-not $entry.Required) { continue }
    if (-not $listed.ContainsKey($req)) {
        Fail "required bundle member not listed in receipt: $req"
    }
}

# Exact tested DLL name only — refuse a differently named "first DLL".
if (-not $listed.ContainsKey('librustdesk.dll')) {
    Fail 'required bundle member not listed in receipt: librustdesk.dll'
}
$dllEntry = $listed['librustdesk.dll']
if ($dllEntry.Role -ne 'exact-tested-dll') {
    Fail 'librustdesk.dll must carry role exact-tested-dll'
}

# Import library only at declared exact filenames.
foreach ($k in $listed.Keys) {
    if ($listed[$k].Role -eq 'import-library') {
        if ($k -notin @('librustdesk.dll.lib', 'librustdesk.lib')) {
            Fail "import-library must use the declared exact filename (got $k)"
        }
    }
}

# --- PE machine gates (native ABI members only) -----------------------------
function Get-PeMachine([string]$path) {
    $fs = [System.IO.File]::OpenRead($path)
    try {
        if ($fs.Length -lt 64) { return $null }
        $br = [System.IO.BinaryReader]::new($fs)
        $fs.Position = 0
        $mz = $br.ReadUInt16()
        if ($mz -ne 0x5A4D) { return $null }
        $fs.Position = 0x3C
        $e_lfanew = $br.ReadUInt32()
        if (($e_lfanew + 6) -gt $fs.Length) { return $null }
        if ($e_lfanew -gt 4096) { return $null }
        $fs.Position = $e_lfanew
        $pe = $br.ReadUInt32()
        if ($pe -ne 0x00004550) { return $null }
        return $br.ReadUInt16()
    } finally {
        $fs.Dispose()
    }
}

function Assert-PeX64([string]$label, $entry) {
    $machine = Get-PeMachine $entry.Full
    if ($null -eq $machine) {
        Fail "$label is not a parseable PE image (missing MZ/PE signature)"
    }
    if ($machine -eq 0x14C) {
        Fail "$label PE machine is i386 (14C); expected x64 (8664)"
    }
    if ($machine -ne 0x8664) {
        Fail ("$label PE machine is 0x{0:X4}; expected x64 (8664)" -f $machine)
    }
}

# Native DLL, C harness EXE, and C# apphost EXE must be x64. The managed C#
# assembly may legitimately be AnyCPU and is not a native ABI member.
Assert-PeX64 'retained DLL' $dllEntry
Assert-PeX64 'C harness EXE' $listed['windows-harness.exe']
Assert-PeX64 'C# apphost EXE' $listed['csharp-lifetime-check/csharp-lifetime-check.exe']
$csAssembly = $listed['csharp-lifetime-check/csharp-lifetime-check.dll']
$csMachine = Get-PeMachine $csAssembly.Full
if ($null -eq $csMachine) {
    Fail 'managed C# assembly is not a parseable PE image'
}

# --- external prerequisites must describe measured imports ------------------
$prereq = $receipt.external_prerequisites
if (-not $prereq) { Fail 'receipt.external_prerequisites is required' }
if (-not $prereq.note -or [string]$prereq.note -notmatch 'Not installed') {
    Fail 'receipt.external_prerequisites.note must state that prerequisites are not installed by this helper'
}
$nh = (@($prereq.native_harness) | ForEach-Object { "$_" }) -join ' '
$cs = (@($prereq.csharp_lifetime_check) | ForEach-Object { "$_" }) -join ' '
if ($nh -notmatch 'MSVCP140' -or $nh -notmatch 'VCRUNTIME140' -or $nh -notmatch 'VCRUNTIME140_1') {
    Fail 'external_prerequisites.native_harness must name measured MSVC CRT imports (MSVCP140, VCRUNTIME140, VCRUNTIME140_1)'
}
if ($nh -notmatch 'Universal CRT|api-ms-win-crt|UCRT') {
    Fail 'external_prerequisites.native_harness must name the Universal CRT'
}
if ($cs -notmatch '\.NET 10' -and $cs -notmatch 'Microsoft\.NETCore\.App') {
    Fail 'external_prerequisites.csharp_lifetime_check must name the .NET 10 runtime'
}

Write-Output "lab bundle OK: $($listed.Count) retained members, DLL $($dllEntry.Sha256) ($($dllEntry.Size) bytes), PE x64 (8664)"
Write-Output 'note: inert unsigned lab bundle; connect/observation/channel_binding remain UNAVAILABLE'
exit 0
