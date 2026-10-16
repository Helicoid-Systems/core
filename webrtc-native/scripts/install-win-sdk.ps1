# Bounded official Windows SDK 10.0.28000 prerequisite for native CI.
# Independently usable: preflight-only or download+verify+install+preflight.
#
# Trust contract (fail closed):
#   - Pinned official installer: SHA256 + size + Authenticode Valid + Microsoft
#     publisher + PE product identity, all observed before execution.
#   - Existing SDK is "complete" only when required files are present AND
#     non-empty AND observed installed servicing metadata matches the chosen
#     exact policy. Empty placeholders / unknown servicing are NOT pinned.
#   - Provenance separates expected pin fields from observed host fields and
#     records whether the installer was actually checked and/or executed.
#
# Lifecycle contract:
#   - Immutable official resolved HTTPS URL (not the fwlink hop).
#   - Bounded download (timeout + exact byte size) and bounded installer wait.
#   - On timeout, terminate only this script's process tree. Parent cleanup
#     in finally. Never kill unrelated/global processes.
#
# Usage:
#   ./install-win-sdk.ps1                # preflight; install if incomplete/unknown
#   ./install-win-sdk.ps1 -PreflightOnly # verify only; no download/install
#   ./install-win-sdk.ps1 -WorkDir <dir> # download/log scratch
param(
    [switch]$PreflightOnly,
    [string]$WorkDir = $(Join-Path ([System.IO.Path]::GetTempPath()) "hs-win-sdk-setup"),
    [int]$DownloadTimeoutSec = 120,
    [int]$InstallTimeoutSec = 900
)
$ErrorActionPreference = "Stop"
# Supported host is PowerShell 7+ (workflow `shell: pwsh`). Bound timeout knobs.
if ($DownloadTimeoutSec -lt 5 -or $DownloadTimeoutSec -gt 600) {
    throw "DownloadTimeoutSec must be 5..600 (got $DownloadTimeoutSec)"
}
if ($InstallTimeoutSec -lt 30 -or $InstallTimeoutSec -gt 3600) {
    throw "InstallTimeoutSec must be 30..3600 (got $InstallTimeoutSec)"
}
$Here = Split-Path -Parent $PSScriptRoot
$PinsPath = Join-Path $Here "inventory/win-sdk-pins.json"
if (-not (Test-Path $PinsPath)) { throw "missing pin manifest $PinsPath" }
$pins = Get-Content $PinsPath -Raw | ConvertFrom-Json

$SdkFolder = $pins.sdk_version_folder
$Servicing = $pins.servicing_version
$ExpectedSha = $pins.installer.sha256.ToLowerInvariant()
$ExpectedSize = [int64]$pins.installer.size_bytes
$ExpectedProduct = $pins.installer.product_name
$ExpectedCompany = $pins.installer.company_name
# Prefer the immutable download.microsoft.com URL already pinned.
$DownloadUrl = $pins.official_sources.installer_resolved
if (-not $DownloadUrl) { $DownloadUrl = $pins.official_sources.installer_fwlink }
$Features = @($pins.install_features)
$PreflightRel = @($pins.preflight_relative_paths)

function Write-Info([string]$Msg) { Write-Host "[win-sdk] $Msg" }
function Require([bool]$Cond, [string]$Msg) {
    if (-not $Cond) { throw "win-sdk fail-closed: $Msg" }
}

function Get-KitsRoot {
    foreach ($r in @(${env:ProgramFiles(x86)}, $env:ProgramFiles) | Where-Object { $_ }) {
        $p = Join-Path $r "Windows Kits\10"
        if (Test-Path $p) { return $p }
    }
    $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" -ErrorAction SilentlyContinue
    if ($reg -and $reg.KitsRoot10) { return $reg.KitsRoot10 }
    return $null
}

function Test-SdkPreflight {
    # File-level preflight. "present" requires a non-empty file — empty
    # placeholders are insufficient and must not look complete.
    param([string]$KitsRoot)
    $missing = @()
    $empty = @()
    $present = @()
    if (-not $KitsRoot -or -not (Test-Path $KitsRoot)) {
        return @{ ok = $false; missing = @("KitsRoot10"); empty = @(); present = @(); root = $KitsRoot }
    }
    foreach ($rel in $PreflightRel) {
        $full = Join-Path $KitsRoot $rel
        if (-not (Test-Path $full)) {
            $missing += $rel
            continue
        }
        $item = Get-Item $full -ErrorAction SilentlyContinue
        if (-not $item -or $item.Length -le 0) {
            $empty += $rel
            continue
        }
        $present += $rel
    }
    return @{
        ok     = (($missing.Count -eq 0) -and ($empty.Count -eq 0))
        missing = $missing
        empty   = $empty
        present = $present
        root    = $KitsRoot
    }
}

function Get-ObservedServicing {
    # Observe installed SDK servicing identity from host metadata.
    # Unversioned Include folder names alone are NOT servicing proof.
    param([string]$KitsRoot, [string]$SdkFolder)
    $hits = @()
    $matched = $null
    $source = "none"

    # (a) Uninstall registry entries for the Windows SDK product.
    foreach ($uPath in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )) {
        $entries = Get-ItemProperty $uPath -ErrorAction SilentlyContinue
        foreach ($e in @($entries)) {
            if (-not $e.DisplayName) { continue }
            if ($e.DisplayName -notlike "*Windows Software Development Kit*") { continue }
            $ver = "$($e.DisplayVersion)"
            $hits += "uninstall:$($e.DisplayName)|DisplayVersion=$ver"
            if ($ver -eq $Servicing -or $e.DisplayName -like "*$Servicing*") {
                $matched = $Servicing
                $source = "uninstall-registry"
            }
        }
    }

    # (b) Microsoft SDKs Windows v10.0 product registration.
    foreach ($sdkKey in @(
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0",
            "HKLM:\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0"
        )) {
        $r = Get-ItemProperty $sdkKey -ErrorAction SilentlyContinue
        if (-not $r) { continue }
        $pv = "$($r.ProductVersion)"
        $hits += "ms-sdks:$pv|ProductName=$($r.ProductName)"
        if ($pv -eq $Servicing) {
            $matched = $Servicing
            if ($source -eq "none") { $source = "ms-sdks-registry" }
        }
    }

    # (c) Installed tool FileVersion (empty/placeholder files carry none).
    if ($KitsRoot) {
        foreach ($toolRel in @(
                "bin/$SdkFolder/x64/rc.exe",
                "Debuggers/x64/dbghelp.dll"
            )) {
            $tool = Join-Path $KitsRoot $toolRel
            if (-not (Test-Path $tool)) { continue }
            $vi = (Get-Item $tool).VersionInfo
            $fv = "$($vi.FileVersion)"
            $pv = "$($vi.ProductVersion)"
            $hits += "tool:$toolRel|FileVersion=$fv|ProductVersion=$pv"
            if (-not $matched) {
                if ($fv -like "$Servicing*" -or $pv -like "$Servicing*" -or
                    $fv -like "*28000.2957*" -or $pv -like "*28000.2957*") {
                    $matched = $Servicing
                    if ($source -eq "none") { $source = "tool-file-version" }
                } elseif ($fv -or $pv) {
                    # A real tool version that is not our servicing policy.
                    if ($source -eq "none") { $source = "tool-file-version-mismatch" }
                }
            }
        }
    }

    return @{
        observed_servicing_version = $matched
        observed_source            = $source
        observed_details           = $hits
    }
}

function Get-InstallerProductInfo {
    param([string]$ExePath)
    $vi = (Get-Item $ExePath).VersionInfo
    return @{
        ProductName      = $vi.ProductName
        CompanyName      = $vi.CompanyName
        FileVersion      = $vi.FileVersion
        ProductVersion   = $vi.ProductVersion
        OriginalFilename = $vi.OriginalFilename
    }
}

function Assert-InstallerTrust {
    param([string]$ExePath)
    Require (Test-Path $ExePath) "installer missing at $ExePath"
    $item = Get-Item $ExePath
    Require ($item.Length -gt 0) "installer is empty"
    # Exact size from the pin; no "about right" download acceptance.
    Require ($item.Length -eq $ExpectedSize) "installer size $($item.Length) != pinned $ExpectedSize"

    $sha = (Get-FileHash -Algorithm SHA256 $ExePath).Hash.ToLowerInvariant()
    Require ($sha -eq $ExpectedSha) "installer sha256 $sha != pinned $ExpectedSha"

    # Windows Authenticode: must be Valid and Microsoft publisher.
    $sig = Get-AuthenticodeSignature -FilePath $ExePath
    Require ($sig.Status -eq "Valid") "Authenticode status $($sig.Status) != Valid"
    $pub = $sig.SignerCertificate.Subject
    Require ($pub -match [regex]::Escape($ExpectedCompany)) "Authenticode subject '$pub' missing '$ExpectedCompany'"

    $info = Get-InstallerProductInfo -ExePath $ExePath
    Require ($info.ProductName -eq $ExpectedProduct) "ProductName '$($info.ProductName)' != pinned '$ExpectedProduct'"
    Require ($info.CompanyName -eq $ExpectedCompany) "CompanyName '$($info.CompanyName)' != pinned"
    Write-Info "installer trusted sha=$sha authenticode=Valid publisher_ok product=$($info.ProductName)"
    return @{
        sha256         = $sha
        authenticode   = "Valid"
        product        = $info.ProductName
        file_version   = $info.FileVersion
        checked        = $true
    }
}

function Invoke-BoundedDownload {
    param([string]$Url, [string]$OutFile)
    Require ($Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) "download URL must be immutable HTTPS: $Url"
    Write-Info "downloading official installer $Url (timeout ${DownloadTimeoutSec}s, ceiling $ExpectedSize bytes)"
    # Stream with a hard byte ceiling enforced while reading (not after write).
    # CTS is passed to header and body operations: ResponseHeadersRead ends
    # HttpClient.Timeout at headers, so body ReadAsync must take the token.
    $timeout = [TimeSpan]::FromSeconds($DownloadTimeoutSec)
    $cts = New-Object System.Threading.CancellationTokenSource
    $cts.CancelAfter($timeout)
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = $timeout
    $response = $null
    $src = $null
    $dst = $null
    try {
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "download HTTP $([int]$response.StatusCode) from $Url"
        }
        # PowerShell unwraps Nullable<long>: use $null -ne, not .HasValue/.Value.
        $cl = $response.Content.Headers.ContentLength
        if ($null -ne $cl) {
            Require ([int64]$cl -eq $ExpectedSize) "Content-Length $([int64]$cl) != pinned $ExpectedSize"
        }
        $src = $response.Content.ReadAsStreamAsync($cts.Token).GetAwaiter().GetResult()
        $buf = New-Object byte[] 65536
        $total = [int64]0
        $dst = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        while ($true) {
            $n = $src.ReadAsync($buf, 0, $buf.Length, $cts.Token).GetAwaiter().GetResult()
            if ($n -le 0) { break }
            $total += $n
            if ($total -gt $ExpectedSize) {
                throw "download exceeded byte ceiling $ExpectedSize at $total"
            }
            $dst.Write($buf, 0, $n)
        }
        Require ($total -eq $ExpectedSize) "downloaded $total bytes != pinned $ExpectedSize"
        Write-Info "download complete bytes=$total"
    } finally {
        if ($dst) { $dst.Dispose() }
        if ($src) { $src.Dispose() }
        if ($response) { $response.Dispose() }
        $cts.Dispose()
        $client.Dispose()
    }
}

function Stop-OwnedProcess {
    # Kill only the exact Process object this script started. Use Kill(true)
    # for the owned tree. No PID lookup (reused PIDs) and no taskkill/global kill.
    param([System.Diagnostics.Process]$Process)
    if (-not $Process) { return }
    if ($Process.HasExited) {
        Write-Info "owned process id=$($Process.Id) already exited"
        return
    }
    Write-Info "timeout: terminating owned process tree id=$($Process.Id)"
    $Process.Kill($true)
    if (-not $Process.WaitForExit(15000)) {
        throw "owned process id=$($Process.Id) did not exit within 15s after Kill"
    }
}

function Invoke-OfficialInstall {
    param([string]$ExePath, [string]$LogPath)
    # Documented WinSDKSetup.exe features only. /quiet /norestart.
    # Exit codes: 0 success; 3010 reboot requested — not treated as success
    # without a usable post-install toolchain preflight.
    Write-Info "install features: $($Features -join ', ') (timeout ${InstallTimeoutSec}s)"
    # Explicitly quote /log (WorkDir may contain spaces).
    $logArg = '"' + $LogPath + '"'
    $featArg = $Features -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.Arguments = "/quiet /norestart /log $logArg /features $featArg"
    $psi.UseShellExecute = $false
    # Quiet GUI installer: do not redirect stdout/stderr. Redirect + WaitForExit
    # before ReadToEnd invites pipe deadlock; streams are unused under /quiet.
    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        Require ($null -ne $proc) "failed to start $ExePath"
        $ms = [int]($InstallTimeoutSec * 1000)
        if (-not $proc.WaitForExit($ms)) {
            Stop-OwnedProcess -Process $proc
            Require $false "winsdksetup exceeded ${InstallTimeoutSec}s; terminated own process tree only"
        }
        $code = $proc.ExitCode
        Write-Info "winsdksetup exit=$code"
        Require ($code -eq 0 -or $code -eq 3010) "winsdksetup exit $code not 0/3010"
        return $code
    } finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-OwnedProcess -Process $proc
        }
        if ($proc) { $proc.Dispose() }
    }
}

function Write-PrereqRecord {
    param(
        [hashtable]$Preflight,
        [hashtable]$ServicingInfo,
        [string]$Outcome,
        [hashtable]$Trust = $null,
        [object]$InstallExit = $null,
        [bool]$InstallerChecked = $false,
        [bool]$InstallerExecuted = $false
    )
    $prov = Join-Path $Here "inventory/win-sdk-prereq.txt"
    $details = ($ServicingInfo.observed_details -join '; ')
    if (-not $details) { $details = "(none)" }
    $lines = @(
        "# hs-win-sdk-prereq record (observed vs expected must not be conflated)"
        "# expected_* come from inventory/win-sdk-pins.json (policy only)"
        "expected_sdk_version_folder=$SdkFolder"
        "expected_servicing_version=$Servicing"
        "expected_installer_sha256=$ExpectedSha"
        "expected_installer_url=$DownloadUrl"
        "expected_features=$($Features -join ',')"
        "# observed_* are host facts from this run only"
        "observed_kits_root=$($Preflight.root)"
        "observed_preflight_present=$($Preflight.present.Count)"
        "observed_preflight_empty=$($Preflight.empty.Count)"
        "observed_preflight_missing=$($Preflight.missing.Count)"
        "observed_servicing_source=$($ServicingInfo.observed_source)"
        "observed_servicing_version=$($ServicingInfo.observed_servicing_version)"
        "observed_servicing_details=$details"
        "installer_checked=$(if ($InstallerChecked) { 'true' } else { 'false' })"
        "installer_authenticode=$(if ($Trust) { $Trust.authenticode } else { 'not-checked' })"
        "installer_sha256_observed=$(if ($Trust) { $Trust.sha256 } else { 'not-checked' })"
        "installer_product_observed=$(if ($Trust) { $Trust.product } else { 'not-checked' })"
        "installer_file_version_observed=$(if ($Trust) { $Trust.file_version } else { 'not-checked' })"
        "installer_executed=$(if ($InstallerExecuted) { 'true' } else { 'false' })"
        "winsdksetup_exit=$(if ($null -ne $InstallExit) { $InstallExit } else { 'not-executed' })"
        "outcome=$Outcome"
        "checked_at=$(Get-Date -Format o)"
    )
    $lines | Set-Content -Encoding ascii $prov
    Write-Info "wrote validated prerequisite record $prov"
}

# --- main ---
Write-Info "pins: folder=$SdkFolder expected_servicing=$Servicing"
Write-Info "policy URL: $DownloadUrl"
$kits = Get-KitsRoot
$pre = Test-SdkPreflight -KitsRoot $kits
$svc = Get-ObservedServicing -KitsRoot $kits -SdkFolder $SdkFolder
$pathsOk = $pre.ok
$svcOk = ($svc.observed_servicing_version -eq $Servicing)

if ($pathsOk -and $svcOk) {
    Write-Info "preflight complete and servicing observed: $($svc.observed_servicing_version) via $($svc.observed_source) at $($pre.root)"
    Write-PrereqRecord -Preflight $pre -ServicingInfo $svc -Outcome "existing-complete" -InstallerChecked $false -InstallerExecuted $false
    if ($PreflightOnly) {
        Write-Host "win-sdk preflight ok (existing, servicing observed)"
        exit 0
    }
    Write-Info "existing SDK matches exact servicing policy; installer not required"
    Write-Host "win-sdk preflight ok (existing, servicing observed)"
    exit 0
}

# Paths complete but servicing unknown/mismatch: do NOT label pinned/trusted.
if ($pathsOk -and -not $svcOk) {
    Write-Info "paths present but servicing not verified (source=$($svc.observed_source) observed='$($svc.observed_servicing_version)' expected='$Servicing')"
    Write-Info "existing SDK must not be labeled pinned/trusted; repair/install or fail"
    if ($PreflightOnly) {
        # Dry-run: report failure only. Do not overwrite inventory provenance.
        Require $false "preflight-only: paths exist but observed servicing != $Servicing (source=$($svc.observed_source))"
    }
} else {
    Write-Info "incomplete preflight: missing=$($pre.missing.Count) empty=$($pre.empty.Count) (empty placeholders are not complete)"
    if ($PreflightOnly) {
        # Dry-run: report failure only. Do not overwrite inventory provenance.
        Require $false "preflight-only mode but SDK $SdkFolder is incomplete at '$($pre.root)' (missing=$($pre.missing.Count) empty=$($pre.empty.Count))"
    }
}

# Install/repair the pinned official servicing package (disposable runner only).
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$ExePath = Join-Path $WorkDir "winsdksetup.exe"
$LogPath = Join-Path $WorkDir "winsdksetup-install.log"
try {
    if (Test-Path $ExePath) {
        Write-Info "reusing download at $ExePath (sha will be re-checked)"
    } else {
        Invoke-BoundedDownload -Url $DownloadUrl -OutFile $ExePath
    }
    $trust = Assert-InstallerTrust -ExePath $ExePath

    $code = Invoke-OfficialInstall -ExePath $ExePath -LogPath $LogPath
    $kits2 = Get-KitsRoot
    $pre2 = Test-SdkPreflight -KitsRoot $kits2
    $svc2 = Get-ObservedServicing -KitsRoot $kits2 -SdkFolder $SdkFolder
    if ($code -eq 3010) {
        Write-Info "installer requested reboot (3010); re-running preflight on current filesystem"
    }
    # Reboot is not silent success: usable toolchain proof is file-level
    # preflight PLUS observed servicing metadata matching policy.
    Require $pre2.ok "post-install preflight failed; missing=$($pre2.missing.Count) empty=$($pre2.empty.Count); missing=$($pre2.missing -join '; ') empty=$($pre2.empty -join '; ')"
    Require ($svc2.observed_servicing_version -eq $Servicing) "post-install observed servicing '$($svc2.observed_servicing_version)' != '$Servicing' (source=$($svc2.observed_source))"

    Write-PrereqRecord -Preflight $pre2 -ServicingInfo $svc2 -Outcome "installed-or-repaired" -Trust $trust -InstallExit $code -InstallerChecked $true -InstallerExecuted $true
    Write-Host "win-sdk preflight ok (installed, servicing observed)"
    exit 0
} finally {
    # Parent cleanup: drop the downloaded installer from scratch so a failed
    # or timed-out run does not leave a large tree. Never touch other caches.
    if ($ExePath -and (Test-Path $ExePath)) {
        Remove-Item -Force $ExePath -ErrorAction SilentlyContinue
    }
}
