# Fetch the PINNED Google WebRTC checkout + depot_tools into dedicated scratch.
# Exact commits come from inventory/upstream-pins.json. Prevents depot_tools
# self-update drift. No system gn/ninja fallback.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $PSScriptRoot
$pins = Get-Content (Join-Path $Here "inventory/upstream-pins.json") -Raw | ConvertFrom-Json
$SrcUrl = $pins.webrtc_src_url
$SrcCommit = $pins.webrtc_src_commit
$DepotUrl = $pins.depot_tools.url
$DepotCommit = $pins.depot_tools.commit

New-Item -ItemType Directory -Force -Path (Join-Path $Root "webrtc-checkout") | Out-Null
$Depot = Join-Path $Root "depot_tools"
if (-not (Test-Path (Join-Path $Depot ".git"))) {
    git init $Depot
    if ($LASTEXITCODE -ne 0) { throw "git init depot_tools failed" }
    git -C $Depot remote add origin $DepotUrl
    if ($LASTEXITCODE -ne 0) { throw "git remote add failed" }
    git -C $Depot fetch --depth 1 origin $DepotCommit
    if ($LASTEXITCODE -ne 0) { throw "git fetch depot_tools $DepotCommit failed" }
    git -C $Depot checkout -q FETCH_HEAD
    if ($LASTEXITCODE -ne 0) { throw "git checkout depot_tools failed" }
}
$DepotHead = (git -C $Depot rev-parse HEAD).Trim()
if ($DepotHead -ne $DepotCommit) { throw "depot_tools $DepotHead != pinned $DepotCommit" }

$env:DEPOT_TOOLS_UPDATE = "0"
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = "0"
$env:PATH = "$Depot;$env:PATH"

# Process-scoped Git config inherited by gclient child Git: canonical LF for
# DEPS raw-byte hashing on Windows. Appends to any caller GIT_CONFIG_COUNT
# entries; never writes machine/user/global git config.
$gcfgCount = 0
if ($null -ne $env:GIT_CONFIG_COUNT -and $env:GIT_CONFIG_COUNT -ne "") {
    $gcfgCount = [int]$env:GIT_CONFIG_COUNT
}
Set-Item -Path "env:GIT_CONFIG_KEY_$gcfgCount" -Value "core.autocrlf"
Set-Item -Path "env:GIT_CONFIG_VALUE_$gcfgCount" -Value "false"
Set-Item -Path "env:GIT_CONFIG_KEY_$($gcfgCount + 1)" -Value "core.eol"
Set-Item -Path "env:GIT_CONFIG_VALUE_$($gcfgCount + 1)" -Value "lf"
$env:GIT_CONFIG_COUNT = [string]($gcfgCount + 2)

Set-Location (Join-Path $Root "webrtc-checkout")
@"
solutions = [
  {
    "name": "src",
    "url": "$SrcUrl@$SrcCommit",
    "deps_file": "DEPS",
    "managed": False,
    "custom_deps": {},
    "custom_vars": {},
  },
]
target_os = ["win"]
"@ | Set-Content -Encoding ascii .gclient

# Run the exact pinned DEPS hooks (clang/SDK download etc.). DEPOT_TOOLS_UPDATE=0
# prevents depot self-update; DEPOT_TOOLS_WIN_TOOLCHAIN=0 prefers hosted VS.
gclient sync --no-history --revision "src@$SrcCommit"
if ($LASTEXITCODE -ne 0) { throw "gclient sync (with hooks) failed" }

$SrcHead = (git -C src rev-parse HEAD).Trim()
if ($SrcHead -ne $SrcCommit) { throw "src $SrcHead != pinned $SrcCommit" }

$DepsSha = (Get-FileHash -Algorithm SHA256 (Join-Path "src" "DEPS")).Hash.ToLower()
if ($DepsSha -ne $pins.deps_sha256) { throw "DEPS sha $DepsSha != pinned $($pins.deps_sha256)" }

Write-Host "src=$SrcHead"
Write-Host "depot_tools=$DepotHead"
Write-Host "deps_sha256=$DepsSha"
