# Build and run the C# wrapper runtime check against hs_webrtc_shared.dll.
# Uses the hosted .NET SDK on the runner (or DOTNET_ROOT). Fails closed.
param(
    [Parameter(Mandatory=$true)][string]$Root,
    [string]$Out = "out-win-x64"
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $PSScriptRoot
$Src = Join-Path $Root "webrtc-checkout/src"
$OutDir = Join-Path $Src "out/$Out"
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet not found on PATH (hosted SDK expected on windows-2022)"
}
$env:PATH = "$OutDir;$env:PATH"
$Proj = Join-Path $Here "native/runtime/csharp_runtime_check.csproj"
Write-Host "==> dotnet build/run $Proj"
dotnet build $Proj -c Release -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed" }
dotnet run --project $Proj -c Release --no-build
if ($LASTEXITCODE -ne 0) { throw "dotnet run failed" }
