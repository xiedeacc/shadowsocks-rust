#!pwsh
# Launches deploy_windows.ps1 -Action Run in an elevated child window so
# the user can browse with Chrome while sslocal stays in foreground.
#
# - Stays attached in the elevated window until the user hits Ctrl-C or
#   closes the window. deploy_windows.ps1 then rolls back routes / DNS /
#   processes itself.
# - This wrapper returns immediately so the caller (Cursor agent) does
#   not block; the user owns the elevated window.
$ErrorActionPreference = "Stop"
$Root        = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$DeployPath  = Join-Path $PSScriptRoot "deploy_windows.ps1"

$argList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $DeployPath,
    '-InstallDir', 'D:\software\shadowsocks',
    '-SkipBuild',
    '-Action', 'Run',
    '-Verbosity', 'vv'
)

Write-Host "Launching elevated sslocal (foreground)..."
Write-Host "  install : D:\software\shadowsocks"
Write-Host "  action  : Run (foreground, TUN + routes + DNS managed by deploy script)"
Write-Host "  stop    : Ctrl-C inside the elevated window (auto rolls back)"
Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs | Out-Null
Write-Host "Elevated window spawned. Test with Chrome now."
