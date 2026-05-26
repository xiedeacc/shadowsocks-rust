#!pwsh
# Convenience launcher used when the user double-clicks deploy. Forwards
# every CLI parameter to deploy_windows.ps1 so it stays in lock-step.
$ErrorActionPreference = "Stop"
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Log  = Join-Path $Root "deploy-windows-elevated.log"
try {
    & (Join-Path $PSScriptRoot "deploy_windows.ps1") -InstallDir "D:\software\shadowsocks" -SkipBuild @args *>&1 | Tee-Object -FilePath $Log
    "DEPLOY_OK"   | Out-File -FilePath (Join-Path $Root "deploy-windows-elevated.ok") -Encoding utf8
} catch {
    $_ | Out-File -FilePath $Log -Append -Encoding utf8
    "DEPLOY_FAIL" | Out-File -FilePath (Join-Path $Root "deploy-windows-elevated.ok") -Encoding utf8
    throw
}
