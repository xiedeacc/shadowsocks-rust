#!pwsh
$ErrorActionPreference = 'Stop'
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ok   = Join-Path $Root 'stop-service-elevated.ok'
$log  = Join-Path $Root 'stop-service-elevated.log'
Remove-Item -LiteralPath $ok,$log -Force -ErrorAction SilentlyContinue
Start-Transcript -Path $log -Force | Out-Null
try {
    & (Join-Path $PSScriptRoot 'deploy_windows.ps1') -Action Cleanup -InstallDir 'D:\software\shadowsocks' *>&1
    Get-Process -Name sswinservice,sslocal,xray-plugin -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    'OK' | Out-File -LiteralPath $ok -Encoding utf8
} catch {
    "FAIL: $_" | Out-File -LiteralPath $ok -Encoding utf8
    throw
} finally {
    Stop-Transcript | Out-Null
}
