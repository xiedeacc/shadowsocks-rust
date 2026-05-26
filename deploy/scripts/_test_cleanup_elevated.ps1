$ErrorActionPreference = 'Continue'
$LogDir = 'D:\software\shadowsocks\logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogPath = Join-Path $LogDir 'cleanup.log'
Set-Content -LiteralPath $LogPath -Value '' -Encoding UTF8

Set-Location 'D:\code\shadowsocks\shadowsocks-rust'
& '.\deploy\scripts\deploy_windows.ps1' -Action Cleanup *>&1 |
    Tee-Object -FilePath $LogPath -Append

$exit = $LASTEXITCODE
"EXITCODE:$exit" | Add-Content -Path $LogPath
exit $exit
