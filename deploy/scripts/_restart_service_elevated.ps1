#!pwsh
# Stops ssservice, swaps in the freshly built sswinservice.exe, starts it again.
$ErrorActionPreference = 'Stop'
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ok   = Join-Path $Root 'restart-service-elevated.ok'
$log  = Join-Path $Root 'restart-service-elevated.log'
Remove-Item -LiteralPath $ok,$log -Force -ErrorAction SilentlyContinue
Start-Transcript -Path $log -Force | Out-Null
try {
    $src = Join-Path $Root 'target\release\sswinservice.exe'
    $dst = 'D:\software\shadowsocks\bin\sswinservice.exe'
    if (-not (Test-Path -LiteralPath $src)) { throw "missing $src" }

    if (Get-Service -Name 'ssservice' -ErrorAction SilentlyContinue) {
        Write-Host "[restart] stopping ssservice"
        Stop-Service -Name ssservice -Force -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline) {
            $svc = Get-Service -Name ssservice -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    # Wait for any leftover xray-plugin to die so the file is unlocked.
    Get-Process -Name xray-plugin,sslocal,sswinservice -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_ | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Milliseconds 1500

    Copy-Item -LiteralPath $src -Destination $dst -Force
    Write-Host "[restart] copied $(((Get-Item $dst).LastWriteTime))"

    Start-Service -Name ssservice
    Start-Sleep -Seconds 2
    Get-Service ssservice | Format-Table Name,Status,StartType -AutoSize | Out-Host
    Get-Process -Name sswinservice,xray-plugin -ErrorAction SilentlyContinue | Format-Table Name,Id -AutoSize | Out-Host
    'OK' | Out-File -LiteralPath $ok -Encoding utf8
} catch {
    Write-Host "[restart] ERROR: $_"
    "FAIL: $_" | Out-File -LiteralPath $ok -Encoding utf8
    throw
} finally {
    Stop-Transcript | Out-Null
}
