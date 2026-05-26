#!pwsh
<#
.SYNOPSIS
    Non-elevated wrapper that triggers UAC, runs the TUN end-to-end test
    in an elevated child PowerShell, and waits for the result file to
    appear. Mirrors run_deploy_elevated.ps1 but for the test script.

    Outputs the parsed result JSON when finished, and exits 0/1 based
    on the test's `success` field.
#>
[CmdletBinding()]
param(
    [int]$WaitSeconds = 240
)

$ErrorActionPreference = 'Stop'
$Root           = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$TestScript     = Join-Path $PSScriptRoot "_test_tun_elevated.ps1"
$ResultPath     = Join-Path $Root "test-tun-result.json"
$ProgressLog    = Join-Path $Root "test-tun-progress.log"
$TranscriptLog  = Join-Path $Root "test-tun-transcript.log"

# Clear stale outputs so we know the result is fresh.
foreach ($p in @($ResultPath, $ProgressLog, $TranscriptLog)) {
    try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } catch {}
}

Write-Host "[run-tun] launching elevated test (UAC prompt may appear)..." -ForegroundColor Cyan
$argList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $TestScript
)
$proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -PassThru
Write-Host "[run-tun] elevated pid=$($proc.Id), polling for $ResultPath..."

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $ResultPath) { break }
    if ($proc.HasExited -and -not (Test-Path -LiteralPath $ResultPath)) {
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path -LiteralPath $ResultPath)) {
            Write-Warning "[run-tun] elevated child exited (code=$($proc.ExitCode)) without producing $ResultPath"
            break
        }
    }
    Start-Sleep -Seconds 1
}

if (-not (Test-Path -LiteralPath $ResultPath)) {
    Write-Warning "[run-tun] timed out waiting for result"
    exit 2
}

$obj = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
$obj | ConvertTo-Json -Depth 8
if ($obj.success) { exit 0 } else { exit 1 }
