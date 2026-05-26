#!pwsh
<#
Kill a stuck _test_tun_elevated.ps1 run and put the system back into a
healthy state: stop sslocal/sswinservice, remove the recorded TUN
routes, restore DNS, then exit. Used when the previous elevated test
hangs after sslocal's -vv flood.
#>
[CmdletBinding()]
param(
    [string]$InstallDir  = "D:\software\shadowsocks",
    [string]$TunName     = "shadowsocks-tun",
    [string]$ServiceName = "ssservice",
    [int[]] $KillPids    = @()
)

$ErrorActionPreference = 'Continue'

function Write-Step { param([string]$M) Write-Host "[kill-stuck] $M" -ForegroundColor Yellow }

# 1. force-kill any caller-supplied PIDs
foreach ($pidValue in $KillPids) {
    try {
        $proc = Get-Process -Id $pidValue -ErrorAction Stop
        Write-Step "killing PID $pidValue ($($proc.Name))"
        Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
    } catch { Write-Step "PID $pidValue not present (ok)" }
}

# 2. force-kill sslocal / sswinservice
foreach ($name in 'sslocal','sswinservice','xray-plugin') {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Step "killing all $name processes"
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 1

# 3. reuse deploy_windows.ps1's helpers for a real cleanup
$deployScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "deploy_windows.ps1")
$startIdx = $deployScript.IndexOf("function Assert-Admin")
$mainIdx  = $deployScript.IndexOf("# Main")
if ($startIdx -ge 0 -and $mainIdx -ge 0) {
    Invoke-Expression $deployScript.Substring($startIdx, $mainIdx - $startIdx)
    try {
        Invoke-Cleanup -Root $InstallDir -ServiceName $ServiceName -TunName $TunName
    } catch {
        Write-Step "Invoke-Cleanup raised: $($_.Exception.Message) (continuing)"
    }
}

# 4. truncate the giant trace log so re-runs aren't slowed by leftover bytes
$logs = @(
    (Join-Path $InstallDir "logs\sslocal.stdout.log"),
    (Join-Path $InstallDir "logs\sslocal.stderr.log")
)
foreach ($p in $logs) {
    if (Test-Path -LiteralPath $p) {
        Set-Content -LiteralPath $p -Value '' -Encoding UTF8 -Force -ErrorAction SilentlyContinue
    }
}

# 5. write a marker so the parent shell knows we ran
$marker = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "kill-stuck-test.ok"
"OK $(Get-Date -Format o)" | Set-Content -LiteralPath $marker -Encoding UTF8
Write-Step "done; wrote $marker"
