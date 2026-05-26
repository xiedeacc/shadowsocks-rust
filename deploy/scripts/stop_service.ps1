#!pwsh
<#
.SYNOPSIS
    Soft-stop sswinservice (graceful) - keeps it installed.

.DESCRIPTION
    Stops the 'ssservice' Windows service so traffic is no longer
    proxied. Routes (`0.0.0.0/1` etc.) are dropped by sslocal's own
    Drop impl as it exits. DNS overrides on the physical adapter are
    NOT restored - if you also need DNS back to DHCP, run
    `force_cleanup.ps1` instead.

    Safe to run repeatedly. Falls back to killing leftover processes
    if Stop-Service times out.

.PARAMETER ServiceName
    Defaults to 'ssservice' (the name sswinservice registers itself as).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\stop_service.ps1
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "ssservice"
)

$ErrorActionPreference = "Continue"

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "stop_service.ps1 requires an elevated PowerShell session."
    }
}

Assert-Admin

Write-Host "[stop] looking up service '$ServiceName'..." -ForegroundColor Cyan
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "[stop] current status: $($svc.Status), start type: $($svc.StartType)"
    if ($svc.Status -ne 'Stopped') {
        Write-Host "[stop] stopping..."
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Host "[stop] service stopped." -ForegroundColor Green
        } catch {
            Write-Warning "[stop] Stop-Service failed: $($_.Exception.Message); will hard-kill instead"
        }
    } else {
        Write-Host "[stop] service already stopped."
    }
} else {
    Write-Host "[stop] service not registered; nothing to stop."
}

# Belt-and-braces: kill any orphan sslocal / sswinservice instances.
foreach ($name in 'sslocal','sswinservice') {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "[stop] killing leftover $name processes: $($procs.Id -join ', ')" -ForegroundColor Yellow
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[stop] done. Service is still INSTALLED (will re-start on next boot)." -ForegroundColor Green
Write-Host "       - to disable auto-start  :  sc.exe config $ServiceName start= demand"
Write-Host "       - to start again now     :  Start-Service $ServiceName"
Write-Host "       - to also restore DNS    :  .\deploy\scripts\force_cleanup.ps1"
Write-Host "       - to fully uninstall     :  .\deploy\scripts\force_cleanup.ps1 -RemoveService"
