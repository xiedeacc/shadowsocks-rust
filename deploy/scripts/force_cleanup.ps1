#!pwsh
<#
.SYNOPSIS
    Hard-stop + roll back EVERY system change made by deploy_windows.ps1.

.DESCRIPTION
    Use this when:
      * the service is hung or refusing to stop
      * DNS is broken (Chrome shows DNS_PROBE_FINISHED_NO_INTERNET)
      * leftover routes are still hijacking traffic to a dead TUN
      * you want to completely uninstall

    Steps performed:
      1. Stop-Service ssservice (with timeout) and SIGKILL any orphan
         sslocal.exe / sswinservice.exe.
      2. Delete every IPv4/IPv6 route whose InterfaceIndex points at the
         shadowsocks-tun adapter (even if the adapter is already gone).
      3. Drop the recorded LAN/server-IP/gateway-pin bypass routes on
         the physical adapter using install-record.json. If the record
         is missing, fall back to a best-effort sweep of well-known
         private prefixes with RouteMetric=1.
      4. Restore DNS on every interface back to its recorded servers
         (or to DHCP if it was DHCP originally). Both IPv4 and IPv6.
         If no record exists, reset any interface whose DNS still
         points at 127.0.0.1 / ::1 to DHCP via netsh.
      5. Flush the OS DNS cache.
      6. With -RemoveService: also sc.exe delete the service so it
         won't come back on next boot.

.PARAMETER InstallDir
    Where the deployed artefacts live. Defaults to D:\software\shadowsocks.

.PARAMETER ServiceName
    Defaults to 'ssservice'.

.PARAMETER TunName
    Defaults to 'shadowsocks-tun'.

.PARAMETER RemoveService
    Also delete the Windows service entry (full uninstall).

.EXAMPLE
    # full uninstall (service + routes + DNS)
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\force_cleanup.ps1 -RemoveService

.EXAMPLE
    # emergency: stop traffic, restore DNS, but keep service installed for next boot
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\force_cleanup.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir   = "D:\software\shadowsocks",
    [string]$ServiceName  = "ssservice",
    [string]$TunName      = "shadowsocks-tun",
    [switch]$RemoveService
)

$ErrorActionPreference = "Continue"

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "force_cleanup.ps1 requires an elevated PowerShell session."
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "[cleanup] $Message" -ForegroundColor Cyan
}

function Write-Warn-Local {
    param([string]$Message)
    Write-Warning "[cleanup] $Message"
}

Assert-Admin

$RecordPath = Join-Path $InstallDir "state\install-record.json"
$record = $null
if (Test-Path -LiteralPath $RecordPath) {
    try {
        $record = Get-Content -Raw -LiteralPath $RecordPath | ConvertFrom-Json
    } catch {
        Write-Warn-Local "install-record.json is corrupt: $($_.Exception.Message); proceeding without it"
    }
} else {
    Write-Warn-Local "no install-record.json found at $RecordPath; using best-effort sweep"
}

# 1. Stop service + kill orphans ------------------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Step "stopping service $ServiceName (status=$($svc.Status))"
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    } catch {
        Write-Warn-Local "Stop-Service failed: $($_.Exception.Message)"
    }
    $svcInst = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($svcInst -and $svcInst.ProcessId -and $svcInst.ProcessId -ne 0) {
        Write-Step "killing service PID $($svcInst.ProcessId)"
        Stop-Process -Id $svcInst.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

foreach ($name in 'sslocal','sswinservice') {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Step "killing orphan $name processes: $($procs.Id -join ', ')"
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

if ($RemoveService) {
    if ($svc -or (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Step "deleting service $ServiceName"
        & sc.exe delete $ServiceName | Out-Null
    }
}

# 2. Drop every route still pointing at the TUN --------------------------------
$tun = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
if ($tun) {
    Write-Step "removing routes via TUN '$TunName' (ifIndex $($tun.ifIndex))"
    foreach ($family in 'IPv4','IPv6') {
        Get-NetRoute -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $tun.ifIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
} else {
    Write-Step "TUN adapter '$TunName' is gone (nothing to delete on its ifIndex)"
}

# 3. Drop the LAN/server/gateway bypass routes we previously installed ---------
function Get-PhysicalAdapter {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if (-not $r) { return $null }
    return Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
}

if ($record -and $record.physical_routes -and $record.physical_alias) {
    $physical = Get-NetAdapter -InterfaceAlias $record.physical_alias -ErrorAction SilentlyContinue
    if ($physical) {
        foreach ($r in $record.physical_routes) {
            Write-Step "removing recorded route $($r.prefix) via $($r.nexthop) on '$($record.physical_alias)'"
            Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $r.prefix -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.NextHop -eq $r.nexthop } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
} else {
    $physical = Get-PhysicalAdapter
    if ($physical) {
        Write-Step "no record; sweeping well-known private prefixes on '$($physical.InterfaceAlias)'"
        $sweep = @('10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15')
        foreach ($prefix in $sweep) {
            Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.RouteMetric -eq 1 } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

# 4. Restore DNS ----------------------------------------------------------------
$backups = @()
if ($record) {
    if ($record.dns_backups)    { $backups = @($record.dns_backups) }
    elseif ($record.dns_backup -and $record.dns_backup.alias) { $backups = @($record.dns_backup) }
}

if ($backups.Count -gt 0) {
    foreach ($b in $backups) {
        $alias    = $b.alias
        $idx      = $b.index
        $family   = if ($b.family) { [string]$b.family } else { 'IPv4' }
        $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
        $servers  = @()
        if ($b.servers) { $servers = @($b.servers | Where-Object { $_ -and $_ -ne $loopback }) }
        try {
            if ($servers.Count -gt 0) {
                Write-Step "restoring $family DNS on '$alias' to $($servers -join ', ')"
                if ($idx) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $servers -ErrorAction Stop | Out-Null
                } else {
                    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $servers -ErrorAction Stop | Out-Null
                }
            } else {
                Write-Step "resetting $family DNS on '$alias' to DHCP"
                $proto = if ($family -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
                & netsh interface $proto set dnsservers name="$alias" source=dhcp *> $null
            }
        } catch {
            Write-Warn-Local "failed to restore $family DNS for '$alias': $($_.Exception.Message)"
        }
    }
} else {
    Write-Step "no DNS backup; resetting any interface still pointing at 127.0.0.1 / ::1 to DHCP"
    foreach ($family in 'IPv4','IPv6') {
        $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
        $proto    = if ($family -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
        Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ServerAddresses -and ($_.ServerAddresses -contains $loopback) -and
                $_.InterfaceAlias -notmatch '^Loopback' -and $_.InterfaceAlias -ne $TunName
            } |
            ForEach-Object {
                Write-Step "  resetting $family on '$($_.InterfaceAlias)'"
                & netsh interface $proto set dnsservers name="$($_.InterfaceAlias)" source=dhcp *> $null
            }
    }
}

# 5. Flush DNS cache ------------------------------------------------------------
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
& ipconfig /flushdns *> $null
Write-Step "flushed OS DNS cache"

# 6. Remove the install-record so next deploy starts clean ----------------------
if (Test-Path -LiteralPath $RecordPath) {
    Remove-Item -LiteralPath $RecordPath -Force -ErrorAction SilentlyContinue
    Write-Step "removed install-record.json"
}

Write-Host ""
Write-Host "[cleanup] done." -ForegroundColor Green
if ($RemoveService) {
    Write-Host "          service is REMOVED; reboot recommended."
} else {
    Write-Host "          service is still INSTALLED but stopped."
    Write-Host "          - re-enable: Start-Service $ServiceName"
    Write-Host "          - disable auto-start: sc.exe config $ServiceName start= demand"
    Write-Host "          - full uninstall: rerun this script with -RemoveService"
}
