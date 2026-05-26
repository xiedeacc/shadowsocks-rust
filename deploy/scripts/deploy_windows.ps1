#!pwsh
<#
.SYNOPSIS
    Windows TUN deployment helper for shadowsocks-rust.

.DESCRIPTION
    Three actions are supported via -Action:

      Run     (default) - build + copy artefacts, install TUN routes/DNS,
                          run sslocal.exe in foreground; on Ctrl-C or any
                          exit the script reverses every system change.

      Install           - legacy mode that registers and starts the
                          sswinservice Windows service. Use only when you
                          want autostart at boot.

      Cleanup           - undo every change a previous Run/Install made:
                          stop+remove the service, drop TUN routes,
                          remove bypass routes added to the physical
                          adapter and restore the original DNS servers.

    All system mutations are recorded in <InstallDir>\state\install-record.json
    so that Cleanup can reverse them exactly even after a reboot or a
    process crash.

.PARAMETER InstallDir
    Target install directory. Defaults to D:\software\shadowsocks.

.PARAMETER TunName
    TUN adapter name; must match locals.tun_interface_name in the JSON
    config. Defaults to "shadowsocks-tun".

.EXAMPLE
    # foreground run + cleanup on exit (recommended for testing)
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\deploy_windows.ps1

.EXAMPLE
    # just undo a previous deployment
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\deploy_windows.ps1 -Action Cleanup
#>
[CmdletBinding()]
param(
    [ValidateSet('Run','Install','Cleanup')]
    [string]$Action = 'Run',
    [string]$InstallDir = "D:\software\shadowsocks",
    [string]$ServiceName = "ssservice",
    [string]$TunName = "shadowsocks-tun",
    [string]$Features = "full local-tun local-web-admin local-http-rustls winservice",
    [string]$XrayPlugin = "",
    [switch]$SkipBuild,
    [switch]$ForceConfig,
    [switch]$NoConfigCopy,
    # Log verbosity passed to sslocal.exe in Run mode. The accepted values
    # mirror sslocal's own -v / -vv / -vvv flags:
    #   "off" - no -v flag (warn level)
    #   "v"   - info  (default)
    #   "vv"  - debug
    #   "vvv" - trace (very chatty; use when investigating TUN/DNS bugs)
    [ValidateSet('off','v','vv','vvv')]
    [string]$Verbosity = 'v'
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Windows deployment requires an elevated PowerShell session."
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "[deploy] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Warning "[deploy] $Message"
}

function Get-StateDir {
    param([string]$Root)
    return (Join-Path $Root "state")
}

function Get-RecordPath {
    param([string]$Root)
    return (Join-Path (Get-StateDir -Root $Root) "install-record.json")
}

function New-EmptyRecord {
    return [pscustomobject]@{
        tun_name        = $null
        tun_routes      = @()  # @(@{ prefix = '0.0.0.0/1' }, ...)
        physical_alias  = $null
        physical_routes = @()  # @(@{ prefix = '10.0.0.0/8'; nexthop = '192.168.1.1' }, ...)
        # Legacy single-alias backup, kept for older roll-backs.
        dns_backup      = $null  # @{ alias = 'Ethernet'; servers = @('192.168.1.1') }
        # Authoritative multi-interface IPv4/IPv6 DNS backup list. Each entry:
        # @{ family = 'IPv4'|'IPv6'; alias = '...'; index = <int>; servers = @('...') }
        dns_backups     = @()
    }
}

# PowerShell `ConvertFrom-Json` produces PSCustomObject instances which reject
# assignment to non-existent properties. Older state records written before
# `dns_backups` existed will not have the field, so any later
# `$record.dns_backups = ...` blows up. Patch loaded records in-place.
function Ensure-RecordFields {
    param($Record)
    if (-not $Record) { return }
    if (-not ($Record.PSObject.Properties.Match('dns_backups').Count)) {
        Add-Member -InputObject $Record -NotePropertyName 'dns_backups' -NotePropertyValue @() -Force
    }
    if (-not ($Record.PSObject.Properties.Match('dns_backup').Count)) {
        Add-Member -InputObject $Record -NotePropertyName 'dns_backup' -NotePropertyValue $null -Force
    }
    if (-not ($Record.PSObject.Properties.Match('tun_routes').Count)) {
        Add-Member -InputObject $Record -NotePropertyName 'tun_routes' -NotePropertyValue @() -Force
    }
    if (-not ($Record.PSObject.Properties.Match('physical_routes').Count)) {
        Add-Member -InputObject $Record -NotePropertyName 'physical_routes' -NotePropertyValue @() -Force
    }
}

function Save-Record {
    param(
        [string]$Root,
        $Record
    )
    $stateDir = Get-StateDir -Root $Root
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    $Record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Get-RecordPath -Root $Root) -Encoding UTF8
}

function Load-Record {
    param([string]$Root)
    $path = Get-RecordPath -Root $Root
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $rec = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        Ensure-RecordFields -Record $rec
        return $rec
    } catch {
        Write-Warn "install record at $path is corrupt: $($_.Exception.Message)"
        return $null
    }
}

function Remove-Record {
    param([string]$Root)
    $path = Get-RecordPath -Root $Root
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------
# Network discovery helpers
# ------------------------------------------------------------------

function Get-PhysicalDefaultRoute {
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
}

function Get-PhysicalAdapter {
    $defaultRoute = Get-PhysicalDefaultRoute
    if (-not $defaultRoute) { return $null }
    return Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
}

function Wait-TunAdapter {
    param([string]$Name, [int]$TimeoutSeconds = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -ne 'Disabled') { return $adapter }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

# Surface conflicts with Windows services that hold port 53 (DNS Server
# role, Internet Connection Sharing, Hyper-V vSwitch, etc.) before we
# spawn sslocal, since Windows' DNS client API can only point at 127.0.0.1
# with the well-known DNS port 53 - moving the listener to 1053 silently
# breaks Chrome.
function Test-Port53Conflict {
    param([int]$ExpectedPid = 0)
    $conflicts = @()
    try {
        $udp = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -in @('0.0.0.0','::','127.0.0.1') -and $_.OwningProcess -ne $ExpectedPid }
        foreach ($e in $udp) {
            $proc = Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue
            $conflicts += "UDP $($e.LocalAddress):53 held by PID $($e.OwningProcess) ($($proc.ProcessName))"
        }
    } catch {}
    try {
        $tcp = Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -ne $ExpectedPid }
        foreach ($e in $tcp) {
            $proc = Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue
            $conflicts += "TCP $($e.LocalAddress):53 held by PID $($e.OwningProcess) ($($proc.ProcessName))"
        }
    } catch {}
    return $conflicts
}

function Get-ConfigJson {
    param([string]$ConfigPath)
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    return Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
}

function Test-TunEnabled {
    param([string]$ConfigPath)
    $config = Get-ConfigJson -ConfigPath $ConfigPath
    if (-not $config) { return $false }
    return @($config.locals | Where-Object { $_.protocol -eq "tun" }).Count -gt 0
}

function Extract-Ip {
    param([string]$Value)
    if (-not $Value) { return $null }
    $text = $Value.Trim()
    if ($text -match '^\[(?<host>[^\]]+)\](?::\d+)?$') { $text = $Matches.host }
    elseif ($text -match '^(?<host>[^:]+):\d+$')      { $text = $Matches.host }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($text, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-ServerIps {
    param([string]$ConfigPath)
    $config = Get-ConfigJson -ConfigPath $ConfigPath
    if (-not $config) { return @() }
    $ips = @()
    foreach ($s in @($config.servers)) {
        $ip = Extract-Ip -Value $s.server
        if ($ip) { $ips += $ip }
    }
    if ($config.route_rules) {
        # ONLY domestic_dns belongs in the physical-bypass list. sslocal
        # opens raw sockets directly to these (DnsClient::lookup_local),
        # so they need a /32 exception so the packet doesn't loop back
        # into the TUN catch-all.
        #
        # foreign_dns IPs (e.g. 8.8.8.8) MUST NOT be here: those queries
        # are wrapped in the SS protocol and addressed to the SS server.
        # sslocal never opens a raw socket to them, so a /32 exception
        # would be at best wasted, at worst HARMFUL: OS-level tools
        # (Chrome's DoH probe, `nslookup -server=8.8.8.8`, Steam, etc.)
        # would then bypass the TUN-based DNS interceptor in
        # `local/tun/udp.rs` and hit a GFW-poisoned 8.8.8.8 directly.
        # Mirrors `windows_bypass_route_ips` in tun/mod.rs.
        foreach ($d in @($config.route_rules.domestic_dns)) {
            $ip = Extract-Ip -Value $d
            if ($ip) { $ips += $ip }
        }
    }
    return $ips | Select-Object -Unique
}

# ------------------------------------------------------------------
# Cleanup: undo every recorded mutation. Safe to call at any time;
# missing routes / adapters / DNS state are tolerated silently.
# ------------------------------------------------------------------

function Invoke-Cleanup {
    param(
        [string]$Root,
        [string]$ServiceName,
        [string]$TunName
    )

    Write-Step "starting cleanup"

    # Stop + remove service if present so the binary releases the TUN handle.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $svcInst = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($svcInst -and $svcInst.ProcessId -and $svcInst.ProcessId -ne 0) {
            Stop-Process -Id $svcInst.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Step "deleting service $ServiceName"
        & sc.exe delete $ServiceName | Out-Null
    }

    # If there are stray sslocal.exe / sswinservice.exe processes still
    # holding the TUN handle, kill them so route cleanup succeeds.
    foreach ($name in 'sslocal','sswinservice') {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }

    $record = Load-Record -Root $Root

    # 1. Drop every route still pointing at the TUN adapter.
    $tunAdapter = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
    if ($tunAdapter) {
        Write-Step "removing IPv4 routes via TUN adapter '$TunName' (ifIndex $($tunAdapter.ifIndex))"
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $tunAdapter.ifIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        Write-Step "TUN adapter '$TunName' not present (already gone)"
    }

    # 2. Drop the LAN/server/gateway bypass routes we previously injected
    #    into the physical adapter. Only delete routes that match the
    #    recorded prefix AND ifIndex; falls back to a best-effort sweep
    #    if no record exists.
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
            $sweep = @('10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15')
            foreach ($prefix in $sweep) {
                Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.RouteMetric -eq 1 } |
                    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }

    # 3. Restore DNS on every interface we overrode. Prefer the new
    #    multi-iface `dns_backups` field (with per-entry `family`); fall
    #    back to the legacy single-alias `dns_backup` for records written
    #    by older builds.
    $backups = @()
    if ($record) {
        if ($record.dns_backups) { $backups = @($record.dns_backups) }
        elseif ($record.dns_backup -and $record.dns_backup.alias) { $backups = @($record.dns_backup) }
    }
    if ($backups.Count -gt 0) {
        foreach ($b in $backups) {
            $alias   = $b.alias
            $idx     = $b.index
            # Default family for legacy records (no `family` field) is IPv4.
            $family  = if ($b.family) { [string]$b.family } else { 'IPv4' }
            $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
            $servers = @()
            if ($b.servers) { $servers = @($b.servers | Where-Object { $_ -and $_ -ne $loopback }) }
            try {
                if ($servers.Count -gt 0) {
                    Write-Step "restoring $family DNS on '$alias' to $($servers -join ', ')"
                    # Set-DnsClientServerAddress detects family per address,
                    # so a v4-only or v6-only list updates only that family.
                    if ($idx) {
                        Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $servers -ErrorAction Stop | Out-Null
                    } else {
                        Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $servers -ErrorAction Stop | Out-Null
                    }
                } else {
                    # Backup was empty -> family was DHCP-managed.
                    # Set-DnsClientServerAddress -ResetServerAddresses resets
                    # BOTH families which would clobber the other family we
                    # may still need to restore. Use netsh to reset only this
                    # family.
                    Write-Step "resetting $family DNS on '$alias' to DHCP"
                    $proto = if ($family -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
                    & netsh interface $proto set dnsservers name="$alias" source=dhcp *> $null
                }
            } catch {
                Write-Warn "failed to restore $family DNS for '$alias': $($_.Exception.Message)"
            }
        }
    } else {
        # No record on disk -- best effort: for each interface currently
        # pinned to 127.0.0.1 or ::1 (it can only have come from us), reset
        # that family to DHCP via netsh so the other family is left alone.
        foreach ($family in 'IPv4','IPv6') {
            $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
            $proto    = if ($family -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
            Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.ServerAddresses -and ($_.ServerAddresses -contains $loopback) -and
                    $_.InterfaceAlias -notmatch '^Loopback' -and $_.InterfaceAlias -ne $TunName
                } |
                ForEach-Object {
                    Write-Step "no record; resetting $family DNS on '$($_.InterfaceAlias)' to DHCP"
                    & netsh interface $proto set dnsservers name="$($_.InterfaceAlias)" source=dhcp *> $null
                }
        }
    }

    # 4. Flush the OS DNS cache so Chrome stops returning the stale
    #    "no resolver" answer.
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    & ipconfig /flushdns *> $null

    Remove-Record -Root $Root
    Write-Step "cleanup finished"
}

# ------------------------------------------------------------------
# Install routes + DNS: returns an install record that Save-Record can
# persist. Idempotent. Logs every mutation.
# ------------------------------------------------------------------

function Install-RoutesAndDns {
    param(
        [string]$Root,
        [string]$ConfigPath,
        [string]$TunName
    )

    $record = New-EmptyRecord
    $record.tun_name = $TunName

    if (-not (Test-TunEnabled -ConfigPath $ConfigPath)) {
        Write-Step "TUN is disabled in config; no routes installed"
        return $record
    }

    $tunAdapter = Wait-TunAdapter -Name $TunName
    if (-not $tunAdapter) {
        Write-Warn "TUN adapter '$TunName' did not appear within 15s; check that sslocal.exe is running and the wintun driver is installed"
        return $record
    }
    Write-Step "TUN adapter '$TunName' detected (ifIndex $($tunAdapter.ifIndex), status $($tunAdapter.Status))"

    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -ne $tunAdapter.ifIndex -and $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if (-not $defaultRoute) {
        Write-Warn "no physical default route found; aborting route installation"
        return $record
    }
    $physical = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
    if (-not $physical) {
        Write-Warn "physical adapter for default route not found; aborting route installation"
        return $record
    }
    $record.physical_alias = $physical.InterfaceAlias
    Write-Step "physical adapter '$($physical.InterfaceAlias)' (ifIndex $($physical.ifIndex)) next-hop $($defaultRoute.NextHop)"

    # Drop any default route someone has previously attached to the TUN.
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -eq $tunAdapter.ifIndex } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    # TUN catch-all (0.0.0.0/1 + 128.0.0.0/1). Higher-priority than any
    # 0.0.0.0/0 the OS may keep, but does not delete the physical default
    # so direct/bypass outbound from sslocal can still find the gateway.
    foreach ($prefix in "0.0.0.0/1", "128.0.0.0/1") {
        Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $tunAdapter.ifIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $tunAdapter.ifIndex -NextHop "0.0.0.0" -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        $record.tun_routes += @{ prefix = $prefix }
        Write-Step "installed TUN catch-all route $prefix -> ifIndex $($tunAdapter.ifIndex)"
    }

    # LAN / loopback / link-local stay on the physical adapter so internal
    # traffic never enters TUN (the user reported 内网通信正常, this keeps
    # that working).
    $lanPrefixes = @('10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15')
    foreach ($prefix in $lanPrefixes) {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.NextHop -eq $defaultRoute.NextHop } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $physical.ifIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        $record.physical_routes += @{ prefix = $prefix; nexthop = $defaultRoute.NextHop }
    }
    Write-Step "installed LAN bypass routes on '$($physical.InterfaceAlias)'"

    # Bypass routes for the SS server IP(s) and configured DNS hops so
    # sslocal can dial them through the physical gateway instead of
    # looping back through TUN (which would deadlock).
    $serverIps = Get-ServerIps -ConfigPath $ConfigPath
    foreach ($ip in $serverIps) {
        $prefix = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "$($ip)/32" } else { "$($ip)/128" }
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.NextHop -eq $defaultRoute.NextHop } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $physical.ifIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        $record.physical_routes += @{ prefix = $prefix; nexthop = $defaultRoute.NextHop }
        Write-Step "installed bypass route $prefix -> $($defaultRoute.NextHop) (server/DNS hop)"
    }

    # Pin the gateway itself so ARP traffic + gateway-targeted packets
    # never go through TUN.
    if ($defaultRoute.NextHop -and $defaultRoute.NextHop -ne "0.0.0.0") {
        $gwPrefix = "$($defaultRoute.NextHop)/32"
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $gwPrefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $physical.ifIndex -and $_.NextHop -eq $defaultRoute.NextHop } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $gwPrefix -InterfaceIndex $physical.ifIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        $record.physical_routes += @{ prefix = $gwPrefix; nexthop = $defaultRoute.NextHop }
        Write-Step "installed gateway pin route $gwPrefix"
    }

    # Optional IPv6 ULA/link-local pinning.
    $defaultRouteV6 = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -ne $tunAdapter.ifIndex } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if ($defaultRouteV6) {
        foreach ($prefix in "fc00::/7", "fe80::/10") {
            Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $defaultRouteV6.InterfaceIndex -and $_.NextHop -eq $defaultRouteV6.NextHop } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRouteV6.InterfaceIndex -NextHop $defaultRouteV6.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        }
    }

    # Back up and override DNS on EVERY non-loopback, non-TUN interface
    # that has at least one server set on EITHER family. Windows DNS
    # Client is multi-homed: even an interface in the Disconnected state
    # (e.g. Wi-Fi without an active link) is still queried in parallel,
    # so leaving a poisoned ISP server on Wi-Fi means GFW-injected
    # answers for google/youtube/etc. beat sslocal's TCP-over-SS reply.
    # We MUST override both v4 and v6: home routers commonly advertise
    # themselves via SLAAC/RDNSS (fdfa:eea3:ae99::1 etc.) and Windows
    # races both families.
    $dnsBackups = @()
    foreach ($family in 'IPv4','IPv6') {
        $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
        Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object {
                $_.InterfaceAlias -and
                $_.InterfaceAlias -notmatch '^Loopback' -and
                $_.InterfaceAlias -ne $TunName -and
                $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0
            } | ForEach-Object {
                $alias = $_.InterfaceAlias
                $idx = $_.InterfaceIndex
                # Strip any prior loopback entry so re-runs don't clobber
                # the original backup with our override.
                $kept = @($_.ServerAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -ne $loopback })
                if ($kept.Count -eq 0 -and -not ($_.ServerAddresses -contains $loopback)) {
                    return
                }
                $dnsBackups += @{ family = $family; alias = $alias; index = $idx; servers = $kept }
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $loopback -ErrorAction Stop | Out-Null
                    Write-Step "set $family DNS on '$alias' to $loopback (backup: $(if($kept){$kept -join ', '}else{'<DHCP>'}))"
                } catch {
                    Write-Warn "failed to override $family DNS on '$alias': $($_.Exception.Message)"
                }
            }
    }
    if (-not $dnsBackups) {
        Write-Warn "no DNS overrides applied -- Chrome may hit ISP DNS directly and see GFW-poisoned answers"
    }
    # Keep legacy single-alias field populated for code paths that still
    # read $record.dns_backup, but the authoritative list is dns_backups.
    $record.dns_backups = $dnsBackups
    $primary = $dnsBackups | Where-Object { $_.alias -eq $physical.InterfaceAlias } | Select-Object -First 1
    if (-not $primary) { $primary = $dnsBackups | Select-Object -First 1 }
    if ($primary) {
        $record.dns_backup = @{ alias = $primary.alias; servers = @($primary.servers) }
    }

    # Flush the OS DNS cache so the very first Chrome lookup hits the new
    # listener instead of returning the cached "no record" answer.
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    & ipconfig /flushdns *> $null

    return $record
}

# ------------------------------------------------------------------
# Build + copy artefacts. Returns the path to the deployed config.
# ------------------------------------------------------------------

function Build-And-Stage {
    param(
        [string]$Root,
        [string]$RepoRoot,
        [bool]$ForceConfig,
        [bool]$NoConfigCopy
    )

    $ReleaseDir   = Join-Path $RepoRoot "target\release"
    $WindowsDir   = Join-Path $RepoRoot "deploy\windows"
    $ConfigSource = Join-Path $WindowsDir "conf\shadowsocks-client.json.example"
    if (-not (Test-Path -LiteralPath $ConfigSource)) {
        $alt = Join-Path $WindowsDir "conf\shadowsocks-client.json"
        if (Test-Path -LiteralPath $alt) { $ConfigSource = $alt }
    }

    if (-not $SkipBuild) {
        Write-Step "cargo build --release (features: $Features)"
        & cargo build --release --no-default-features --features $Features --bin sslocal --bin sswinservice
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    }

    New-Item -ItemType Directory -Force -Path @(
        (Join-Path $Root "bin"),
        (Join-Path $Root "conf"),
        (Join-Path $Root "data"),
        (Join-Path $Root "logs"),
        (Get-StateDir -Root $Root)
    ) | Out-Null

    Copy-Item -Force -LiteralPath (Join-Path $ReleaseDir "sslocal.exe")      -Destination (Join-Path $Root "bin\sslocal.exe")
    if (Test-Path -LiteralPath (Join-Path $ReleaseDir "sswinservice.exe")) {
        Copy-Item -Force -LiteralPath (Join-Path $ReleaseDir "sswinservice.exe") -Destination (Join-Path $Root "bin\sswinservice.exe")
    }
    if ($XrayPlugin) {
        Copy-Item -Force -LiteralPath $XrayPlugin -Destination (Join-Path $Root "bin\xray-plugin.exe")
    }

    $ConfigDest = Join-Path $Root "conf\shadowsocks-client.json"
    if (-not $NoConfigCopy) {
        if ($ForceConfig -or -not (Test-Path -LiteralPath $ConfigDest)) {
            if (Test-Path -LiteralPath $ConfigSource) {
                Copy-Item -Force -LiteralPath $ConfigSource -Destination $ConfigDest
                Write-Step "wrote default config to $ConfigDest"
            }
        }
    }

    $UbuntuData = Join-Path $RepoRoot "deploy\ubuntu\data"
    if (Test-Path -LiteralPath $UbuntuData) {
        Copy-Item -Force -Recurse -Path (Join-Path $UbuntuData "*") -Destination (Join-Path $Root "data")
    }

    return $ConfigDest
}

# ------------------------------------------------------------------
# Action handlers
# ------------------------------------------------------------------

function Invoke-RunAction {
    param([string]$Root, [string]$RepoRoot, [string]$TunName, [string]$ServiceName)

    # Always cleanup first so a previous broken install can be reset.
    Invoke-Cleanup -Root $Root -ServiceName $ServiceName -TunName $TunName

    $ConfigDest = Build-And-Stage -Root $Root -RepoRoot $RepoRoot -ForceConfig:$ForceConfig -NoConfigCopy:$NoConfigCopy
    if (-not (Test-Path -LiteralPath $ConfigDest)) {
        throw "config not found at $ConfigDest; supply one and re-run, or pass -ForceConfig"
    }

    $BinPath = Join-Path $Root "bin\sslocal.exe"
    if (-not (Test-Path -LiteralPath $BinPath)) {
        throw "sslocal.exe missing at $BinPath"
    }

    $LogDir = Join-Path $Root "logs"
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $StdoutLog = Join-Path $LogDir "sslocal.stdout.log"
    $StderrLog = Join-Path $LogDir "sslocal.stderr.log"
    # Truncate before each run so the log only contains the current
    # session - much easier to read when verbosity is vv/vvv.
    Set-Content -LiteralPath $StdoutLog -Value '' -Encoding UTF8
    Set-Content -LiteralPath $StderrLog -Value '' -Encoding UTF8

    $argList = @('-c', $ConfigDest, '--log-without-time')
    switch ($Verbosity) {
        'v'   { $argList += '-v' }
        'vv'  { $argList += '-vv' }
        'vvv' { $argList += '-vvv' }
        default {}
    }

    Write-Step "spawning $BinPath $($argList -join ' ')"
    Write-Step "stdout -> $StdoutLog"
    Write-Step "stderr -> $StderrLog"

    $proc = Start-Process -FilePath $BinPath `
        -ArgumentList $argList `
        -WorkingDirectory $Root `
        -RedirectStandardOutput $StdoutLog `
        -RedirectStandardError  $StderrLog `
        -PassThru -NoNewWindow

    Write-Step "sslocal pid=$($proc.Id); installing TUN routes and DNS override..."
    try {
        # Wait briefly for the TUN adapter to come up before we touch routes.
        Start-Sleep -Seconds 2

        $conflicts = Test-Port53Conflict -ExpectedPid $proc.Id
        if ($conflicts.Count -gt 0) {
            foreach ($c in $conflicts) { Write-Warn "port 53 conflict: $c" }
            Write-Warn "Chrome's DNS will hit the conflicting service first; consider stopping it (e.g. ICS, DNS Server role, Hyper-V vSwitch) before retrying."
        } else {
            Write-Step "port 53 is free (no conflicting Windows service detected)"
        }

        $record = Install-RoutesAndDns -Root $Root -ConfigPath $ConfigDest -TunName $TunName
        Save-Record -Root $Root -Record $record

        Write-Step "running. Press Ctrl-C to stop and roll back every change."

        # Hand-rolled wait loop so Ctrl-C in this powershell process still
        # reaches the `finally` block. Tail the log so the user sees output.
        $tailPath = $StdoutLog
        $tailJob  = $null
        if (Test-Path -LiteralPath $tailPath) {
            $tailJob = Start-Job -ScriptBlock {
                param($p) Get-Content -Path $p -Wait -Tail 50
            } -ArgumentList $tailPath
        }
        try {
            while (-not $proc.HasExited) {
                Start-Sleep -Seconds 1
                if ($tailJob) {
                    Receive-Job -Job $tailJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
                }
            }
        } finally {
            if ($tailJob) {
                Stop-Job -Job $tailJob -ErrorAction SilentlyContinue | Out-Null
                Receive-Job -Job $tailJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
                Remove-Job -Job $tailJob -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Step "sslocal exited with code $($proc.ExitCode)"
    } finally {
        Write-Step "rolling back system changes..."
        if (-not $proc.HasExited) {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
        # Always cleanup, even if Install-RoutesAndDns threw.
        Invoke-Cleanup -Root $Root -ServiceName $ServiceName -TunName $TunName
    }
}

function Invoke-InstallAction {
    param([string]$Root, [string]$RepoRoot, [string]$TunName, [string]$ServiceName)

    if ($ServiceName -ne "ssservice") {
        throw "sswinservice registers itself as 'ssservice'; use the default ServiceName."
    }

    # Reset any prior state cleanly.
    Invoke-Cleanup -Root $Root -ServiceName $ServiceName -TunName $TunName

    $ConfigDest = Build-And-Stage -Root $Root -RepoRoot $RepoRoot -ForceConfig:$ForceConfig -NoConfigCopy:$NoConfigCopy
    if (-not (Test-Path -LiteralPath $ConfigDest)) {
        throw "config not found at $ConfigDest"
    }

    $ServiceExe = Join-Path $Root "bin\sswinservice.exe"
    if (-not (Test-Path -LiteralPath $ServiceExe)) {
        throw "sswinservice.exe missing at $ServiceExe; build with feature 'winservice'"
    }
    $BinPath = "`"$ServiceExe`" local -c `"$ConfigDest`" --log-without-time"
    Write-Step "registering service $ServiceName"
    & sc.exe create $ServiceName binPath= $BinPath start= auto | Out-Host
    Start-Service -Name $ServiceName
    Write-Step "service started"

    Start-Sleep -Seconds 2
    $record = Install-RoutesAndDns -Root $Root -ConfigPath $ConfigDest -TunName $TunName
    Save-Record -Root $Root -Record $record

    Write-Step "install finished. Manage with: Get-Service -Name $ServiceName  /  Stop-Service $ServiceName"
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

Assert-Admin

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Write-Step "repo: $RepoRoot"
Write-Step "install: $InstallDir"
Write-Step "action: $Action"

switch ($Action) {
    'Cleanup' {
        Invoke-Cleanup -Root $InstallDir -ServiceName $ServiceName -TunName $TunName
    }
    'Install' {
        Invoke-InstallAction -Root $InstallDir -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
    }
    'Run' {
        Invoke-RunAction -Root $InstallDir -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
    }
}
