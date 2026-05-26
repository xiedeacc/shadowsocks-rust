#!pwsh
<#
.SYNOPSIS
    Windows TUN deployment helper for shadowsocks-rust.

.DESCRIPTION
    Single entry point for installing, starting, stopping and inspecting
    the sslocal Windows TUN deployment. Five actions are supported via
    -Action:

      Start    (default) - register the sswinservice Windows service with
                           autostart=auto, build+copy artefacts if needed,
                           install the TUN catch-all routes and the
                           per-interface DNS overrides, then start the
                           service. Idempotent.

      Stop               - "Stop AND disable" in one shot:
                           stop the service, DELETE it (so it cannot
                           auto-start on reboot), hard-kill any orphan
                           sslocal/sswinservice/xray-plugin processes,
                           restore every per-interface DNS server we
                           overrode, remove every bypass route we added
                           to the physical adapter, drop every route
                           still pointing at the TUN adapter, and flush
                           the OS DNS cache. After this the box is in
                           the same network state as before the very
                           first Start. Idempotent.

      Restart            - rebuild + swap the binary + bounce the service.
                           Routes and DNS overrides are NOT touched - this
                           is the fast path for "I just recompiled, pick
                           up the new sslocal.exe".

      Status             - read-only diagnostic: service state, child
                           process pids, current TUN routes, current
                           per-interface DNS servers, install-record
                           contents.

      Run                - foreground sslocal for debugging. Does an
                           internal Stop first, runs sslocal.exe in this
                           shell, and runs Stop again on Ctrl-C / exit.

    All system mutations made by Start/Run are journalled into
    <InstallDir>\state\install-record.json so that Stop can reverse them
    exactly even across reboots or unexpected crashes.

    The script self-elevates via UAC: if you launch it from a
    non-administrator shell it will spawn a new elevated PowerShell
    window with -NoExit so you can read the output.

.PARAMETER InstallDir
    Target install directory. Defaults to D:\software\shadowsocks.

.PARAMETER TunName
    TUN adapter name; must match locals.tun_interface_name in the JSON
    config. Defaults to "shadowsocks-tun".

.EXAMPLE
    # Install + start + enable autostart (the canonical "I want SS now"):
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\deploy_windows.ps1 -Action Start

.EXAMPLE
    # Full uninstall + revert all network changes:
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\deploy_windows.ps1 -Action Stop

.EXAMPLE
    # After `cargo build --release`, swap binary + restart service:
    powershell -ExecutionPolicy Bypass -File .\deploy\scripts\deploy_windows.ps1 -Action Restart
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Stop','Restart','Status','Run')]
    [string]$Action = 'Start',
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

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If we are not running elevated, request UAC and re-launch the same
# script in a new admin PowerShell window with the same arguments. We
# pass -NoExit so the elevated window stays open for the user to read
# the output (especially Stop's per-interface DNS restore log) and a
# `-WorkingDirectory` so cargo/etc. inherit the caller's CWD instead
# of the C:\Windows\system32 default that elevated processes get.
#
# NOTE: $PSBoundParameters here MUST be the SCRIPT's bound parameters
# (so we forward `-Action Restart` etc.), not the function's own
# bound parameters. We accept it as an explicit argument because a
# function's automatic `$PSBoundParameters` is local to the function
# and would otherwise come back empty.
function Invoke-SelfElevate {
    param(
        [hashtable]$BoundParams = @{},
        [string]$WorkingDirectory = $null
    )
    if (-not $PSCommandPath) {
        throw "Cannot self-elevate: \$PSCommandPath is unset (run via -File, not piped)."
    }
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File', $PSCommandPath)
    foreach ($k in $BoundParams.Keys) {
        $v = $BoundParams[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $argList += "-$k" }
        } else {
            $argList += "-$k"
            $argList += "$v"
        }
    }
    $actionForMsg = if ($BoundParams.ContainsKey('Action')) { $BoundParams['Action'] } else { 'Start (default)' }
    Write-Host "[deploy] not elevated; requesting UAC to relaunch with -Action $actionForMsg..." -ForegroundColor Yellow
    try {
        $spArgs = @{
            FilePath     = 'powershell.exe'
            ArgumentList = $argList
            Verb         = 'RunAs'
        }
        if ($WorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) {
            $spArgs['WorkingDirectory'] = $WorkingDirectory
        }
        Start-Process @spArgs | Out-Null
    } catch {
        throw "UAC prompt was cancelled or failed: $($_.Exception.Message)"
    }
    Write-Host "[deploy] elevated window spawned; this shell is done." -ForegroundColor Green
    exit 0
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
    # ONLY the listener's `local_dns_address` (= "domestic" upstream)
    # belongs in the physical-bypass list. sslocal opens raw sockets
    # directly to it (DnsClient::lookup_local), so it needs a /32
    # exception otherwise the packet loops back into the TUN catch-all.
    #
    # The `remote_dns_address` (= "foreign" upstream, e.g. 8.8.8.8)
    # MUST NOT be here: those queries are wrapped in the SS protocol
    # and addressed to the SS server. sslocal never opens a raw socket
    # to them, so a /32 exception would be at best wasted, at worst
    # HARMFUL: OS-level tools (Chrome's DoH probe, `nslookup -server=
    # 8.8.8.8`, Steam, etc.) would then bypass the TUN-based DNS
    # interceptor in `local/tun/udp.rs` and hit a GFW-poisoned 8.8.8.8
    # directly. Mirrors `windows_bypass_route_ips` in tun/mod.rs.
    foreach ($l in @($config.locals)) {
        if ($l.protocol -eq 'dns' -and $l.local_dns_address) {
            $ip = Extract-Ip -Value $l.local_dns_address
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
                    #
                    # InterfaceIndex can become stale between backup and restore
                    # (Wi-Fi adapters re-enumerate when the radio cycles, VMware
                    # vmnetN adapters reload when their service bounces, etc.).
                    # Try the recorded index first, then fall back to the alias
                    # which is more stable, then to netsh as a last resort.
                    $set = $false
                    if ($idx) {
                        try {
                            Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $servers -ErrorAction Stop | Out-Null
                            $set = $true
                        } catch {
                            Write-Warn "InterfaceIndex $idx no longer matches '$alias' ($($_.Exception.Message)); retrying by alias"
                        }
                    }
                    if (-not $set) {
                        try {
                            Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $servers -ErrorAction Stop | Out-Null
                            $set = $true
                        } catch {
                            Write-Warn "alias-based DNS restore for '$alias' failed: $($_.Exception.Message); retrying via netsh"
                        }
                    }
                    if (-not $set) {
                        # netsh takes a literal alias (in quotes) and is less
                        # picky than the CIM-backed cmdlet about adapter state.
                        # `set dnsservers ... static <ip>` clears and sets the
                        # primary; `add dnsservers ... index=N` appends the
                        # rest in the original order.
                        $proto = if ($family -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
                        & netsh interface $proto set dnsservers name="$alias" static $($servers[0]) *> $null
                        for ($i = 1; $i -lt $servers.Count; $i++) {
                            & netsh interface $proto add dnsservers name="$alias" $($servers[$i]) index=$($i + 1) *> $null
                        }
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

function Invoke-StartAction {
    param([string]$Root, [string]$RepoRoot, [string]$TunName, [string]$ServiceName)

    if ($ServiceName -ne "ssservice") {
        throw "sswinservice registers itself as 'ssservice'; use the default ServiceName."
    }

    # Reset any prior install state cleanly before installing fresh.
    # This guarantees DNS backups are taken from the real OS state, not
    # from a half-broken previous run where DNS was still pinned to
    # 127.0.0.1.
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

    # Idempotent service registration. If a previous install was Stopped
    # via `sc delete` the service is gone and we create it; if for some
    # reason it survived (e.g. user ran sc.exe manually) we just update
    # binPath and force start type back to auto.
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "service '$ServiceName' already registered; updating binPath + start= auto"
        & sc.exe config $ServiceName binPath= $BinPath start= auto | Out-Host
    } else {
        Write-Step "registering service '$ServiceName' (start= auto)"
        & sc.exe create $ServiceName binPath= $BinPath start= auto | Out-Host
    }

    Write-Step "starting service '$ServiceName'"
    Start-Service -Name $ServiceName

    Start-Sleep -Seconds 2
    $record = Install-RoutesAndDns -Root $Root -ConfigPath $ConfigDest -TunName $TunName
    Save-Record -Root $Root -Record $record

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "[deploy] START finished." -ForegroundColor Green
    if ($svc) {
        Write-Host "   service '$ServiceName' : Status=$($svc.Status), StartType=$($svc.StartType) (Automatic = will auto-start on next boot)"
    }
    Write-Host "   to STOP + uninstall    : deploy_windows.ps1 -Action Stop"
    Write-Host "   to inspect             : deploy_windows.ps1 -Action Status"
}

function Invoke-StopAction {
    param([string]$Root, [string]$ServiceName, [string]$TunName)

    # `Invoke-Cleanup` already does:
    #   1. Stop-Service + sc.exe delete (so service disappears + cannot auto-start on reboot)
    #   2. Kill orphaned sslocal/sswinservice/xray-plugin processes
    #   3. Drop every route still pointing at the TUN adapter
    #   4. Drop the LAN/server/gateway bypass routes recorded on the physical adapter
    #   5. Restore the per-interface DNS server lists we overrode (v4 + v6)
    #   6. Flush the OS DNS cache
    #   7. Remove the install-record.json
    # That covers the user's "completely as if never installed" requirement.
    Invoke-Cleanup -Root $Root -ServiceName $ServiceName -TunName $TunName

    # Belt-and-braces: kill any xray-plugin spawned by the dead service.
    foreach ($name in 'sslocal','sswinservice','xray-plugin') {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "[deploy] STOP finished." -ForegroundColor Green
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "   service '$ServiceName' : still present (Status=$($svc.Status), StartType=$($svc.StartType))" -ForegroundColor Yellow
        Write-Host "   (sc.exe delete may need a reboot if the SCM cached a handle.)"
    } else {
        Write-Host "   service '$ServiceName' : removed"
    }
    foreach ($name in 'sslocal','sswinservice','xray-plugin') {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host "   ${name}: still running pids $($p.Id -join ', ')" -ForegroundColor Red
        }
    }
    Write-Host "   routes / DNS overrides : reverted (see lines above for details)"
    Write-Host "   to start again         : deploy_windows.ps1 -Action Start"
}

function Invoke-RestartAction {
    param([string]$Root, [string]$RepoRoot, [string]$TunName, [string]$ServiceName)

    # Restart = "I just rebuilt sslocal, swap the binary and bounce".
    # Routes and DNS overrides are deliberately preserved so the user
    # doesn't see DNS resolution flap during the restart.
    #
    # If the service hasn't been registered yet (or was removed by a
    # previous -Action Stop), there is nothing to "restart" - in that
    # case fall through to the full Start path which will register the
    # service with start= auto, build + copy binaries, install routes
    # and DNS overrides, and bring sslocal up.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Step "service '$ServiceName' not registered; delegating to -Action Start (register + enable autostart + install routes/DNS + start)"
        Invoke-StartAction -Root $Root -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
        return
    }

    Write-Step "stopping service '$ServiceName' for restart"
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline) {
            $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $s -or $s.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }

    # Give Windows a moment to release the binary lock - xray-plugin in
    # particular can stay alive briefly after its parent dies.
    foreach ($name in 'sslocal','sswinservice','xray-plugin') {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 1500

    if (-not $SkipBuild) {
        Write-Step "cargo build --release (features: $Features)"
        & cargo build --release --no-default-features --features $Features --bin sslocal --bin sswinservice
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    }

    $ReleaseDir = Join-Path $RepoRoot "target\release"
    foreach ($exe in 'sslocal.exe','sswinservice.exe') {
        $src = Join-Path $ReleaseDir $exe
        $dst = Join-Path $Root "bin\$exe"
        if (Test-Path -LiteralPath $src) {
            Copy-Item -Force -LiteralPath $src -Destination $dst
            Write-Step "copied $exe ($(((Get-Item $dst).LastWriteTime)))"
        }
    }

    Write-Step "starting service '$ServiceName'"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "[deploy] RESTART finished." -ForegroundColor Green
    if ($svc) {
        Write-Host "   service '$ServiceName' : Status=$($svc.Status), StartType=$($svc.StartType)"
    }
}

function Invoke-StatusAction {
    param([string]$Root, [string]$TunName, [string]$ServiceName)

    Write-Host ""
    Write-Host "==== service ====" -ForegroundColor Cyan
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Get-Service -Name $ServiceName | Select-Object Name,Status,StartType,DisplayName |
            Format-Table -AutoSize | Out-Host
    } else {
        Write-Host "  (service '$ServiceName' not registered)"
    }

    Write-Host "==== processes ====" -ForegroundColor Cyan
    $any = $false
    foreach ($name in 'sslocal','sswinservice','xray-plugin') {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($p) {
            $any = $true
            $p | Select-Object Name,Id,@{n='CPU(s)';e={[int]$_.CPU}},@{n='WS(MB)';e={[int]($_.WorkingSet64/1MB)}} |
                Format-Table -AutoSize | Out-Host
        }
    }
    if (-not $any) { Write-Host "  (no sslocal/sswinservice/xray-plugin processes running)" }

    Write-Host "==== TUN adapter ====" -ForegroundColor Cyan
    $tun = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
    if ($tun) {
        $tun | Select-Object Name,Status,ifIndex,MacAddress,LinkSpeed | Format-Table -AutoSize | Out-Host
        Write-Host "==== routes via TUN ====" -ForegroundColor Cyan
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $tun.ifIndex } |
            Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceMetric |
            Sort-Object DestinationPrefix |
            Format-Table -AutoSize | Out-Host
    } else {
        Write-Host "  (TUN adapter '$TunName' not present)"
    }

    Write-Host "==== DNS overrides (loopback servers indicate active interception) ====" -ForegroundColor Cyan
    foreach ($family in 'IPv4','IPv6') {
        $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
        $hits = Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object {
                $_.InterfaceAlias -and
                $_.InterfaceAlias -notmatch '^Loopback' -and
                $_.InterfaceAlias -ne $TunName -and
                $_.ServerAddresses -contains $loopback
            }
        if ($hits) {
            $hits | Select-Object @{n='Family';e={$family}},InterfaceAlias,InterfaceIndex,@{n='Servers';e={$_.ServerAddresses -join ', '}} |
                Format-Table -AutoSize | Out-Host
        }
    }

    Write-Host "==== install record ====" -ForegroundColor Cyan
    $recPath = Get-RecordPath -Root $Root
    if (Test-Path -LiteralPath $recPath) {
        Write-Host "  $recPath"
        $rec = Load-Record -Root $Root
        if ($rec) {
            Write-Host "  tun_name           : $($rec.tun_name)"
            Write-Host "  physical_alias     : $($rec.physical_alias)"
            Write-Host "  tun_routes         : $((@($rec.tun_routes) | ForEach-Object { $_.prefix }) -join ', ')"
            Write-Host "  physical_routes    : $((@($rec.physical_routes) | ForEach-Object { $_.prefix }) -join ', ')"
            Write-Host "  dns_backups count  : $((@($rec.dns_backups)).Count)"
        }
    } else {
        Write-Host "  (no install record at $recPath; either never started or fully stopped)"
    }
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

# Capture script-scope bound parameters BEFORE entering any function,
# because automatic `$PSBoundParameters` is function-local and would
# come back empty inside Invoke-SelfElevate.
$ScriptBoundParameters = $PSBoundParameters

# `.Path` collapses PathInfo to a plain string; later interpolation
# (Set-Location, "$RepoRoot\..", cargo --manifest-path, etc.) is much
# better-behaved with a string than with a PathInfo wrapper.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# UAC-elevated PowerShell starts in C:\Windows\system32 by default.
# Hop into the repo root so `cargo build`, relative paths, etc. all
# resolve from the workspace as the un-elevated caller would expect.
Set-Location -LiteralPath $RepoRoot

if (-not (Test-IsAdmin)) {
    Invoke-SelfElevate -BoundParams $ScriptBoundParameters -WorkingDirectory $RepoRoot
    # Invoke-SelfElevate calls `exit`; defence-in-depth if not:
    throw "Windows deployment requires an elevated PowerShell session."
}

Write-Step "repo: $RepoRoot"
Write-Step "install: $InstallDir"
Write-Step "action: $Action"

switch ($Action) {
    'Start' {
        Invoke-StartAction -Root $InstallDir -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
    }
    'Stop' {
        Invoke-StopAction -Root $InstallDir -ServiceName $ServiceName -TunName $TunName
    }
    'Restart' {
        Invoke-RestartAction -Root $InstallDir -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
    }
    'Status' {
        Invoke-StatusAction -Root $InstallDir -TunName $TunName -ServiceName $ServiceName
    }
    'Run' {
        Invoke-RunAction -Root $InstallDir -RepoRoot $RepoRoot -TunName $TunName -ServiceName $ServiceName
    }
}
