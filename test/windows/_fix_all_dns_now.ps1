#!pwsh
# One-shot helper: pin DNS to 127.0.0.1 on every IPv4 interface that
# still has a non-loopback DNS server configured. Use when sslocal is
# already running but the original deploy only overrode the physical
# adapter and another interface (Wi-Fi, an extra Ethernet, ...) is
# leaking GFW-poisoned answers into the OS resolver cache.
$ErrorActionPreference = 'Stop'
$record = @{ dns_backups = @() }
# IPv4 + IPv6 in the SAME pass. The IPv6 DNS server is the killer
# on home networks: the router exposes itself via SLAAC/RDNSS at
# something like fdfa:eea3:ae99::1, which Windows uses *in parallel*
# with the IPv4 DNS server. If we override only IPv4, the router
# DNS still wins for AAAA queries (and many A queries too, since
# Windows races both families). Override both.
foreach ($family in 'IPv4','IPv6') {
    Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
        Where-Object {
            $_.InterfaceAlias -and
            $_.InterfaceAlias -notmatch '^Loopback' -and
            $_.InterfaceAlias -ne 'shadowsocks-tun' -and
            $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0
        } | ForEach-Object {
            $loopback = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
            $kept = @($_.ServerAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -ne $loopback })
            if ($kept.Count -eq 0) { return }
            Write-Host "override $family DNS on '$($_.InterfaceAlias)' (was: $($kept -join ', '))"
            $record.dns_backups += @{ family = $family; alias = $_.InterfaceAlias; index = $_.InterfaceIndex; servers = $kept }
            try {
                Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $loopback -ErrorAction Stop | Out-Null
            } catch {
                Write-Host "  failed: $($_.Exception.Message)"
            }
        }
}
Clear-DnsClientCache
& ipconfig /flushdns *> $null
$path = 'D:\software\shadowsocks\state\extra-dns-backup.json'
New-Item -ItemType Directory -Force -Path (Split-Path $path -Parent) | Out-Null
$record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
"backup_saved=$path"
"--- after ---"
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Format-Table InterfaceAlias,ServerAddresses -AutoSize
