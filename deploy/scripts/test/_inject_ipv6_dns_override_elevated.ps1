#!pwsh
# One-shot in-place patch: override IPv6 DNS on every non-loopback,
# non-TUN interface to ::1, and merge the backup entries into the
# existing install-record.json so Invoke-Cleanup will roll back
# correctly when the user eventually stops sslocal.
#
# Use ONLY when sslocal is already running with the new IPv6 DNS
# listener (::1:53) but the original Install-RoutesAndDns pass did not
# include IPv6 overrides. Idempotent: rerunning is safe -- entries
# already present in dns_backups are not duplicated and live overrides
# already pointing at ::1 are left alone.
$ErrorActionPreference = 'Stop'
$recordPath = 'D:\software\shadowsocks\state\install-record.json'
if (-not (Test-Path $recordPath)) {
    Write-Host "ABORT: install-record.json missing at $recordPath -- is sslocal running via deploy_windows.ps1?"
    exit 1
}

$record = Get-Content -Raw -LiteralPath $recordPath | ConvertFrom-Json
if (-not ($record.PSObject.Properties.Match('dns_backups').Count)) {
    Add-Member -InputObject $record -NotePropertyName dns_backups -NotePropertyValue @() -Force
}

# Helpful index keyed by (family|alias|index) so we never duplicate.
$existing = @{}
foreach ($b in @($record.dns_backups)) {
    $fam = if ($b.family) { [string]$b.family } else { 'IPv4' }
    $key = "$fam|$($b.alias)|$($b.index)"
    $existing[$key] = $true
}

$added = 0
Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceAlias -and
        $_.InterfaceAlias -notmatch '^Loopback' -and
        $_.InterfaceAlias -ne 'shadowsocks-tun' -and
        $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0
    } | ForEach-Object {
        $alias = $_.InterfaceAlias
        $idx   = $_.InterfaceIndex
        $kept  = @($_.ServerAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -ne '::1' })
        if ($kept.Count -eq 0) {
            Write-Host "skip '$alias' (already ::1 only)"
            return
        }
        $key = "IPv6|$alias|$idx"
        if (-not $existing.ContainsKey($key)) {
            $record.dns_backups += @{ family = 'IPv6'; alias = $alias; index = $idx; servers = $kept }
            $existing[$key] = $true
            $added++
        }
        try {
            Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ::1 -ErrorAction Stop | Out-Null
            Write-Host "set IPv6 DNS on '$alias' to ::1 (was: $($kept -join ', '))"
        } catch {
            Write-Host "  failed: $($_.Exception.Message)"
        }
    }

Clear-DnsClientCache 2>$null
& ipconfig /flushdns *> $null

# Persist merged record so cleanup restores both families.
$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $recordPath -Encoding UTF8
Write-Host ""
Write-Host "added $added new IPv6 backup entries to install-record.json"
Write-Host "--- IPv6 DNS after ---"
Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.InterfaceAlias -notmatch '^Loopback' -and $_.InterfaceAlias -ne 'shadowsocks-tun' } |
    Format-Table InterfaceAlias,ServerAddresses -AutoSize | Out-String
