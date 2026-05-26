<#
SS-UDP probe to a non-DNS UDP target the local sslocal cannot short-
circuit. Targets:
  1) 54.179.191.126:30000  -> AWS hairpin echo (proves the full relay).
  2) 162.159.200.1:123     -> Cloudflare NTP (independent service).
#>
$ErrorActionPreference = "Stop"

function Probe-Udp {
    param(
        [string]$Server,
        [int]$Port,
        [byte[]]$Payload,
        [int]$TimeoutMs = 8000
    )
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Connect($Server, $Port)
        [void]$udp.Send($Payload, $Payload.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remoteEp)
        $sw.Stop()
        return @{ ok=$true; bytes=$resp.Length; ms=[int]$sw.ElapsedMilliseconds; preview=([System.BitConverter]::ToString($resp[0..([Math]::Min(15, $resp.Length-1))])) }
    } catch {
        $sw.Stop()
        return @{ ok=$false; bytes=0; ms=[int]$sw.ElapsedMilliseconds; err=$_.Exception.Message }
    } finally { $udp.Close() }
}

# 1. AWS echo target
$payload = [System.Text.Encoding]::ASCII.GetBytes("SS-UDP-E2E-" + (Get-Date -Format HHmmss))
Write-Host "=== 54.179.191.126:30000 (AWS echo hairpin) ==="
for ($i=1; $i -le 2; $i++) {
    $r = Probe-Udp -Server "54.179.191.126" -Port 30000 -Payload $payload -TimeoutMs 8000
    if ($r.ok) { Write-Host ("  [{0}] OK  {1} bytes in {2}ms preview={3}" -f $i,$r.bytes,$r.ms,$r.preview) }
    else      { Write-Host ("  [{0}] FAIL {1}ms err={2}" -f $i,$r.ms,$r.err) }
}

# 2. NTP target (48-byte client request with LI=0, VN=4, Mode=3 in first byte)
$ntp = New-Object byte[] 48
$ntp[0] = 0x23  # 00 100 011 = LI=0 VN=4 Mode=3 (client)
Write-Host ""
Write-Host "=== 162.159.200.1:123 (Cloudflare NTP) ==="
for ($i=1; $i -le 2; $i++) {
    $r = Probe-Udp -Server "162.159.200.1" -Port 123 -Payload $ntp -TimeoutMs 8000
    if ($r.ok) { Write-Host ("  [{0}] OK  {1} bytes in {2}ms preview={3}" -f $i,$r.bytes,$r.ms,$r.preview) }
    else      { Write-Host ("  [{0}] FAIL {1}ms err={2}" -f $i,$r.ms,$r.err) }
}

Write-Host ""
Write-Host "--- AWS UDP echo log (port 30000) ---"
ssh -o ConnectTimeout=8 ubuntu@54.179.191.126 "sudo tail -n 8 /tmp/_ss_udp_echo.log"
Write-Host ""
Write-Host "--- nginx ss-udp.log tail ---"
ssh -o ConnectTimeout=8 ubuntu@54.179.191.126 "sudo tail -n 10 /var/log/nginx/ss-udp.log"
