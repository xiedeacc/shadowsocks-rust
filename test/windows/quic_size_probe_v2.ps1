<#
Big-packet SS-UDP test against a real QUIC server, using cloudflare-
quic.com (104.18.27.14) as the target since it's confirmed to live in
foreign IP space and therefore SS routes it as proxy. Any UDP response
from a Cloudflare QUIC server proves the carrier handles QUIC-sized
datagrams end-to-end.
#>
$ErrorActionPreference = "Stop"

function Make-Quic-Like {
    param([int]$Size)
    $b = New-Object byte[] $Size
    $b[0] = 0xC0
    $b[1] = 0x00; $b[2] = 0x00; $b[3] = 0x00; $b[4] = 0x01
    $b[5] = 8
    for ($i=6;$i -le 13;$i++) { $b[$i] = (Get-Random -Maximum 256) }
    $b[14] = 8
    for ($i=15;$i -le 22;$i++) { $b[$i] = (Get-Random -Maximum 256) }
    $b[23] = 0
    for ($i=26;$i -lt $Size;$i++) { $b[$i] = (Get-Random -Maximum 256) }
    return ,$b
}

function Probe-Udp {
    param([string]$Server,[int]$Port,[byte[]]$Payload,[int]$TimeoutMs=4000)
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Connect($Server, $Port)
        [void]$udp.Send($Payload, $Payload.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remoteEp)
        $sw.Stop()
        return @{ ok=$true; bytes=$resp.Length; ms=[int]$sw.ElapsedMilliseconds; preview=([System.BitConverter]::ToString($resp[0..([Math]::Min(11,$resp.Length-1))])) }
    } catch {
        $sw.Stop()
        return @{ ok=$false; bytes=0; ms=[int]$sw.ElapsedMilliseconds; err=$_.Exception.Message }
    } finally { $udp.Close() }
}

# 104.18.27.14 (cloudflare-quic.com) is anycast and runs QUIC.
$server = "104.18.27.14"
Write-Host "=== big-packet SS-UDP probe to ${server}:443 (Cloudflare QUIC) ==="
$sizes = @(200, 600, 1100, 1200, 1252, 1400)
foreach ($sz in $sizes) {
    $payload = Make-Quic-Like -Size $sz
    $r = Probe-Udp -Server $server -Port 443 -Payload $payload -TimeoutMs 4000
    if ($r.ok) {
        Write-Host ("  send={0,5}B  recv={1,5}B  {2,4}ms  OK  preview={3}" -f $payload.Length,$r.bytes,$r.ms,$r.preview)
    } else {
        Write-Host ("  send={0,5}B  FAIL {1,4}ms err={2}" -f $payload.Length,$r.ms,$r.err)
    }
}
Write-Host ""
Write-Host "--- sslocal udp relay decision log (last 20) ---"
$log = Get-ChildItem "D:\software\shadowsocks\logs\sslocal*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) { Get-Content $log.FullName -Tail 400 | Select-String "udp relay.*104\.18\.|udp relay.*->.*443" | Select-Object -Last 20 | ForEach-Object { $_.Line } }
Write-Host ""
Write-Host "--- nginx ss-udp.log tail ---"
ssh -o ConnectTimeout=8 ubuntu@54.179.191.126 "sudo tail -n 8 /var/log/nginx/ss-udp.log"
