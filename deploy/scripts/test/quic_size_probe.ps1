<#
Send progressively larger UDP packets to 1.1.1.1:443 (Cloudflare QUIC
endpoint). Even malformed QUIC initials should get a Version
Negotiation response from a real QUIC server. Crucially, port 443
is NOT intercepted by the local ss-dns, so the packets traverse the
full TUN -> SS-UDP -> nginx -> ssserver -> 1.1.1.1 path.
#>
$ErrorActionPreference = "Stop"

function Make-Quic-Like {
    param([int]$Size)
    # Bytes shaped like a long-header QUIC initial:
    #   [0] = 0xC0 (long header, type=Initial)
    #   [1..4] = QUIC version 0xff00001d (draft-29) or 0x00000001 (v1)
    #   [5] = DCID length (8)
    #   [6..13] = DCID
    #   [14] = SCID length (8)
    #   [15..22] = SCID
    #   [23] = token length (0)
    #   [24..25] = packet length (varint, 2-byte)
    #   [26..] = encrypted payload (random)
    $b = New-Object byte[] $Size
    $b[0] = 0xC0
    $b[1] = 0x00; $b[2] = 0x00; $b[3] = 0x00; $b[4] = 0x01  # version 1
    $b[5] = 8
    for ($i=6;$i -le 13;$i++) { $b[$i] = (Get-Random -Maximum 256) }
    $b[14] = 8
    for ($i=15;$i -le 22;$i++) { $b[$i] = (Get-Random -Maximum 256) }
    $b[23] = 0  # token len
    # remaining size used as "encrypted payload"
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
        return @{ ok=$true; bytes=$resp.Length; ms=[int]$sw.ElapsedMilliseconds; preview=([System.BitConverter]::ToString($resp[0..([Math]::Min(15,$resp.Length-1))])) }
    } catch {
        $sw.Stop()
        return @{ ok=$false; bytes=0; ms=[int]$sw.ElapsedMilliseconds; err=$_.Exception.Message }
    } finally { $udp.Close() }
}

Write-Host "=== UDP/443 probe to 1.1.1.1 (QUIC server) ==="
$sizes = @(200, 600, 1100, 1200, 1252, 1400)
foreach ($sz in $sizes) {
    $payload = Make-Quic-Like -Size $sz
    $r = Probe-Udp -Server "1.1.1.1" -Port 443 -Payload $payload -TimeoutMs 4000
    if ($r.ok) {
        Write-Host ("  send={0,5}B  recv={1,5}B  {2,4}ms  OK  preview={3}" -f $payload.Length,$r.bytes,$r.ms,$r.preview)
    } else {
        Write-Host ("  send={0,5}B  FAIL {1,4}ms err={2}" -f $payload.Length,$r.ms,$r.err)
    }
}

Write-Host ""
Write-Host "=== nginx ss-udp.log tail (look for upstream_bytes_received != 0) ==="
ssh -o ConnectTimeout=8 ubuntu@54.179.191.126 "sudo tail -n 10 /var/log/nginx/ss-udp.log"
