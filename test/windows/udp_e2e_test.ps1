<#
End-to-end SS-UDP smoke test. We craft a tiny DNS A query and send it
over UDP to a few foreign resolvers that are NOT in the bypass list, so
the TUN ought to classify them as proxy traffic and route through the
SS-UDP relay. A successful answer proves the chain:
    Windows UDP -> TUN -> sslocal -> SS-UDP -> nginx UDP/443
    -> ssserver UDP -> resolver -> reverse path

Each target is queried twice: with a high timeout (covers cold-start
TUN UDP NAT) and once more to confirm steady-state latency.
#>
$ErrorActionPreference = "Stop"

function Make-DnsQuery {
    param([string]$Name)
    # Wire-format DNS A query (id=0xABCD, RD=1, qtype=A, qclass=IN).
    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    [void]$bytes.AddRange([byte[]](0xAB,0xCD, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00))
    foreach ($label in $Name.Split('.')) {
        $b = [System.Text.Encoding]::ASCII.GetBytes($label)
        [void]$bytes.Add([byte]$b.Length)
        [void]$bytes.AddRange($b)
    }
    [void]$bytes.AddRange([byte[]](0x00, 0x00,0x01, 0x00,0x01))
    return ,$bytes.ToArray()
}

function Probe-Udp {
    param(
        [string]$Server,
        [int]$Port,
        [string]$Query,
        [int]$TimeoutMs
    )
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Connect($Server, $Port)
        $bytes = Make-DnsQuery -Name $Query
        [void]$udp.Send($bytes, $bytes.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remoteEp)
        $sw.Stop()
        return @{ ok = $true; bytes = $resp.Length; ms = [int]$sw.ElapsedMilliseconds; err = $null }
    } catch {
        $sw.Stop()
        return @{ ok = $false; bytes = 0; ms = [int]$sw.ElapsedMilliseconds; err = $_.Exception.Message }
    } finally { $udp.Close() }
}

$targets = @(
    @{ name = "Quad9 (foreign)";              ip = "9.9.9.9";       port = 53 },
    @{ name = "Cloudflare (foreign)";         ip = "1.1.1.1";       port = 53 },
    @{ name = "OpenDNS (foreign)";            ip = "208.67.222.222";port = 53 }
)

foreach ($t in $targets) {
    Write-Host "=== $($t.name) $($t.ip):$($t.port) ==="
    for ($i=1; $i -le 2; $i++) {
        $r = Probe-Udp -Server $t.ip -Port $t.port -Query "www.google.com" -TimeoutMs 8000
        if ($r.ok) {
            Write-Host ("  [{0}] OK  {1} bytes in {2}ms" -f $i, $r.bytes, $r.ms)
        } else {
            Write-Host ("  [{0}] FAIL {1}ms err={2}" -f $i, $r.ms, $r.err)
        }
    }
}

Write-Host ""
Write-Host "--- nginx ss-udp.log tail on AWS ---"
ssh -o ConnectTimeout=8 ubuntu@54.179.191.126 "sudo tail -n 12 /var/log/nginx/ss-udp.log"
Write-Host ""
Write-Host "If you see your public IP (163.x...) lines with non-zero upstream_bytes_received, end-to-end UDP works."
