<#
Big-packet SS-UDP smoke test. QUIC initial packets are typically
~1200 bytes (Chrome uses ~1250). If the SS-UDP path drops/fragments
those, Chrome can't complete the QUIC handshake.

We use a UDP echo we spawn on AWS bound to 0.0.0.0:30000 and reach it
via SS-UDP through the ssserver. Targeting the AWS PRIVATE address
(172.31.27.202) instead of the public IP avoids the hairpin NAT
limitation that bites 54.179.191.126:30000.
#>
$ErrorActionPreference = "Stop"

function Probe-Udp {
    param(
        [string]$Server,
        [int]$Port,
        [byte[]]$Payload,
        [int]$TimeoutMs = 6000
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
        return @{ ok=$true; bytes=$resp.Length; ms=[int]$sw.ElapsedMilliseconds }
    } catch {
        $sw.Stop()
        return @{ ok=$false; bytes=0; ms=[int]$sw.ElapsedMilliseconds; err=$_.Exception.Message }
    } finally { $udp.Close() }
}

# Probe a known foreign UDP target. We can't use the AWS hairpin path,
# so use Cloudflare NTP just to verify the carrier still works after the
# nginx fix, and then a UDP-DNS query (which IS proxied because the
# TUN does NOT short-circuit foreign DNS via SS-UDP after our prior
# fixes -- it short-circuits port-53-from-the-LAN-resolver-perspective,
# not in-flight UDP/53 *destined* for an external IP). Test multiple
# payload sizes.

# We pick OpenDNS (208.67.220.220) which accepts arbitrary-padded DNS
# queries because it ignores unknown OPT records and returns NXDOMAIN
# for the same byte count. But to avoid DNS edge cases entirely, use
# Cloudflare NTP for a fixed 48-byte exchange and "echo via raw UDP" to
# a target we control.

# Strategy: send a packet to 1.1.1.1:53 (DNS) but the QUESTION section
# embeds enough bytes to grow the request to 600/1200/1400 bytes via
# spurious labels. Cloudflare DNS will either parse and return short
# answer, or drop. Either way we measure carrier behaviour.

function Make-Bloated-Dns-Query {
    param([int]$TargetSize)
    # Minimum query is ~32 bytes. Inflate with EDNS0 OPT RR padding
    # (RFC 7830). Format: a normal A query for "a.com" then OPT RR
    # with PADDING option to fill to TargetSize.
    $hdr = [byte[]](0xAB,0xCD, 0x01,0x20, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x01)
    $qname = [byte[]](0x01, 0x61, 0x03, 0x63, 0x6F, 0x6D, 0x00)  # a.com
    $qtailer = [byte[]](0x00,0x01, 0x00,0x01)  # qtype=A class=IN
    # OPT RR header: name=root(00), type=OPT(0029), udp size(1232=0x04D0), flags(0000),
    # then RDLEN (2 bytes) + RDATA (option code 12 = padding, option len, then zeros)
    $optHdr = [byte[]](0x00, 0x00,0x29, 0x04,0xD0, 0x00,0x00,0x00,0x00)
    $baseSize = $hdr.Length + $qname.Length + $qtailer.Length + $optHdr.Length + 2 + 4 # +2 RDLEN +4 padding hdr(code+len)
    $padLen = $TargetSize - $baseSize
    if ($padLen -lt 0) { $padLen = 0 }
    $rdlen = 4 + $padLen
    $rdHeader = [byte[]]([byte](($rdlen -shr 8) -band 0xFF), [byte]($rdlen -band 0xFF))
    $pad = [byte[]](0x00,0x0C, [byte](($padLen -shr 8) -band 0xFF), [byte]($padLen -band 0xFF))
    $padding = New-Object byte[] $padLen
    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    $bytes.AddRange($hdr); $bytes.AddRange($qname); $bytes.AddRange($qtailer)
    $bytes.AddRange($optHdr); $bytes.AddRange($rdHeader); $bytes.AddRange($pad); $bytes.AddRange($padding)
    return ,$bytes.ToArray()
}

# Cloudflare-quic.com itself uses 1.1.1.1 for DNS. Test if 1.1.1.1:53
# UDP can answer big EDNS-padded queries through SS-UDP.
# (1.1.1.1 returns a small NOERROR + answer for a.com; we just need a
# response of any size to confirm round-trip.)
$sizes = @(64, 256, 600, 1100, 1232, 1400)
Write-Host "=== big-packet UDP probe to 1.1.1.1:53 (EDNS0-padded DNS) ==="
foreach ($sz in $sizes) {
    $payload = Make-Bloated-Dns-Query -TargetSize $sz
    $r = Probe-Udp -Server "1.1.1.1" -Port 53 -Payload $payload -TimeoutMs 4000
    if ($r.ok) { Write-Host ("  send={0,4}B  recv={1,4}B  {2,4}ms  OK"  -f $payload.Length, $r.bytes, $r.ms) }
    else      { Write-Host ("  send={0,4}B  FAIL {1,4}ms err={2}" -f $payload.Length, $r.ms, $r.err) }
}

Write-Host ""
Write-Host "Note: 1.1.1.1 may rate-limit or refuse oversized OPT queries;"
Write-Host "any 'OK' response (even an error code) proves round-trip carries."
