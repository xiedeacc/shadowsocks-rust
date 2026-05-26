<#
Probes AWS UDP/443 reachability. Sends a small UDP datagram to the
shadowsocks server and watches the nginx access log on the AWS box.
A "recv" line in /var/log/nginx/ss-udp.log proves the security group
allows UDP/443.

Usage:
    powershell -ExecutionPolicy Bypass -File probe_aws_udp443.ps1
#>
$ErrorActionPreference = "Stop"

$Server = "54.179.191.126"
$Port   = 443

Write-Host "=== sending probe to ${Server}:${Port}/udp ==="
$udp = New-Object System.Net.Sockets.UdpClient
$udp.Client.ReceiveTimeout = 2000
try {
    $udp.Connect($Server, $Port)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("SS-UDP-PROBE-" + (Get-Date -Format HHmmss))
    $udp.Send($bytes, $bytes.Length) | Out-Null
    Write-Host "sent: $($bytes.Length) bytes"
    # We don't expect a reply for plaintext (ssserver will reject) — only the
    # nginx access log line matters.
} finally { $udp.Close() }

Start-Sleep -Seconds 1

Write-Host ""
Write-Host "=== tail of /var/log/nginx/ss-udp.log on AWS ==="
ssh -o ConnectTimeout=8 ubuntu@$Server "sudo tail -n 5 /var/log/nginx/ss-udp.log"

Write-Host ""
Write-Host "If a line shows your local IP + UDP, SG is OPEN."
Write-Host "If the tail is unchanged from before, SG still BLOCKS UDP/${Port}."
