param(
    # NOTE: use the names browsers actually hit. `baidu.com` (bare apex) is an
    # un-geo-optimized 302 redirector pinned to a single Hebei Unicom IDC, and
    # `google.com` is a 301 to `www.google.com`. Measuring the bare names makes
    # us look at the redirect-target, not the page users actually load. Default
    # to the `www.` hostnames so TLS / TTFB numbers reflect the real user path.
    [string[]]$Targets = @('www.google.com', 'www.baidu.com'),
    [int]$Iterations = 3
)

$ErrorActionPreference = 'Stop'

foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
                    'http_proxy','https_proxy','all_proxy','no_proxy')) {
    Set-Item -Path "Env:$name" -Value '' -ErrorAction SilentlyContinue
}

function Measure-DnsAndTcp {
    param([string]$Domain)

    Write-Host ""
    Write-Host "==================== $Domain ====================" -ForegroundColor Cyan

    # 1) DNS resolution (cold via ipconfig flushdns, then warm)
    ipconfig /flushdns | Out-Null
    Start-Sleep -Milliseconds 200

    $dnsCold = Measure-Command {
        $script:resolved = Resolve-DnsName $Domain -Type A -DnsOnly -ErrorAction Stop
    }
    $aRecords = @($script:resolved | Where-Object { $_.Type -eq 'A' } | Select-Object -ExpandProperty IPAddress)
    Write-Host ("DNS cold:        {0,7:N1} ms  -> {1}" -f $dnsCold.TotalMilliseconds, ($aRecords -join ', '))

    $dnsWarm = Measure-Command {
        Resolve-DnsName $Domain -Type A -DnsOnly -ErrorAction Stop | Out-Null
    }
    Write-Host ("DNS warm:        {0,7:N1} ms" -f $dnsWarm.TotalMilliseconds)

    if (-not $aRecords -or $aRecords.Count -eq 0) {
        Write-Host "No A records, skipping TCP/TLS tests" -ForegroundColor Yellow
        return
    }

    $ip = $aRecords[0]
    Write-Host ("Test IP:          {0}" -f $ip)

    # ICMP ping to target IP (will go via TUN → SS or direct depending on routing)
    $pingOut = & ping -n 3 $ip 2>&1
    $pingLine = ($pingOut | Where-Object { $_ -match 'Average' }) -join ' '
    Write-Host ("ICMP via route:  {0}" -f $pingLine.Trim())

    # 2) Plain TCP connect time to :443 (uses the same path that HTTPS would use)
    $tcpTimes = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip, 443, $null, $null)
            if (-not $iar.AsyncWaitHandle.WaitOne(8000)) {
                $sw.Stop()
                Write-Host ("TCP connect [{0}]: TIMEOUT" -f $i) -ForegroundColor Red
                $client.Close()
                continue
            }
            $client.EndConnect($iar)
            $sw.Stop()
            $tcpTimes += $sw.Elapsed.TotalMilliseconds
            $client.Close()
        } catch {
            $sw.Stop()
            Write-Host ("TCP connect [{0}]: error {1}" -f $i, $_.Exception.Message) -ForegroundColor Red
        }
    }
    if ($tcpTimes.Count -gt 0) {
        $avg = ($tcpTimes | Measure-Object -Average).Average
        $min = ($tcpTimes | Measure-Object -Minimum).Minimum
        Write-Host ("TCP 443 connect: min={0,6:N1}ms avg={1,6:N1}ms ({2} runs)" -f $min, $avg, $tcpTimes.Count)
    }

    # 3) Full HTTPS GET timing decomposition via curl-with-trace
    #    --noproxy forces curl to ignore any leaked HTTPS_PROXY/SOCKS env so we
    #    truly measure the TUN/direct path rather than the SOCKS5 listener.
    $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue)
    if ($curl) {
        $fmt = 'dns_resolution=%{time_namelookup}s tcp_connect=%{time_connect}s tls_handshake=%{time_appconnect}s starttransfer=%{time_starttransfer}s total=%{time_total}s http=%{http_code} remote=%{remote_ip}'
        for ($i = 0; $i -lt $Iterations; $i++) {
            $out = & curl.exe --noproxy '*' -sS -o NUL -w $fmt --max-time 10 "https://$Domain/" 2>&1
            Write-Host ("curl HTTPS [{0}]: {1}" -f $i, ($out -join ' '))
        }
    }
}

Write-Host "Base RTT to AWS edge (54.179.191.126):" -ForegroundColor Yellow
ping -n 5 54.179.191.126 | Select-Object -Last 5

foreach ($t in $Targets) {
    Measure-DnsAndTcp -Domain $t
}

Write-Host ""
Write-Host "==== bypass_ip.txt size, dynamic entries: ====" -ForegroundColor Yellow
$bypassFile = "D:\software\shadowsocks\data\bypass_ip.txt"
if (Test-Path $bypassFile) {
    "lines: $((Get-Content $bypassFile | Measure-Object).Count)"
}
