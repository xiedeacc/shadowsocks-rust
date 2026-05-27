#!pwsh
# Quick A/B perf measurement script.
# Runs N curl iterations against a list of (label,url) targets and prints
# percentiles for TLS handshake and TTFB.

param(
    [int]$N = 10,
    # Default targets use the `www.` hostnames that browsers actually navigate
    # to. The bare apex names (`baidu.com`, `google.com`) are 301/302 redirect
    # entrypoints whose A records are NOT geo-optimised and therefore do not
    # represent real user-perceived latency. For baidu in particular:
    #   baidu.com       -> Hebei Unicom IDC (~200 ms TLS from SZ Unicom)
    #   www.baidu.com   -> www.a.shifen.com -> Guangzhou Unicom (~70 ms TLS)
    [string[]]$Targets = @(
        'baidu_direct=https://www.baidu.com/',
        'google_proxied=https://www.google.com/',
        'cloudflare_proxied=https://www.cloudflare.com/',
        'youtube_proxied=https://www.youtube.com/'
    )
)

$ErrorActionPreference = 'Stop'

# Strip every shell proxy env var that could route curl through SOCKS instead
# of the TUN path we are measuring.
foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
                    'http_proxy','https_proxy','all_proxy','no_proxy')) {
    Set-Item -Path "Env:$name" -Value '' -ErrorAction SilentlyContinue
}

function Pct {
    param($arr, $p)
    if (-not $arr -or $arr.Count -eq 0) { return 0 }
    $sorted = @($arr) | Sort-Object
    $idx = [Math]::Min([Math]::Floor($sorted.Count * $p), $sorted.Count - 1)
    return [Math]::Round($sorted[$idx] * 1000, 0)
}

foreach ($t in $Targets) {
    $label,$url = $t -split '=', 2
    Write-Host "" 
    Write-Host "== $label ($url) ==" -ForegroundColor Cyan

    $tcp = @(); $tls = @(); $ttfb = @(); $remote = ''
    for ($i = 0; $i -lt $N; $i++) {
        $out = & curl.exe --noproxy '*' -sS -o NUL --max-time 10 -w "%{time_connect};%{time_appconnect};%{time_starttransfer};%{remote_ip}" $url 2>$null
        if (-not $out) { continue }
        $parts = $out -split ';'
        if ($parts.Count -lt 4) { continue }
        $tcp  += [double]$parts[0]
        $tls  += [double]$parts[1]
        $ttfb += [double]$parts[2]
        $remote = $parts[3]
        Start-Sleep -Milliseconds 200
    }

    if ($tcp.Count -eq 0) {
        Write-Host "  (no successful samples)" -ForegroundColor Yellow
        continue
    }

    Write-Host ("  remote      : {0}" -f $remote)
    Write-Host ("  TCP   p50/p90: {0,4}ms / {1,4}ms" -f (Pct $tcp 0.5), (Pct $tcp 0.9))
    Write-Host ("  TLS   p50/p90: {0,4}ms / {1,4}ms" -f (Pct $tls 0.5), (Pct $tls 0.9))
    Write-Host ("  TTFB  p50/p90: {0,4}ms / {1,4}ms" -f (Pct $ttfb 0.5), (Pct $ttfb 0.9))
    Write-Host ("  samples     : {0}" -f $tcp.Count)
}
