#!pwsh
<#
.SYNOPSIS
    Probe whether the SS server / xray-plugin TCP path is healthy by:
      1. Spawning sslocal in the foreground (no system DNS/route changes).
      2. Using curl through SOCKS5 (127.0.0.1:1080) to fetch a few
         foreign HTTPS endpoints.
      3. Recording results to test-socks-only-result.json.

    This isolates the TCP-via-SS path from TUN routing and DNS upstream
    so we can tell whether a foreign-DNS timeout is caused by a broken
    SS plugin link or by the UDP-via-SS path specifically.

    No admin required; no routes/DNS are touched.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "D:\software\shadowsocks",
    [string]$ConfigFile = "shadowsocks-client-socksonly.json",
    [int]   $StartupSeconds = 6,
    [int]   $CurlTimeoutSec = 12
)

$ErrorActionPreference = 'Continue'
$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..\..\")
$ResultPath = Join-Path $RepoRoot "test-socks-only-result.json"

$Findings = [ordered]@{
    started_at  = (Get-Date).ToString("o")
    finished_at = $null
    success     = $false
    proc_pid    = $null
    probes      = @()
    errors      = @()
    log_excerpt = @()
}

function Record-Probe([string]$Name, [bool]$Ok, [string]$Detail) {
    $Findings.probes += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail }
}

function Save-Result {
    $Findings.finished_at = (Get-Date).ToString("o")
    $Findings | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

$BinPath    = Join-Path $InstallDir "bin\sslocal.exe"
$ConfigPath = Join-Path $InstallDir "conf\$ConfigFile"
$LogDir     = Join-Path $InstallDir "logs"
$StdoutLog  = Join-Path $LogDir "sslocal.stdout.log"
$StderrLog  = Join-Path $LogDir "sslocal.stderr.log"

foreach ($p in @($BinPath, $ConfigPath)) {
    if (-not (Test-Path -LiteralPath $p)) {
        $Findings.errors += "missing artefact: $p"
        Save-Result
        throw "missing artefact: $p"
    }
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
foreach ($p in @($StdoutLog, $StderrLog)) {
    try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } catch {}
    New-Item -ItemType File -Path $p -Force | Out-Null
}

foreach ($n in 'sslocal','sswinservice','xray-plugin') {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

$proc = Start-Process -FilePath $BinPath `
    -ArgumentList @('-c', $ConfigPath, '--log-without-time', '-v') `
    -WorkingDirectory $InstallDir `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError  $StderrLog `
    -PassThru -NoNewWindow
$Findings.proc_pid = $proc.Id
Write-Host "spawned sslocal pid=$($proc.Id)" -ForegroundColor Cyan

try {
    Start-Sleep -Seconds $StartupSeconds

    if ($proc.HasExited) {
        $Findings.errors += "sslocal exited early code=$($proc.ExitCode)"
        throw "sslocal died at startup"
    }

    $curl = "$env:WINDIR\System32\curl.exe"
    if (-not (Test-Path -LiteralPath $curl)) { $curl = "curl.exe" }

    $targets = @(
        @{ name = "socks5h:cloudflare-trace"; url = "https://www.cloudflare.com/cdn-cgi/trace";    resolver = "socks5h" },
        @{ name = "socks5h:google-204";       url = "https://www.google.com/generate_204";        resolver = "socks5h" },
        @{ name = "socks5h:github-zen";       url = "https://api.github.com/zen";                 resolver = "socks5h" },
        @{ name = "socks5h:icanhazip";        url = "https://icanhazip.com";                      resolver = "socks5h" },
        @{ name = "socks5h:ifconfig.me";      url = "https://ifconfig.me/ip";                     resolver = "socks5h" },
        @{ name = "socks5h:1.1.1.1";          url = "https://1.1.1.1/cdn-cgi/trace";              resolver = "socks5h" },
        @{ name = "socks5h:cf-doh";           url = "https://1.1.1.1/dns-query?name=www.google.com&type=A"; resolver = "socks5h" }
    )

    foreach ($t in $targets) {
        $proxy = if ($t.resolver -eq 'socks5h') { 'socks5h://127.0.0.1:1080' } else { 'socks5://127.0.0.1:1080' }
        try {
            $output = & $curl --silent --show-error --max-time $CurlTimeoutSec --proxy $proxy `
                -H 'accept: */*' `
                -o NUL -w "http=%{http_code} t=%{time_total}s code=$LASTEXITCODE" $t.url 2>&1
            $exit = $LASTEXITCODE
        } catch {
            $output = "exception: $($_.Exception.Message)"
            $exit = -1
        }
        $ok = $exit -eq 0 -and "$output" -match 'http=2\d{2}|http=3\d{2}'
        Record-Probe -Name $t.name -Ok $ok -Detail "exit=$exit $output"
    }

    $Findings.success = ($Findings.probes | Where-Object { $_.ok }).Count -gt 0
} catch {
    $Findings.errors += "test body: $($_.Exception.Message)"
} finally {
    if ($proc -and -not $proc.HasExited) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    foreach ($n in 'sslocal','sswinservice','xray-plugin') {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # Grab the last ~24 KiB of the log for diagnosis without slurping huge files.
    if (Test-Path -LiteralPath $StdoutLog) {
        try {
            $s = [System.IO.File]::Open($StdoutLog,'Open','Read','ReadWrite')
            $len = $s.Length
            $start = [Math]::Max(0L, $len - 24576)
            $null = $s.Seek($start, 'Begin')
            $r = New-Object System.IO.StreamReader($s, [System.Text.Encoding]::UTF8)
            if ($start -gt 0) { [void]$r.ReadLine() }
            $lines = New-Object System.Collections.Generic.List[string]
            while (-not $r.EndOfStream) { $lines.Add($r.ReadLine()) }
            $s.Dispose()
            if ($lines.Count -gt 60) { $lines = $lines.GetRange($lines.Count - 60, 60) }
            $Findings.log_excerpt = @($lines)
        } catch {
            $Findings.errors += "log read: $($_.Exception.Message)"
        }
    }

    Save-Result
    Write-Host "result written to $ResultPath" -ForegroundColor Cyan
}
