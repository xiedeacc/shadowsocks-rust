#!pwsh
<#
.SYNOPSIS
    Probe sslocal's DNS module without TUN. Runs sslocal in the
    foreground with SOCKS:1080 + DNS:1053 and resolves foreign / domestic
    names through 127.0.0.1:1053, recording response time.

    This is used to validate the "skip UDP upstream when plugin is
    TcpOnly" fix: with the fix, foreign queries should complete in
    ~500-2000ms via TCP-over-SS instead of timing out at 5-10s.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "D:\software\shadowsocks",
    [string]$ConfigFile = "shadowsocks-client-dnstest.json",
    [int]   $StartupSeconds = 4,
    [int]   $QueryTimeoutSec = 6
)

$ErrorActionPreference = 'Continue'
$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..\..\")
$ResultPath = Join-Path $RepoRoot "test-dns-only-result.json"

$Findings = [ordered]@{
    started_at  = (Get-Date).ToString("o")
    finished_at = $null
    success     = $false
    proc_pid    = $null
    probes      = @()
    errors      = @()
    log_excerpt = @()
}

function Record-Probe([string]$Name, [bool]$Ok, [string]$Detail, [double]$ElapsedMs) {
    $Findings.probes += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail; elapsed_ms = [int]$ElapsedMs }
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

try {
    Start-Sleep -Seconds $StartupSeconds

    if ($proc.HasExited) {
        $Findings.errors += "sslocal exited early code=$($proc.ExitCode)"
        throw "sslocal died at startup"
    }

    # Build a minimal A-record DNS query (RFC 1035 header + question).
    function New-DnsQuery {
        param([string]$Name)
        $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $idBuf  = [byte[]]::new(2); $rng.GetBytes($idBuf); $rng.Dispose()
        # Header: id, flags=RD(0x0100), QD=1, AN=0, NS=0, AR=0
        $header = $idBuf + @(0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00)
        # QNAME: each label prefixed by its length, terminated by zero
        $qname = New-Object System.Collections.Generic.List[byte]
        foreach ($label in $Name.Split('.')) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            $qname.Add([byte]$bytes.Length)
            $qname.AddRange($bytes)
        }
        $qname.Add(0)
        # QTYPE=A (1), QCLASS=IN (1)
        $tail = @(0x00,0x01, 0x00,0x01)
        return [byte[]]($header + $qname.ToArray() + $tail)
    }

    function Parse-DnsAnswer {
        param([byte[]]$Buf)
        if ($null -eq $Buf -or $Buf.Length -lt 12) { return $null }
        $ancount = ([int]$Buf[6] -shl 8) -bor $Buf[7]
        if ($ancount -le 0) { return $null }
        # Skip header + question
        $idx = 12
        while ($idx -lt $Buf.Length -and $Buf[$idx] -ne 0) {
            if ($Buf[$idx] -ge 0xC0) { $idx += 2; break }
            $idx += 1 + $Buf[$idx]
        }
        if ($Buf[$idx] -eq 0) { $idx += 1 }
        $idx += 4   # QTYPE + QCLASS
        # Walk answer RRs
        for ($i = 0; $i -lt $ancount; $i++) {
            if ($idx -ge $Buf.Length) { return $null }
            # NAME: skip (compressed pointer is 2 bytes starting with 0xC0)
            if ($Buf[$idx] -ge 0xC0) { $idx += 2 }
            else {
                while ($idx -lt $Buf.Length -and $Buf[$idx] -ne 0) { $idx += 1 + $Buf[$idx] }
                $idx += 1
            }
            if ($idx + 10 -gt $Buf.Length) { return $null }
            $type  = ([int]$Buf[$idx] -shl 8) -bor $Buf[$idx+1]
            $rdlen = ([int]$Buf[$idx+8] -shl 8) -bor $Buf[$idx+9]
            $idx  += 10
            if ($type -eq 1 -and $rdlen -eq 4) {
                return "A=$($Buf[$idx]).$($Buf[$idx+1]).$($Buf[$idx+2]).$($Buf[$idx+3])"
            }
            $idx += $rdlen
        }
        return "ancount=$ancount no-A"
    }

    function Invoke-UdpDns {
        param([string]$Hostname, [string]$Server, [int]$Port, [int]$TimeoutMs)
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.UdpClient
            $client.Client.ReceiveTimeout = $TimeoutMs
            $client.Connect($Server, $Port)
            $q = New-DnsQuery -Name $Hostname
            $null = $client.Send($q, $q.Length)
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $buf = $client.Receive([ref]$remote)
            return Parse-DnsAnswer -Buf $buf
        } finally {
            if ($client) { $client.Close() }
        }
    }

    $targets = @(
        @{ name = "foreign:www.google.com";     host = "www.google.com" },
        @{ name = "foreign:www.cloudflare.com"; host = "www.cloudflare.com" },
        @{ name = "foreign:api.github.com";     host = "api.github.com" },
        @{ name = "domestic:www.baidu.com";     host = "www.baidu.com" },
        @{ name = "domestic:weibo.com";         host = "weibo.com" }
    )

    foreach ($t in $targets) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $detail = Invoke-UdpDns -Hostname $t.host -Server '127.0.0.1' -Port 1053 -TimeoutMs ($QueryTimeoutSec * 1000)
            $sw.Stop()
            if ($detail -match '^A=') {
                Record-Probe -Name $t.name -Ok $true -Detail $detail -ElapsedMs $sw.Elapsed.TotalMilliseconds
            } else {
                Record-Probe -Name $t.name -Ok $false -Detail "no A record: $detail" -ElapsedMs $sw.Elapsed.TotalMilliseconds
            }
        } catch {
            $sw.Stop()
            Record-Probe -Name $t.name -Ok $false -Detail "exception: $($_.Exception.Message)" -ElapsedMs $sw.Elapsed.TotalMilliseconds
        }
    }

    $Findings.success = ($Findings.probes | Where-Object { $_.ok -and $_.name -like 'foreign:*' }).Count -gt 0
} catch {
    $Findings.errors += "test body: $($_.Exception.Message)"
} finally {
    if ($proc -and -not $proc.HasExited) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    foreach ($n in 'sslocal','sswinservice','xray-plugin') {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $StdoutLog) {
        try {
            $s = [System.IO.File]::Open($StdoutLog,'Open','Read','ReadWrite')
            $len = $s.Length
            $start = [Math]::Max(0L, $len - 32768)
            $null = $s.Seek($start, 'Begin')
            $r = New-Object System.IO.StreamReader($s, [System.Text.Encoding]::UTF8)
            if ($start -gt 0) { [void]$r.ReadLine() }
            $lines = New-Object System.Collections.Generic.List[string]
            while (-not $r.EndOfStream) { $lines.Add($r.ReadLine()) }
            $s.Dispose()
            if ($lines.Count -gt 50) { $lines = $lines.GetRange($lines.Count - 50, 50) }
            $Findings.log_excerpt = @($lines)
        } catch {
            $Findings.errors += "log read: $($_.Exception.Message)"
        }
    }

    Save-Result
    Write-Host "result written to $ResultPath" -ForegroundColor Cyan
}
