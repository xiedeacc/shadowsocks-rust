#!pwsh
<#
.SYNOPSIS
    Spin up the Windows TUN deployment, run a fixed-duration smoke test
    that exercises TCP via TUN + DNS via the local listener, then tear
    everything down. Must run elevated.

.DESCRIPTION
    Reused functions from deploy_windows.ps1 (Install-RoutesAndDns,
    Invoke-Cleanup, etc.) by dot-sourcing the script with a guard so
    Assert-Admin only fires once and the trailing `switch ($Action)`
    block is skipped via -DotSource.

    Flow:
      1. cleanup any leftovers
      2. spawn sslocal.exe -c <config> --log-without-time -vv
      3. wait for the TUN adapter (handled by Install-RoutesAndDns)
      4. install catch-all routes + DNS override
      5. test connectivity:
           - resolve a known foreign + domestic host via the 127.0.0.1:53
             listener
           - GET an external HTTPS endpoint (forced via TUN catch-all)
      6. always cleanup, even on failure
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "D:\software\shadowsocks",
    [string]$TunName    = "shadowsocks-tun",
    [string]$ServiceName= "ssservice",
    # Total time the smoke test gives sslocal to handle traffic before
    # we tear everything down. Includes ramp-up, the DNS/HTTP probes,
    # and a short cooldown so trailing log lines flush. Keep short:
    # with -vv (TRACE), sslocal writes ~5 MB/s of packet dumps and we
    # don't want to drown in disk I/O during cleanup.
    [int]   $TestSeconds = 15
)

$ErrorActionPreference = 'Stop'
$script:RepoRoot     = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$script:ResultPath   = Join-Path $script:RepoRoot "test-tun-result.json"
$script:ProgressLog  = Join-Path $script:RepoRoot "test-tun-progress.log"
$script:TranscriptLog= Join-Path $script:RepoRoot "test-tun-transcript.log"

# Capture every stream so silent crashes are diagnosable next run.
try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
try { Start-Transcript -LiteralPath $script:TranscriptLog -Force | Out-Null } catch {}
$script:Findings   = [ordered]@{
    started_at     = (Get-Date).ToString("o")
    finished_at    = $null
    success        = $false
    proc_pid       = $null
    proc_exit_code = $null
    config_path    = $null
    tun_adapter    = $null
    routes_after   = @()
    dns_after      = @()
    probes         = @()
    errors         = @()
    log_excerpt    = @()
    log_head       = @()
}
# Truncate progress log so the parent shell can tail it.
Set-Content -LiteralPath $script:ProgressLog -Value '' -Encoding UTF8

function Trace-Progress {
    param([string]$Phase)
    $line = "$(Get-Date -Format o) $Phase"
    Add-Content -LiteralPath $script:ProgressLog -Value $line -Encoding UTF8
    Write-Host "[test-tun] $Phase" -ForegroundColor Cyan
}

function Record-Probe {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $script:Findings.probes += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail }
}

function Save-Result {
    $script:Findings.finished_at = (Get-Date).ToString("o")
    $script:Findings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:ResultPath -Encoding UTF8
}

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Windows deployment requires an elevated PowerShell session."
    }
}

# ------------------------------------------------------------------
# We rebuild minimal versions of the helpers from deploy_windows.ps1
# instead of dot-sourcing so we don't have to refactor that script.
# Keep these in lock-step with the originals.
# ------------------------------------------------------------------

function Write-Step { param([string]$M) Write-Host "[test-tun] $M" -ForegroundColor Cyan }
function Write-Warn { param([string]$M) Write-Warning "[test-tun] $M" }

# Load deploy_windows.ps1 functions. The original script body has a
# trailing `switch ($Action)` that runs side effects, so we can't
# dot-source it directly. Instead slice out only the helper-function
# body (between the prelude and the "# Main" marker) and Invoke-Expression
# it into our scope.
$deployScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "deploy_windows.ps1")
$mainMarker   = "# Main"
$mainIdx      = $deployScript.IndexOf($mainMarker)
if ($mainIdx -lt 0) { throw "could not find '$mainMarker' marker in deploy_windows.ps1" }
# Skip the prelude (#!pwsh + comment-help + [CmdletBinding()] + param + $ErrorActionPreference)
# by anchoring on the unique 'function Assert-Admin' definition.
$startMarker = "function Assert-Admin"
$startIdx    = $deployScript.IndexOf($startMarker)
if ($startIdx -lt 0) { throw "could not find '$startMarker' in deploy_windows.ps1" }
$helperBody  = $deployScript.Substring($startIdx, $mainIdx - $startIdx)
Invoke-Expression $helperBody

Assert-Admin

# ------------------------------------------------------------------
# Run the whole flow inside a top-level try/finally so silent crashes
# (Start-Process throwing, an unhandled Set-Content failure, etc.)
# still get reflected in the result file and the transcript.
# ------------------------------------------------------------------
$proc = $null
try {
# ------------------------------------------------------------------
# 1. cleanup leftovers
# ------------------------------------------------------------------
Trace-Progress "phase=pre_cleanup start"
# Invoke-Cleanup only kills sslocal + sswinservice. The SS config uses
# xray-plugin as a child process: if it survives sslocal it keeps the
# inherited stdout handle on D:\software\shadowsocks\logs\sslocal.stdout.log
# which blocks the next Remove-Item / Start-Process redirect.
foreach ($name in 'sslocal','sswinservice','xray-plugin') {
    Get-Process -Name $name -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}
try {
    Invoke-Cleanup -Root $InstallDir -ServiceName $ServiceName -TunName $TunName
} catch {
    $script:Findings.errors += "pre-cleanup: $($_.Exception.Message)"
    Write-Warn "pre-cleanup raised: $($_.Exception.Message) (continuing)"
}
# Belt-and-braces in case Invoke-Cleanup spawned/inherited a plugin.
foreach ($name in 'sslocal','sswinservice','xray-plugin') {
    Get-Process -Name $name -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}
# Give the kernel a tick to drop any inherited handles before we
# attempt to truncate / redirect the log files.
Start-Sleep -Milliseconds 500
Trace-Progress "phase=pre_cleanup done"

# ------------------------------------------------------------------
# 2. sanity-check artefacts
# ------------------------------------------------------------------
$BinPath    = Join-Path $InstallDir "bin\sslocal.exe"
$ConfigPath = Join-Path $InstallDir "conf\shadowsocks-client.json"
$LogDir     = Join-Path $InstallDir "logs"
$StdoutLog  = Join-Path $LogDir    "sslocal.stdout.log"
$StderrLog  = Join-Path $LogDir    "sslocal.stderr.log"
$script:Findings.config_path = $ConfigPath

foreach ($p in @($BinPath, $ConfigPath)) {
    if (-not (Test-Path -LiteralPath $p)) {
        $script:Findings.errors += "missing artefact: $p"
        throw "missing artefact: $p"
    }
}
Trace-Progress "artefacts present"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
# Truncate log files; previous runs may have left them locked or huge.
# Delete + recreate is safer than Set-Content when the file may have
# been opened by another process moments earlier.
foreach ($p in @($StdoutLog, $StderrLog)) {
    try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } catch {}
}
New-Item -ItemType File -Path $StdoutLog -Force | Out-Null
New-Item -ItemType File -Path $StderrLog -Force | Out-Null
Trace-Progress "log files reset"

# ------------------------------------------------------------------
# 3. spawn sslocal.exe with --vv
# ------------------------------------------------------------------
$argList = @('-c', $ConfigPath, '--log-without-time', '-vv')
Trace-Progress "about to spawn sslocal args=$($argList -join ' ')"
$proc = Start-Process -FilePath $BinPath `
    -ArgumentList $argList `
    -WorkingDirectory $InstallDir `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError  $StderrLog `
    -PassThru -NoNewWindow
$script:Findings.proc_pid = $proc.Id
Trace-Progress "sslocal spawned pid=$($proc.Id)"

try {
    # Wait briefly for the TUN adapter to materialise.
    Start-Sleep -Seconds 2

    if ($proc.HasExited) {
        $msg = "sslocal exited prematurely with code $($proc.ExitCode); see $StderrLog"
        $script:Findings.errors += $msg
        Save-Result
        throw $msg
    }

    # --------------------------------------------------------------
    # 4. install routes + DNS override
    # --------------------------------------------------------------
    Trace-Progress "install routes + DNS override"
    $record = Install-RoutesAndDns -Root $InstallDir -ConfigPath $ConfigPath -TunName $TunName
    Save-Record -Root $InstallDir -Record $record
    Trace-Progress "routes installed"

    $tunAdapter = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
    if ($tunAdapter) {
        $script:Findings.tun_adapter = [ordered]@{
            name       = $tunAdapter.Name
            ifIndex    = $tunAdapter.ifIndex
            status     = "$($tunAdapter.Status)"
            macAddress = "$($tunAdapter.MacAddress)"
        }
        $script:Findings.routes_after = @(
            Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $tunAdapter.ifIndex } |
                ForEach-Object {
                    [ordered]@{
                        prefix  = $_.DestinationPrefix
                        nexthop = $_.NextHop
                        metric  = $_.RouteMetric
                    }
                }
        )
    } else {
        $script:Findings.errors += "TUN adapter '$TunName' not present after Install-RoutesAndDns"
    }

    $physical = Get-PhysicalAdapter
    if ($physical) {
        $dns = Get-DnsClientServerAddress -InterfaceAlias $physical.InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dns) {
            $script:Findings.dns_after += [ordered]@{
                alias   = $physical.InterfaceAlias
                servers = @($dns.ServerAddresses | ForEach-Object { [string]$_ })
            }
        }
    }

    # --------------------------------------------------------------
    # 5. probes
    # --------------------------------------------------------------
    Trace-Progress "warm up 3s"
    Start-Sleep -Seconds 3

    # Helper: run a scriptblock in a fresh runspace with a hard wall-
    # clock timeout. Returns the scriptblock's return value, or a
    # synthesized "timeout" pscustomobject. Using a runspace keeps the
    # parent thread responsive even when the probe blocks on a socket.
    # NOTE: do NOT name the array parameter `$Args` — it collides with
    # PowerShell's automatic `$Args` variable inside functions and the
    # bound value is silently lost (every probe in the previous run
    # got "argument is null or empty" because of this).
    function Invoke-WithTimeout {
        param(
            [scriptblock]$Script,
            [object[]]$ScriptArgs = @(),
            [int]$TimeoutSec = 8
        )
        $rs = [runspacefactory]::CreateRunspace()
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        $null = $ps.AddScript($Script)
        foreach ($a in $ScriptArgs) { $null = $ps.AddArgument($a) }
        $handle = $ps.BeginInvoke()
        if ($handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))) {
            try {
                $result = $ps.EndInvoke($handle)
                if ($result.Count -gt 0) { return $result[-1] }
                return $null
            } catch {
                return [pscustomobject]@{ ok=$false; detail=$_.Exception.Message }
            } finally {
                $ps.Dispose(); $rs.Dispose()
            }
        } else {
            try { $ps.Stop() } catch {}
            $ps.Dispose(); $rs.Dispose()
            return [pscustomobject]@{ ok=$false; detail="timeout after ${TimeoutSec}s" }
        }
    }

    # 5a. local DNS over 127.0.0.1:53 (TCP+UDP). `$host` is a PowerShell
    # automatic variable, so use a different name.
    Trace-Progress "probes:dns start"
    foreach ($probeHost in @('www.baidu.com','www.cloudflare.com','www.google.com')) {
        $r = Invoke-WithTimeout -Script {
            param($Name)
            try {
                $ans = Resolve-DnsName -Name $Name -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop
                $a = $ans | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
                if ($a)  { return [pscustomobject]@{ ok=$true;  detail="A=$($a.IPAddress)" } }
                $cn = $ans | Select-Object -First 1
                if ($cn) { return [pscustomobject]@{ ok=$true;  detail="$($cn.Type)=$($cn.NameHost)" } }
                return [pscustomobject]@{ ok=$false; detail='empty answer' }
            } catch {
                return [pscustomobject]@{ ok=$false; detail=$_.Exception.Message }
            }
        } -ScriptArgs @($probeHost) -TimeoutSec 5
        Record-Probe -Name "dns:$probeHost" -Ok $r.ok -Detail $r.detail
    }

    Trace-Progress "probes:http start"
    # Flush the Windows DNS Client cache. Without this the test can
    # silently reuse a stale (potentially poisoned / pre-TUN) resolution
    # for hosts like www.google.com, which makes the probe look like a
    # TUN+SS failure when it is really just OS-level cache reuse.
    try { Clear-DnsClientCache -ErrorAction Stop | Out-Null; Trace-Progress 'dns cache cleared' } catch { Trace-Progress "dns cache clear failed: $_" }
    # 5b. TCP via TUN catch-all. Use a non-bypassed host so the request
    # has to flow through the catch-all + sslocal.
    foreach ($url in @('https://www.cloudflare.com/cdn-cgi/trace','https://www.google.com/generate_204')) {
        # Use curl.exe rather than Invoke-WebRequest: the .NET HTTP
        # stack does opaque pre-flight (OCSP, ALPN, HTTP/2 probing)
        # that can silently hang on some hosts via the TUN path while
        # curl just opens a TCP socket and runs TLS, matching what
        # Chrome does. This makes the probe a cleaner signal.
        $r = Invoke-WithTimeout -Script {
            param($Url)
            $args = @('-s','-o','NUL','-w','status=%{http_code} ip=%{remote_ip} ttotal=%{time_total}','--max-time','8','--resolve',('dummy:443:127.0.0.1'),$Url)
            # Above --resolve is a no-op placeholder; rely on the
            # system resolver (= sslocal at 127.0.0.1:53). Curl uses
            # getaddrinfo by default, same as Chrome.
            $args = @('-s','-o','NUL','-w','status=%{http_code} ip=%{remote_ip} ttotal=%{time_total}','--max-time','8',$Url)
            $out = & curl.exe @args 2>&1
            if ($LASTEXITCODE -eq 0) {
                return [pscustomobject]@{ ok=$true; detail=("$out" -replace '\s+',' ') }
            } else {
                return [pscustomobject]@{ ok=$false; detail=("curl exit=$LASTEXITCODE $out" -replace '\s+',' ') }
            }
        } -ScriptArgs @($url) -TimeoutSec 10
        Record-Probe -Name "http-tun:$url" -Ok $r.ok -Detail $r.detail
    }

    Trace-Progress "probes done"
    # 5c. let logs accumulate for the remainder of the test window.
    $remaining = [Math]::Max(2, $TestSeconds - 6)
    Trace-Progress "soaking ${remaining}s"
    Start-Sleep -Seconds $remaining

    # Capture sslocal RSS / private bytes to verify memory work.
    try {
        $sslocalProc = Get-Process -Name sslocal -ErrorAction Stop | Select-Object -First 1
        $rssMB = [int]($sslocalProc.WorkingSet64 / 1MB)
        $privateMB = [int]($sslocalProc.PrivateMemorySize64 / 1MB)
        $cpuS = [double]$sslocalProc.CPU
        $script:Findings.memory = [ordered]@{
            pid = $sslocalProc.Id
            rss_mb = $rssMB
            private_mb = $privateMB
            cpu_s = $cpuS
        }
        Trace-Progress "sslocal pid=$($sslocalProc.Id) RSS=${rssMB}MB private=${privateMB}MB cpu=${cpuS}s"
    } catch { Trace-Progress "memory probe failed: $_" }

    # Capture log evidence WITHOUT slurping the whole file. With -vv
    # this file is ~5 MB/s, so `Get-Content -Tail` can balloon to
    # multi-GB RSS while the underlying file grows. Instead seek to
    # the last ~64 KiB and decode that slice.
    function Read-LogTail {
        param([string]$Path, [int]$Bytes = 65536)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $stream = $null
        try {
            $stream = [System.IO.File]::Open($Path,'Open','Read','ReadWrite')
            $len = $stream.Length
            $start = [Math]::Max(0L, $len - $Bytes)
            $null = $stream.Seek($start, 'Begin')
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            # Drop the first (possibly partial) line.
            if ($start -gt 0) { [void]$reader.ReadLine() }
            $lines = New-Object System.Collections.Generic.List[string]
            while (-not $reader.EndOfStream) { $lines.Add($reader.ReadLine()) }
            return $lines.ToArray()
        } finally {
            if ($stream) { $stream.Dispose() }
        }
    }

    function Read-LogHead {
        param([string]$Path, [int]$Lines = 60)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $stream = $null
        try {
            $stream = [System.IO.File]::Open($Path,'Open','Read','ReadWrite')
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $list = New-Object System.Collections.Generic.List[string]
            while (-not $reader.EndOfStream -and $list.Count -lt $Lines) {
                $list.Add($reader.ReadLine())
            }
            return $list.ToArray()
        } finally {
            if ($stream) { $stream.Dispose() }
        }
    }

    Trace-Progress "capturing log excerpts"
    if (Test-Path -LiteralPath $StdoutLog) {
        $logHead = Read-LogHead -Path $StdoutLog -Lines 60
        $script:Findings.log_head = @($logHead)
        $logTail = Read-LogTail -Path $StdoutLog -Bytes 65536
        # Keep just the last 80 lines for the result file so it stays
        # human-readable.
        if ($logTail.Count -gt 80) { $logTail = $logTail[-80..-1] }
        $script:Findings.log_excerpt = @($logTail)
        $script:Findings | Add-Member -NotePropertyName log_size_bytes -NotePropertyValue (Get-Item -LiteralPath $StdoutLog).Length -Force
    }
    Trace-Progress "log excerpts captured"

    if ($proc.HasExited) {
        $script:Findings.proc_exit_code = $proc.ExitCode
        $script:Findings.errors += "sslocal exited during test (code=$($proc.ExitCode))"
    }
    $script:Findings.success = -not $proc.HasExited -and (
        ($script:Findings.probes | Where-Object { $_.ok }).Count -gt 0
    )
} catch {
    $script:Findings.errors += "test body: $($_.Exception.Message)"
    Write-Warn "test body raised: $($_.Exception.Message)"
} finally {
    # ------------------------------------------------------------------
    # 6. cleanup
    # ------------------------------------------------------------------
    if ($proc) {
        Trace-Progress "stopping sslocal pid=$($proc.Id)"
        if (-not $proc.HasExited) {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
            # give the process a moment to release the TUN handle so cleanup
            # can drop routes without the kernel re-creating them.
            Start-Sleep -Seconds 1
        }
    } else {
        Trace-Progress "sslocal was never spawned; skipping Stop-Process"
    }
    # Make sure no plugin child outlives the test; otherwise it keeps
    # the stdout/stderr log handles open.
    foreach ($name in 'sslocal','sswinservice','xray-plugin') {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Trace-Progress "inner-finally post-cleanup start"
    try {
        Invoke-Cleanup -Root $InstallDir -ServiceName $ServiceName -TunName $TunName
    } catch {
        $script:Findings.errors += "post-cleanup: $($_.Exception.Message)"
        Write-Warn "post-cleanup raised: $($_.Exception.Message)"
    }
    Trace-Progress "inner-finally post-cleanup done"
}
} catch {
    # Top-level catch so early failures (Start-Process throwing, etc.)
    # still appear in the result file.
    $script:Findings.errors += "top-level: $($_.Exception.Message)"
    Trace-Progress "top-level error: $($_.Exception.Message)"
} finally {
    # Save the result LAST so the parent shell knows everything finished.
    Save-Result
    Trace-Progress "result written to $script:ResultPath"
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
}
