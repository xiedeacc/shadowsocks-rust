$ErrorActionPreference = 'SilentlyContinue'
$log  = 'D:\code\shadowsocks\shadowsocks-rust\futu_conns.log'
$seen = @{}
$sw = New-Object System.IO.StreamWriter($log, $false, [System.Text.Encoding]::ASCII)
$sw.AutoFlush = $true
$sw.WriteLine("=== Futu connection logger (ALL FTNN processes) started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===")

while ($true) {
    # All processes running from the Futu install directory.
    $procs = Get-Process | Where-Object { $_.Path -like '*\FTNN\*' }
    $pids  = $procs.Id
    $pmap  = @{}; foreach ($p in $procs) { $pmap[[int]$p.Id] = $p.ProcessName }

    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $pids -contains $_.OwningProcess -and
            $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|169\.254\.|0\.0\.0\.0|::|172\.(1[6-9]|2[0-9]|3[01])\.|224\.)'
        }

    foreach ($c in $conns) {
        $key = "$($c.LocalPort)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $ts   = Get-Date -Format 'HH:mm:ss.fff'
            $proc = $pmap[[int]$c.OwningProcess]
            $line = "{0}  {1,-14} PID={2,-6} lport={3,-6} -> {4}:{5,-6} {6}" -f `
                    $ts, $proc, $c.OwningProcess, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State
            $sw.WriteLine($line)
        }
    }
    Start-Sleep -Milliseconds 120
}
