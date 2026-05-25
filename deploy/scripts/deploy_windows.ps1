#!pwsh
param(
    [string]$InstallDir = "D:\software\shadowsocks",
    [string]$ServiceName = "ssservice",
    [string]$Features = "full local-web-admin local-http-rustls winservice",
    [string]$XrayPlugin = "",
    [switch]$SkipBuild,
    [switch]$ForceConfig,
    [switch]$SkipService,
    [switch]$SkipRoutes
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Windows deployment requires an elevated PowerShell session."
    }
}

function Invoke-Sc {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & sc.exe @Args | Out-Host
    return $LASTEXITCODE
}

function Wait-TunAdapter {
    param([string]$Name)
    for ($i = 0; $i -lt 20; $i++) {
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            return $adapter
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

function Install-TunRoutes {
    param(
        [string]$ConfigPath,
        [string]$TunName
    )

    $config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    $server = @($config.servers)[0].server

    $adapter = Wait-TunAdapter -Name $TunName
    if (-not $adapter) {
        Write-Warning "TUN adapter '$TunName' was not found; transparent routes were not installed."
        return
    }

    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -ne $adapter.ifIndex -and $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if (-not $defaultRoute) {
        Write-Warning "Physical default route was not found; transparent routes were not installed."
        return
    }

    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    foreach ($prefix in "0.0.0.0/1", "128.0.0.0/1") {
        Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex -NextHop "0.0.0.0" -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }

    foreach ($prefix in "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15") {
        Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRoute.InterfaceIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }

    $defaultRouteV6 = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -ne $adapter.ifIndex } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if ($defaultRouteV6) {
        foreach ($prefix in "fc00::/7", "fe80::/10") {
            Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $defaultRouteV6.InterfaceIndex } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRouteV6.InterfaceIndex -NextHop $defaultRouteV6.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
        }
    }

    $routeIps = @($server)
    if ($config.route_rules) {
        $routeIps += @($config.route_rules.domestic_dns)
        $routeIps += @($config.route_rules.foreign_dns)
    }
    foreach ($routeIpValue in $routeIps) {
        if (-not $routeIpValue) { continue }
        $routeIpText = [string]$routeIpValue
        $routeIpText = $routeIpText.Trim()
        if ($routeIpText -match '^\[(?<host>[^\]]+)\](?::\d+)?$') {
            $routeIpText = $Matches.host
        } elseif ($routeIpText -match '^(?<host>[^:]+):\d+$') {
            $routeIpText = $Matches.host
        }
        [System.Net.IPAddress]$serverIp = $null
        if (-not [System.Net.IPAddress]::TryParse($routeIpText, [ref]$serverIp)) { continue }
        $hostPrefix = if ($serverIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "$routeIpText/32" } else { "$routeIpText/128" }
        Get-NetRoute -DestinationPrefix $hostPrefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $hostPrefix -InterfaceIndex $defaultRoute.InterfaceIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }
}

Assert-Admin
if ($ServiceName -ne "ssservice") {
    throw "sswinservice registers itself as 'ssservice'; use the default ServiceName."
}

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$WindowsDir = Join-Path $RootDir "deploy\windows"
$ReleaseDir = Join-Path $RootDir "target\release"
$ConfigSource = Join-Path $WindowsDir "conf\shadowsocks-client.json"

if (-not $SkipBuild) {
    cargo build --release --no-default-features --features $Features --bin sslocal --bin sswinservice
}

$Directories = @(
    (Join-Path $InstallDir "bin"),
    (Join-Path $InstallDir "conf"),
    (Join-Path $InstallDir "data"),
    (Join-Path $InstallDir "logs")
)
New-Item -ItemType Directory -Force -Path $Directories | Out-Null

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $serviceProcess = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($serviceProcess -and $serviceProcess.ProcessId -and $serviceProcess.ProcessId -ne 0) {
        Stop-Process -Id $serviceProcess.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

Copy-Item -Force -LiteralPath (Join-Path $ReleaseDir "sslocal.exe") -Destination (Join-Path $InstallDir "bin\sslocal.exe")
Copy-Item -Force -LiteralPath (Join-Path $ReleaseDir "sswinservice.exe") -Destination (Join-Path $InstallDir "bin\sswinservice.exe")

if ($XrayPlugin) {
    Copy-Item -Force -LiteralPath $XrayPlugin -Destination (Join-Path $InstallDir "bin\xray-plugin.exe")
}

$ConfigDest = Join-Path $InstallDir "conf\shadowsocks-client.json"
if ($ForceConfig -or -not (Test-Path -LiteralPath $ConfigDest)) {
    Copy-Item -Force -LiteralPath $ConfigSource -Destination $ConfigDest
}

$UbuntuData = Join-Path $RootDir "deploy\ubuntu\data"
if (Test-Path -LiteralPath $UbuntuData) {
    Copy-Item -Force -Recurse -Path (Join-Path $UbuntuData "*") -Destination (Join-Path $InstallDir "data")
}

if (-not $SkipService) {
    $ServiceExe = Join-Path $InstallDir "bin\sswinservice.exe"
    $BinPath = "`"$ServiceExe`" local -c `"$ConfigDest`" --log-without-time"
    if ($existing) {
        Invoke-Sc config $ServiceName binPath= $BinPath start= auto | Out-Null
    } else {
        Invoke-Sc create $ServiceName binPath= $BinPath start= auto | Out-Null
    }
    Start-Service -Name $ServiceName
}

if (-not $SkipRoutes) {
    Install-TunRoutes -ConfigPath $ConfigDest -TunName "shadowsocks-tun"
}

Write-Host "Deployed shadowsocks-rust to $InstallDir"
