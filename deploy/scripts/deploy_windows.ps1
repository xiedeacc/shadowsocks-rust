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

    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    $config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    $server = @($config.servers)[0].server

    $adapter = Wait-TunAdapter -Name $TunName
    if (-not $adapter) {
        Write-Warning "TUN adapter '$TunName' was not found; transparent routes were not installed."
        return
    }

    foreach ($prefix in "0.0.0.0/1", "128.0.0.0/1") {
        Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex -NextHop "0.0.0.0" -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }

    [System.Net.IPAddress]$serverIp = $null
    if ([System.Net.IPAddress]::TryParse($server, [ref]$serverIp) -and $defaultRoute -and $defaultRoute.NextHop -ne "0.0.0.0") {
        $hostPrefix = if ($serverIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "$server/32" } else { "$server/128" }
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
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
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
