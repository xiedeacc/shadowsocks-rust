#!pwsh
# UAC wrapper around _inject_ipv6_dns_override_elevated.ps1.
$ErrorActionPreference = "Stop"
$DeployPath = Join-Path $PSScriptRoot "_inject_ipv6_dns_override_elevated.ps1"
$argList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $DeployPath
)
Write-Host "Spawning elevated child to override IPv6 DNS to ::1..."
$proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -PassThru
$proc.WaitForExit()
Write-Host "elevated exit_code=$($proc.ExitCode)"
