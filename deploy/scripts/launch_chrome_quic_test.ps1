<#
Launch a brand-new Chrome instance with:
  - a fresh user-data-dir (no broken-QUIC markers, no cached DNS)
  - --enable-quic explicitly on
  - --origin-to-force-quic-on for QUIC test sites, so Chrome skips the
    happy-eyeballs race and goes straight to UDP/443
  - a netlog dump in case anything is still odd

The user's normal Chrome session is unaffected. If THIS instance can
load cloudflare-quic.com over HTTP/3, the SS-UDP path works and the
regular session just needs to forget its old broken-host state (which
happens on a full Chrome restart, not on tab close).
#>
$ErrorActionPreference = "Stop"

$candidates = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$chrome = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $chrome) { throw "chrome.exe not found in standard locations" }
Write-Host "chrome: $chrome"

$profileDir = Join-Path $env:TEMP "chrome-quic-test"
$netLog     = Join-Path $env:TEMP "chrome-quic-test\netlog.json"
if (Test-Path $profileDir) { Remove-Item -Recurse -Force $profileDir }
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null

$quicOrigins = "cloudflare-quic.com:443,quic.aiortc.org:443,www.google.com:443"

$flags = @(
    "--user-data-dir=$profileDir",
    "--no-first-run",
    "--no-default-browser-check",
    "--enable-quic",
    "--quic-version=h3",
    "--origin-to-force-quic-on=$quicOrigins",
    "--log-net-log=$netLog",
    "--net-log-capture-mode=Default",
    "--new-window",
    "https://cloudflare-quic.com/"
)

Write-Host "spawning Chrome with explicit QUIC flags..."
Write-Host "  profile : $profileDir"
Write-Host "  netlog  : $netLog"
Write-Host "  forced  : $quicOrigins"
Write-Host ""
Start-Process -FilePath $chrome -ArgumentList $flags | Out-Null
Write-Host "If the page now reports HTTP/3, end-to-end QUIC works."
Write-Host "If it still shows HTTP/2, paste the path '$netLog' back to me;"
Write-Host "I'll grep it for QUIC_SESSION events to see exactly where Chrome stalls."
