@echo off
:: ====================================================================
:: shadowsocks-rust Windows TUN deployment - double-clickable cleanup
::
:: Self-elevates via UAC and runs force_cleanup.ps1, which:
::   * stops ssservice (and kills any orphan sslocal.exe / sswinservice.exe)
::   * removes every IPv4/IPv6 route on the shadowsocks-tun adapter
::   * removes the LAN / server / DNS bypass routes recorded in
::     install-record.json (or falls back to a private-prefix sweep)
::   * restores DNS on every interface back to its recorded servers
::     (both IPv4 and IPv6)
::   * flushes the OS DNS cache
::
:: It does NOT delete the Windows service entry by default - so on next
:: boot the service still auto-starts. If you want a full uninstall,
:: invoke force_cleanup.ps1 directly with -RemoveService.
::
:: Use this whenever Chrome shows DNS_PROBE_FINISHED_BAD_CONFIG, traffic
:: gets stuck after a dirty shutdown, or you simply want a known-clean
:: starting state before the next deploy.
:: ====================================================================

setlocal

:: ---- Self-elevate via UAC if not already running as administrator ----
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath cmd -ArgumentList '/c','""%~f0"" --elevated' -Verb RunAs"
    exit /b
)

:: ---- We are admin now. Run cleanup from this script's directory. ----
pushd "%~dp0"

echo.
echo === shadowsocks-rust Windows cleanup ===
echo Script: %~dp0force_cleanup.ps1
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0force_cleanup.ps1"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo === Cleanup finished successfully ===
) else (
    echo === Cleanup exited with code %RC% ===
)

popd
echo.
echo Press any key to close this window.
pause >nul
endlocal
