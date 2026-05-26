#!pwsh
# Wrapper: triggers UAC and runs _fix_all_dns_now.ps1.
$ErrorActionPreference = 'Stop'
$child = Join-Path $PSScriptRoot '_fix_all_dns_now.ps1'
$out   = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'fix-dns-elevated.log'
$flag  = $out + '.ok'
Remove-Item -LiteralPath $flag -ErrorAction SilentlyContinue
$wrapTemplate = @'
try {
  & 'CHILD_PATH' *>&1 | Tee-Object -FilePath 'OUT_PATH'
  'OK'   | Out-File -FilePath 'FLAG_PATH' -Encoding utf8
} catch {
  $_ | Out-File -FilePath 'OUT_PATH' -Append -Encoding utf8
  'FAIL' | Out-File -FilePath 'FLAG_PATH' -Encoding utf8
}
'@
$wrap = $wrapTemplate.Replace('CHILD_PATH',$child).Replace('OUT_PATH',$out).Replace('FLAG_PATH',$flag)
$tmp = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(),'ps1')
Set-Content -LiteralPath $tmp -Value $wrap -Encoding UTF8
Start-Process powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$tmp) -Verb RunAs -WindowStyle Hidden -Wait
Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
Get-Content -LiteralPath $out | Select-Object -Last 30
"flag = $(Get-Content -LiteralPath $flag -ErrorAction SilentlyContinue)"
