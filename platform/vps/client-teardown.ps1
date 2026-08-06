# ZeroPort - remove the client tunnel completely  (RUN AS ADMINISTRATOR)
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

$WGX  = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$conf = Join-Path $PSScriptRoot 'zpc.conf'

$svc = Get-Service -Name 'WireGuardTunnel$zpc' -ErrorAction SilentlyContinue
if (-not $svc) {
  Write-Host "Tunnel zpc is not installed - nothing to remove." -ForegroundColor Yellow
} else {
  & $WGX /uninstalltunnelservice zpc
  Start-Sleep -Seconds 2
  Write-Host "zpc removed." -ForegroundColor Green
}
Remove-Item $conf -Force -ErrorAction SilentlyContinue

if (Get-NetAdapter -Name 'zpc' -ErrorAction SilentlyContinue) {
  Write-Host "Adapter zpc still present; it disappears a few seconds after the service stops." -ForegroundColor Yellow
} else {
  Write-Host "No zpc adapter remains." -ForegroundColor Green
}
