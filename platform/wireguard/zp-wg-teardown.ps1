# ZeroPort - remove the WireGuard interface completely  (RUN AS ADMINISTRATOR)
# Leaves the machine exactly as it was before zp-wg-setup.ps1.
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

$WGX  = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$conf = Join-Path $PSScriptRoot 'zp0.conf'

$svc = Get-Service -Name 'WireGuardTunnel$zp0' -ErrorAction SilentlyContinue
if (-not $svc) {
  Write-Host "zp0 is not installed - nothing to remove." -ForegroundColor Yellow
} else {
  Write-Host "Removing tunnel service zp0..." -ForegroundColor Cyan
  & $WGX /uninstalltunnelservice zp0
  Start-Sleep -Seconds 2
  Write-Host "zp0 removed." -ForegroundColor Green
}

Remove-Item $conf -Force -ErrorAction SilentlyContinue

$still = Get-NetAdapter -Name 'zp0' -ErrorAction SilentlyContinue
if ($still) {
  Write-Host "Adapter zp0 still present; it usually disappears a few seconds after the service stops." -ForegroundColor Yellow
} else {
  Write-Host "No zp0 adapter remains. The machine is back to its original state." -ForegroundColor Green
}
