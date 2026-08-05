# ZeroPort - connect this Windows machine to the second host  (RUN AS ADMINISTRATOR)
#
#   .\client-setup.ps1 -ServerPublicKey "<key>" -Endpoint "<ip>:51820"
#
# SAFETY: AllowedIPs is pinned to 10.77.0.0/24. It is NEVER 0.0.0.0/0.
# A default-route tunnel would push ALL of this machine's traffic through the
# VPS - which is a different product, costs bandwidth, and can break your
# connectivity if the far end goes away. This script refuses to do that.
#Requires -RunAsAdministrator

param(
  [Parameter(Mandatory = $true)][string]$ServerPublicKey,
  [Parameter(Mandatory = $true)][string]$Endpoint,     # <public-ip>:51820
  [string]$ClientIp = '10.77.0.2'
)

$ErrorActionPreference = 'Stop'

$WG   = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
$WGX  = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$conf = Join-Path $PSScriptRoot 'zpc.conf'

if (-not (Test-Path $WG)) { throw "wg.exe not found at $WG" }

# --- validate inputs rather than trusting them ---
if ($ServerPublicKey -notmatch '^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}$') {
  throw "ServerPublicKey does not look like a WireGuard key: $ServerPublicKey"
}
if ($Endpoint -notmatch '^[0-9A-Za-z\.\-]+:\d{1,5}$') {
  throw "Endpoint should look like 203.0.113.10:51820 - got: $Endpoint"
}
if ($ClientIp -notmatch '^10\.77\.0\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$') {
  throw "ClientIp must be inside 10.77.0.0/24 and not the server .1 - got: $ClientIp"
}

$existing = Get-Service -Name 'WireGuardTunnel$zpc' -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Tunnel zpc is already installed. Remove it first with .\client-teardown.ps1" -ForegroundColor Yellow
  & $WG show zpc
  exit 0
}

Write-Host "Generating this machine's tunnel key..." -ForegroundColor Cyan
$priv = & $WG genkey
$pub  = $priv | & $WG pubkey

# AllowedIPs is the ZeroPort subnet ONLY. Never 0.0.0.0/0.
@"
[Interface]
PrivateKey = $priv
Address    = $ClientIp/24

[Peer]
PublicKey           = $ServerPublicKey
Endpoint            = $Endpoint
AllowedIPs          = 10.77.0.0/24
PersistentKeepalive = 25
"@ | Out-File -FilePath $conf -Encoding ascii

Write-Host "Installing tunnel service zpc..." -ForegroundColor Cyan
& $WGX /installtunnelservice $conf
Start-Sleep -Seconds 3
Remove-Item $conf -Force -ErrorAction SilentlyContinue   # service keeps its own encrypted copy

Write-Host ""
Write-Host "Tunnel zpc is up." -ForegroundColor Green
Write-Host ""
Write-Host "  THIS MACHINE's public key (paste it on the server):" -ForegroundColor Yellow
Write-Host "     $pub"
Write-Host ""
Write-Host "  On the VPS, run:" -ForegroundColor Yellow
Write-Host "     wg set zp0 peer $pub allowed-ips $ClientIp/32"
Write-Host ""
Write-Host "  Then come back here and run:" -ForegroundColor Cyan
Write-Host "     ping 10.77.0.1"
Write-Host "     & '$WG' show zpc"
Write-Host ""
Write-Host "  A reply from 10.77.0.1 is a real IP packet, through a real WireGuard"
Write-Host "  tunnel, across the public internet. That is the number you could not"
Write-Host "  produce on one machine."
Write-Host ""
Write-Host "Undo: .\client-teardown.ps1" -ForegroundColor DarkGray
