# ZeroPort - create the real WireGuard data-plane interface  (RUN AS ADMINISTRATOR)
#
# Creates ONE interface, zp0, on 10.77.0.1/24 with NO peers.
# ZeroPort adds and removes peers at runtime, based on its own authorization
# decisions - that is the whole point: WireGuard moves the packets, ZeroPort
# decides who is allowed to exist in the peer list at all.
#
# SAFETY: AllowedIPs is deliberately confined to 10.77.0.0/24 and this script
# never sets 0.0.0.0/0. A default-route tunnel pointing at a peer that does not
# exist would black-hole ALL of your internet traffic.
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$WG   = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
$WGX  = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$conf = Join-Path $PSScriptRoot 'zp0.conf'

if (-not (Test-Path $WG))  { throw "wg.exe not found at $WG" }
if (-not (Test-Path $WGX)) { throw "wireguard.exe not found at $WGX" }

$existing = Get-Service -Name 'WireGuardTunnel$zp0' -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "zp0 is already installed. Current state:" -ForegroundColor Yellow
  & $WG show zp0
  exit 0
}

Write-Host "Generating the interface key..." -ForegroundColor Cyan
$priv = & $WG genkey
$pub  = $priv | & $WG pubkey

# No [Peer] sections on purpose - ZeroPort populates them.
@"
[Interface]
PrivateKey = $priv
Address    = 10.77.0.1/24
ListenPort = 51820
"@ | Out-File -FilePath $conf -Encoding ascii

Write-Host "Installing tunnel service zp0..." -ForegroundColor Cyan
& $WGX /installtunnelservice $conf
Start-Sleep -Seconds 3

# The service keeps its own encrypted copy; do not leave the private key lying about.
Remove-Item $conf -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "zp0 is up." -ForegroundColor Green
Write-Host "  interface public key : $pub"
Write-Host "  address              : 10.77.0.1/24"
Write-Host "  listen port          : 51820"
Write-Host "  peers                : none yet - ZeroPort will add them"
Write-Host ""
& $WG show zp0
Write-Host ""
Write-Host "Next:  node wg-proof.js   (also from an elevated shell)" -ForegroundColor Cyan
Write-Host "Undo:  .\zp-wg-teardown.ps1" -ForegroundColor DarkGray
