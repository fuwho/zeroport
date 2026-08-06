#!/usr/bin/env bash
# ZeroPort - provision a second host (Ubuntu 22.04/24.04 VPS).
#
# Gives you the one thing a single machine cannot: a real network path between
# two hosts, so the tunnel carries real IP packets and the latency figures are
# wide-area figures rather than loopback figures.
#
# Run as root (or with sudo) on a FRESH VPS:
#     bash provision.sh
set -euo pipefail

WG_PORT=51820
RELAY_PORT=8801
WG_IF=zp0
SERVER_IP=10.77.0.1
CLIENT_IP=10.77.0.2

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash provision.sh"; exit 1; }

say "Installing WireGuard and Node.js"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard iproute2 curl ufw >/dev/null
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs >/dev/null
fi
echo "node $(node --version), wireguard $(wg --version | head -1)"

# ---------------------------------------------------------------- firewall
# ORDER MATTERS. Allow SSH *before* enabling ufw, or you will lock yourself
# out of this machine permanently and have to rebuild it.
say "Firewall"
ufw allow OpenSSH >/dev/null
ufw allow ${WG_PORT}/udp >/dev/null
ufw allow ${RELAY_PORT}/tcp >/dev/null
ufw --force enable >/dev/null
ufw status numbered | sed 's/^/    /'

# ---------------------------------------------------------------- wireguard
say "WireGuard interface ${WG_IF}"
if [ -f /etc/wireguard/${WG_IF}.conf ]; then
  warn "/etc/wireguard/${WG_IF}.conf already exists - leaving it alone"
else
  umask 077
  SRV_PRIV=$(wg genkey)
  SRV_PUB=$(printf '%s' "$SRV_PRIV" | wg pubkey)
  printf '%s' "$SRV_PUB" > /etc/wireguard/${WG_IF}.pub
  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
PrivateKey = ${SRV_PRIV}
Address    = ${SERVER_IP}/24
ListenPort = ${WG_PORT}
# No [Peer] yet - add the client with the printed command, or let ZeroPort do it.
EOF
  chmod 600 /etc/wireguard/${WG_IF}.conf
fi
systemctl enable --now wg-quick@${WG_IF} >/dev/null 2>&1 || systemctl restart wg-quick@${WG_IF}
SRV_PUB=$(cat /etc/wireguard/${WG_IF}.pub)
wg show ${WG_IF} | sed 's/^/    /'

# ---------------------------------------------------------------- relay
say "ZeroPort control plane"
if [ -d /opt/zeroport/demo ]; then
  cat > /etc/systemd/system/zeroport-relay.service <<EOF
[Unit]
Description=ZeroPort Nostr relay (NIP-01)
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/zeroport/demo/nostr-relay.js ${RELAY_PORT}
Restart=always
User=root
WorkingDirectory=/opt/zeroport/demo

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now zeroport-relay >/dev/null 2>&1 || systemctl restart zeroport-relay
  sleep 1
  systemctl is-active zeroport-relay | sed 's/^/    relay: /'
else
  warn "/opt/zeroport/demo not found - copy the demo folder up first, then re-run:"
  warn "    scp -r demo root@<this-host>:/opt/zeroport/demo"
  warn "  (WireGuard is already configured; only the relay was skipped.)"
fi

PUBIP=$(curl -fsS --max-time 5 https://api.ipify.org || echo "<this-server-ip>")

cat <<EOF

============================================================================
  SECOND HOST READY
============================================================================

  public address      : ${PUBIP}
  WireGuard endpoint  : ${PUBIP}:${WG_PORT}
  server public key   : ${SRV_PUB}
  tunnel address      : ${SERVER_IP}/24
  relay               : ws://${PUBIP}:${RELAY_PORT}

  On the Windows machine, from an ELEVATED PowerShell:

    cd C:\\Users\\stnal\\Projects\\zeroport\\demo\\vps
    .\\client-setup.ps1 -ServerPublicKey "${SRV_PUB}" -Endpoint "${PUBIP}:${WG_PORT}"

  That script prints the CLIENT public key. Bring it back here and run:

    wg set ${WG_IF} peer <CLIENT_PUBLIC_KEY> allowed-ips ${CLIENT_IP}/32
    wg show ${WG_IF}

  Then, from Windows:
    ping ${SERVER_IP}        <- a real ping, through a real tunnel, over the internet

============================================================================
EOF
