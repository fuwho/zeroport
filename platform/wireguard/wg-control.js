'use strict';
// The ZeroPort <-> WireGuard bridge.
//
// WireGuard has NO access control of its own: it forwards for whoever is in its
// peer list and refuses everyone else. That is exactly the gap ZeroPort fills.
// Authorization (identity, threshold-signed roster, policy, lease, revocation)
// is decided by ZeroPort; this module then makes the kernel agree by adding or
// removing the peer. Revoking a peer here removes its ability to send a single
// packet - not by a firewall rule, but by ceasing to exist to the data plane.
const { execFileSync } = require('child_process');
const path = require('path');

const WG = process.env.WG_PATH || path.join(process.env.ProgramFiles || 'C:\\Program Files', 'WireGuard', 'wg.exe');
const IFACE = 'zp0';
const SUBNET_PREFIX = '10.77.0.';          // the ONLY range we will ever route

function wg(args, opts = {}) {
  return execFileSync(WG, args, { encoding: 'utf8', ...opts });
}

// Refuse anything outside the ZeroPort subnet. A tunnel with allowed-ips
// 0.0.0.0/0 pointed at a peer that is not there would swallow all traffic on
// this machine, so that value must be impossible to reach from here.
function assertSafeIp(ip) {
  if (typeof ip !== 'string' || !ip.startsWith(SUBNET_PREFIX))
    throw new Error(`refusing allowed-ips "${ip}" - only ${SUBNET_PREFIX}0/24 is permitted`);
  const last = Number(ip.slice(SUBNET_PREFIX.length));
  if (!Number.isInteger(last) || last < 2 || last > 254)
    throw new Error(`refusing allowed-ips "${ip}" - host part out of range`);
}
const isKey = (k) => typeof k === 'string' && /^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}$/.test(k);

// Probes are expected to fail when the interface is absent, so their stderr is
// suppressed - otherwise wg.exe prints a scary line during a normal preflight.
const quiet = { stdio: ['pipe', 'pipe', 'ignore'] };
function available() {
  try { wg(['--version'], quiet); return true; } catch { return false; }
}
function interfaceUp() {
  try { return wg(['show', IFACE, 'public-key'], quiet).trim().length > 0; } catch { return false; }
}
function genKeyPair() {
  const priv = wg(['genkey']).trim();
  const pub = wg(['pubkey'], { input: priv }).trim();
  return { priv, pub };
}

// `wg show <if> dump`: line 1 is the interface, the rest are peers.
function listPeers() {
  const lines = wg(['show', IFACE, 'dump']).trim().split('\n').slice(1);
  return lines.filter(Boolean).map((l) => {
    const [publicKey, , endpoint, allowedIps, latestHandshake, rx, tx] = l.split('\t');
    return { publicKey, endpoint, allowedIps, latestHandshake: Number(latestHandshake), rx: Number(rx), tx: Number(tx) };
  });
}

function addPeer(publicKey, ip, endpoint) {
  if (!isKey(publicKey)) throw new Error('not a valid WireGuard public key');
  assertSafeIp(ip);
  const args = ['set', IFACE, 'peer', publicKey, 'allowed-ips', `${ip}/32`];
  if (endpoint) args.push('endpoint', endpoint);
  args.push('persistent-keepalive', '25');
  wg(args);
  return { publicKey, ip };
}

function removePeer(publicKey) {
  if (!isKey(publicKey)) throw new Error('not a valid WireGuard public key');
  wg(['set', IFACE, 'peer', publicKey, 'remove']);
}

function removeAllPeers() {
  for (const p of listPeers()) removePeer(p.publicKey);
}

module.exports = { WG, IFACE, SUBNET_PREFIX, available, interfaceUp, genKeyPair, listPeers, addPeer, removePeer, removeAllPeers, assertSafeIp };
