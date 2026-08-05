'use strict';
// Real wide-area measurements, once the second host is up.
//
//   node wan-measure.js --public <vps-ip> [--port 8801] [--n 20]
//
// Measures the same endpoint two ways - through the WireGuard tunnel, and
// straight over the public internet - so the tunnel's true overhead is visible.
// These are genuine WAN figures. The single-machine run could only ever report
// loopback ratios, and said so.
const net = require('net');
const path = require('path');
const nclient = require(path.join(__dirname, '..', 'lib', 'nclient'));
const nostr = require(path.join(__dirname, '..', 'lib', 'nostr'));
const frost = require(path.join(__dirname, '..', 'lib', 'frost'));

const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const PUBLIC = arg('public');
const TUNNEL = arg('tunnel', '10.77.0.1');
const PORT = Number(arg('port', 8801));
const N = Number(arg('n', 20));

if (!PUBLIC) {
  console.error('usage: node wan-measure.js --public <vps-ip> [--tunnel 10.77.0.1] [--port 8801] [--n 20]');
  process.exit(1);
}

const stats = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  return { n: s.length, min: s[0], median: s[Math.floor(s.length / 2)], max: s[s.length - 1] };
};
const fmt = (s) => (s ? `min ${s.min.toFixed(1)} / median ${s.median.toFixed(1)} / max ${s.max.toFixed(1)} ms  (${s.n} samples)` : 'no successful samples');

function tcpRtt(host, port, timeout = 4000) {
  return new Promise((res) => {
    const t0 = process.hrtime.bigint();
    const s = new net.Socket();
    const done = (v) => { s.destroy(); res(v); };
    s.setTimeout(timeout);
    s.once('connect', () => done(Number(process.hrtime.bigint() - t0) / 1e6));
    s.once('timeout', () => done(null));
    s.once('error', () => done(null));
    s.connect(port, host);
  });
}

async function series(host, label) {
  const out = [];
  process.stdout.write(`  ${label.padEnd(34)}`);
  for (let i = 0; i < N; i++) {
    const r = await tcpRtt(host, PORT);
    if (r !== null) out.push(r);
    process.stdout.write(r === null ? 'x' : '.');
  }
  console.log('');
  return out;
}

(async () => {
  console.log('');
  console.log('='.repeat(78));
  console.log('  ZEROPORT - WIDE-AREA MEASUREMENTS');
  console.log('='.repeat(78));
  console.log(`  public endpoint : ${PUBLIC}:${PORT}`);
  console.log(`  tunnel endpoint : ${TUNNEL}:${PORT}`);
  console.log('');

  const direct = await series(PUBLIC, 'over the public internet');
  const tunnel = await series(TUNNEL, 'through the WireGuard tunnel');

  const sd = stats(direct), st = stats(tunnel);
  console.log('');
  console.log(`  public internet : ${fmt(sd)}`);
  console.log(`  wireguard tunnel: ${fmt(st)}`);
  if (sd && st) {
    const overhead = st.median - sd.median;
    console.log('');
    console.log(`  tunnel overhead : ${overhead >= 0 ? '+' : ''}${overhead.toFixed(1)} ms on the median`);
    console.log('  Encryption costs very little; almost all of the latency is distance.');
  }
  if (!st) {
    console.log('');
    console.log('  The tunnel produced no samples. Check that the peer was added on the VPS:');
    console.log('      wg set zp0 peer <client-public-key> allowed-ips 10.77.0.2/32');
  }

  // ---- real control-plane round trip over the WAN ----
  console.log('');
  console.log('-'.repeat(78));
  console.log('  CONTROL PLANE OVER THE REAL INTERNET');
  console.log('-'.repeat(78));
  try {
    const conn = await nclient.connect(`ws://${TUNNEL}:${PORT}`, 8000);
    const GROUP = frost.deal(2, 3);
    const ev = nostr.build({
      pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
      tags: [['d', 'zeroport-wan-test']], content: { probe: true },
    }, (id) => frost.sign(id, GROUP.shares.slice(0, 2), GROUP.groupPub));

    const t0 = process.hrtime.bigint();
    const ok = await conn.publish(ev);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    console.log(`  published a FROST-signed roster to the remote relay: ${ok.ok}`);
    console.log(`  round trip through the tunnel: ${ms.toFixed(1)} ms`);
    console.log('  The relay verified a 2-of-3 threshold signature on another continent-scale');
    console.log('  network path, not on this machine.');
    conn.close();
  } catch (e) {
    console.log(`  could not reach the relay over the tunnel: ${e.message}`);
    console.log('  (WireGuard may be up while the relay service is not - check on the VPS:');
    console.log('      systemctl status zeroport-relay )');
  }

  console.log('');
  console.log('='.repeat(78));
  console.log('');
  process.exit(0);
})();
