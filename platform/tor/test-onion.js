'use strict';
// PROOF: the rendezvous plane is reachable as a real Tor onion service.
//
// Starts the rendezvous, puts a real v3 onion service in front of it, then
// talks to it *through the Tor network* over SOCKS. The rendezvous itself binds
// only to 127.0.0.1 - it has no public port at any point.
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');
const ROOT = path.join(__dirname, '..', '..');
const socks = require(path.join(ROOT, 'src', 'transport', 'socks5'));
const tor = require('./start-tor');

const RDV_PORT = 8802;
const bar = (c = '=') => console.log(c.repeat(76));
const out = (s) => console.log('      ' + s);
const step = (s) => console.log('  > ' + s);
const results = [];
const check = (n, ok) => { results.push({ n, ok }); return ok; };

function publicallyBound(port) {
  // does anything answer on a non-loopback interface for this port?
  return new Promise((res) => {
    const s = new net.Socket();
    s.setTimeout(1200);
    const done = (v) => { s.destroy(); res(v); };
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
    // 0.0.0.0 bind would be reachable via the machine's LAN address
    const os = require('os');
    const ip = Object.values(os.networkInterfaces()).flat()
      .find((i) => i && i.family === 'IPv4' && !i.internal);
    if (!ip) return done(false);
    s.connect(port, ip.address);
  });
}

(async () => {
  console.log('');
  bar('#');
  console.log('  ZEROPORT - REAL TOR ONION SERVICE');
  bar('#');
  console.log('');

  const rdv = spawn(process.execPath, [path.join(ROOT, 'src', 'nodes', 'rendezvous.js'), String(RDV_PORT)], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => rdv.stdout.on('data', (d) => { if (d.toString().includes('#READY')) r(); }));
  out(`rendezvous listening on 127.0.0.1:${RDV_PORT} (loopback only)`);

  const exposed = await publicallyBound(RDV_PORT);
  check('the rendezvous is NOT reachable on a public interface', !exposed);
  out(`reachable from this machine's LAN address: ${exposed ? 'YES' : 'NO'}`);

  step('Starting Tor and publishing a v3 onion service...');
  let t;
  try {
    t = await tor.start(RDV_PORT, { onLog: (l) => { if (/bootstrap \d+%/.test(l)) out(l); } });
  } catch (e) {
    console.log('');
    out('Tor failed to start: ' + e.message);
    out('If the network blocks Tor, this is the one thing that cannot be worked around');
    out('from here - the rest of the system is unaffected.');
    rdv.kill();
    process.exit(1);
  }
  out(`onion address: ${t.onion}`);
  check('a real v3 onion address was issued', /^[a-z2-7]{56}\.onion$/.test(t.onion));

  // After bootstrap Tor still has to publish the service descriptor to the
  // directory hashring, and the client has to fetch it and build a rendezvous
  // circuit. The first connection therefore needs patience and a retry.
  async function viaTor(opts, attempts = 6) {
    let last;
    for (let i = 1; i <= attempts; i++) {
      try { return await socks.request({ socksPort: t.socksPort, host: t.onion, port: 80, timeout: 60000, ...opts }); }
      catch (e) {
        last = e;
        out(`attempt ${i}/${attempts} failed (${e.message}) - the descriptor may still be publishing`);
        await new Promise((r) => setTimeout(r, 8000));
      }
    }
    throw last;
  }

  step('Announcing an endpoint THROUGH the Tor network...');
  const payload = JSON.stringify({ id: 'zp1toronion', host: '127.0.0.1', port: 41234 });
  const a = await viaTor({ method: 'POST', path: '/announce', body: payload });
  out(`POST /announce -> HTTP ${a.status} ${a.body.trim()}`);
  check('the onion service accepted a write over Tor', a.status === 200);

  step('Reading it back through Tor...');
  const g = await viaTor({ method: 'GET', path: '/lookup?id=zp1toronion' });
  out(`GET /lookup -> HTTP ${g.status} ${g.body.trim()}`);
  let ok = false;
  try { ok = JSON.parse(g.body).port === 41234; } catch {}
  check('the data round-tripped through the Tor network', ok);

  console.log('');
  bar();
  let pass = 0;
  for (const r of results) { console.log('  ' + (r.ok ? 'PASS  ' : 'FAIL  ') + r.n); if (r.ok) pass++; }
  console.log('');
  console.log(`  ${pass}/${results.length} checks passed`);
  if (pass === results.length) {
    console.log('');
    console.log('  The rendezvous plane is now a genuine Tor onion service. It has no');
    console.log('  public port, its address is derived from its own key, and every');
    console.log('  request above travelled through the real Tor network.');
  }
  bar();
  console.log('');
  t.stop(); rdv.kill();
  process.exit(pass === results.length ? 0 : 1);
})().catch((e) => { console.error('ERROR', e); process.exit(1); });
