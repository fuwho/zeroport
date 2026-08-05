'use strict';
// ZeroPort Operations Console - LIVE.
//
// This is not a mockup. It starts the real network (Nostr relay, rendezvous,
// three agents), then serves a console that shows what is actually happening:
// the real FROST group key, the real signed roster, real audit entries with
// their real hashes, and a chain verification that genuinely runs.
//
// Every button issues a real command to a real agent process.
//
//   node dashboard/server.js      then open http://127.0.0.1:8080
const http = require('http');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const DIR = __dirname;
const ROOT = path.join(DIR, '..');
const zp = require(path.join(ROOT, 'lib', 'zp'));
const bip = require(path.join(ROOT, 'lib', 'bip340'));
const frost = require(path.join(ROOT, 'lib', 'frost'));
const nostr = require(path.join(ROOT, 'lib', 'nostr'));
const nclient = require(path.join(ROOT, 'lib', 'nclient'));
const ws = require(path.join(ROOT, 'lib', 'ws'));

const HTTP_PORT = 8080;
const RELAY_PORT = 8811;
const RDV_PORT = 8812;
const RELAY_WS = `ws://127.0.0.1:${RELAY_PORT}`;
const RDV = `http://127.0.0.1:${RDV_PORT}`;

const kids = [];
const clients = new Set();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const broadcast = (o) => { const s = JSON.stringify(o); for (const c of clients) c.send(s); };

// ---------------------------------------------------------------- state
const GROUP = frost.deal(2, 3);
const officers = [zp.newIdentity(), zp.newIdentity(), zp.newIdentity()];
const officerPubs = officers.map((o) => o.pub);
let version = 0;
let relayConn = null;
let agents = {};
let roster = null;
const log = [];                    // recent audit entries, newest last

function launch(file, args, name) {
  const p = spawn(process.execPath, [path.join(ROOT, file), ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  p.name = name; p.events = [];
  let buf = '';
  const ready = new Promise((res) => (p._res = res));
  p.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line.startsWith('#READY ')) p._res(JSON.parse(line.slice(7)));
      else if (line.startsWith('#EVT ')) {
        const e = JSON.parse(line.slice(5));
        p.events.push(e);
        broadcast({ type: 'agentEvent', agent: name, event: e });
      }
    }
  });
  p.stderr.on('data', (d) => process.stderr.write(`[${name}] ${d}`));
  kids.push(p);
  p.waitReady = () => ready;
  return p;
}
const send = (p, o) => p.stdin.write(JSON.stringify(o) + '\n');
async function ask(p, o, match, ms = 8000) {
  const start = p.events.length;
  send(p, o);
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    for (let i = start; i < p.events.length; i++) if (match(p.events[i])) return p.events[i];
    await sleep(20);
  }
  return { t: 'timeout' };
}

const relayC = async () => (relayConn || (relayConn = await nclient.connect(RELAY_WS)));

async function publishRoster(body, signerCount = 2) {
  const content = { version: ++version, ...body };
  const ev = nostr.build({
    pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']], content,
    created_at: Math.floor(Date.now() / 1000) + version,
  }, (id) => frost.sign(id, GROUP.shares.slice(0, signerCount), GROUP.groupPub));
  const res = await (await relayC()).publish(ev);
  if (!res.ok) version--;
  else { roster = content; pushState(); }
  return { ...res, event: ev };
}

async function publishRevocation(idx, peerIds) {
  const o = officers[idx];
  const ev = nostr.build({
    pubkey: o.pub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-revocation']], content: { revoke: peerIds },
  }, (id) => bip.sign(id, o.priv));
  const res = await (await relayC()).publish(ev);
  if (res.ok && roster) {
    for (const p of roster.peers) if (peerIds.includes(p.id)) p.revoked = true;
    pushState();
  }
  return res;
}

// ---------------------------------------------------------------- audit
const DB_LOG = path.join(ROOT, 'audit-finance-db.log');
let lastSize = 0;
function readNewAudit() {
  try {
    const st = fs.statSync(DB_LOG);
    if (st.size === lastSize) return;
    if (st.size < lastSize) { lastSize = 0; log.length = 0; }
    const txt = fs.readFileSync(DB_LOG, 'utf8');
    const lines = txt.trim().split('\n').filter(Boolean);
    const fresh = lines.slice(log.length);
    for (const l of fresh) { try { log.push(JSON.parse(l)); } catch {} }
    lastSize = st.size;
    const v = zp.verifyLog(DB_LOG);
    broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
  } catch {}
}

function pushState() {
  broadcast({
    type: 'state',
    groupPub: GROUP.groupPub,
    officers: officerPubs.map((p) => p.slice(0, 16)),
    threshold: 2,
    roster,
    agents: Object.fromEntries(Object.entries(agents).map(([k, v]) => [k, { id: v.id, udp: v.udpPort }])),
  });
}

// ---------------------------------------------------------------- boot
async function boot() {
  broadcast({ type: 'boot', message: 'starting control plane' });
  const relay = launch('nostr-relay.js', [String(RELAY_PORT)], 'relay');
  const rdv = launch('rendezvous.js', [String(RDV_PORT)], 'rendezvous');
  await relay.waitReady(); await rdv.waitReady();

  const mk = (name, servicePort) => launch('agent.js', [JSON.stringify({
    name, relay: RELAY_WS, rendezvous: RDV, groupPub: GROUP.groupPub, officerPubs,
    log: path.join(ROOT, `audit-${name}.log`), servicePort,
  })], name);

  const db = mk('finance-db', 5432);
  const alice = mk('alice-laptop', 0);
  const rogue = mk('rogue-node', 0);
  const [dbR, aliceR, rogueR] = await Promise.all([db.waitReady(), alice.waitReady(), rogue.waitReady()]);
  agents = {
    'finance-db': { proc: db, ...dbR },
    'alice-laptop': { proc: alice, ...aliceR },
    'rogue-node': { proc: rogue, ...rogueR },
  };

  await publishRoster({
    peers: [
      { id: dbR.id, idPub: dbR.idPub, staticPub: dbR.staticPub, name: 'finance-db' },
      { id: aliceR.id, idPub: aliceR.idPub, staticPub: aliceR.staticPub, name: 'alice-laptop' },
    ],
    policy: [{ from: aliceR.id, to: dbR.id, port: 5432, allow: true }],
  }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  await ask(alice, { cmd: 'refresh' }, (e) => e.t === 'roster');
  lastSize = 0; log.length = 0; readNewAudit();
  broadcast({ type: 'boot', message: 'network up' });
  pushState();
}

// ---------------------------------------------------------------- commands
async function handle(cmd) {
  const db = agents['finance-db'], alice = agents['alice-laptop'], rogue = agents['rogue-node'];
  const note = (m, level = 'info') => broadcast({ type: 'note', level, message: m });

  if (cmd.action === 'connect') {
    note('alice-laptop -> finance-db:5432 ...');
    const r = await ask(alice.proc, { cmd: 'connect', target: db.id, port: 5432, payload: 'SELECT 1' }, (e) => e.t === 'result');
    note(r.ok ? `ALLOWED - encrypted round trip ${r.rttMs?.toFixed(2)} ms, reply "${r.reply}"`
              : `DENIED - attacker sees "${r.reason}"`, r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'wrongPort') {
    note('alice-laptop -> finance-db:22 (no policy rule) ...');
    const r = await ask(alice.proc, { cmd: 'connect', target: db.id, port: 22 }, (e) => e.t === 'result');
    note(r.ok ? 'ALLOWED (unexpected)' : `DENIED - attacker sees "${r.reason}"`, r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'rogue') {
    note('rogue-node -> finance-db:5432 (not on the roster) ...');
    const r = await ask(rogue.proc, { cmd: 'connect', target: db.id, port: 5432 }, (e) => e.t === 'result');
    note(r.ok ? 'ALLOWED (unexpected)' : `DENIED - attacker sees "${r.reason}"`, r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'enrollOne') {
    note('publishing a roster signed by ONE officer share ...');
    const r = await publishRoster({
      peers: [...roster.peers, { id: rogue.id, idPub: rogue.idPub, staticPub: rogue.staticPub, name: 'rogue-node' }],
      policy: roster.policy,
    }, 1);
    note(r.ok ? 'ACCEPTED (unexpected)' : `REJECTED by the relay - "${r.message}"`, r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'enrollTwo') {
    note('two officers co-sign the same roster ...');
    const r = await publishRoster({
      peers: [...roster.peers, { id: rogue.id, idPub: rogue.idPub, staticPub: rogue.staticPub, name: 'rogue-node' }],
      policy: [...roster.policy, { from: rogue.id, to: agents['finance-db'].id, port: 5432, allow: true }],
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    note(r.ok ? 'ACCEPTED - two shares combined into ONE valid signature' : `REJECTED - ${r.message}`, r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'revoke') {
    note(`one officer revokes ${cmd.peer} ...`);
    const r = await publishRevocation(0, [cmd.peer]);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    note(r.ok ? 'revocation accepted - signed by a single officer, no quorum needed' : 'rejected', r.ok ? 'ok' : 'deny');
  }
  else if (cmd.action === 'lease') {
    note('issuing alice a 6-second lease ...');
    await publishRoster({
      peers: roster.peers.map((p) => (p.id === alice.id ? { ...p, leaseExpires: Date.now() + 6000 } : p)),
      policy: roster.policy,
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    note('lease issued - it expires on its own in 6 seconds', 'ok');
  }
  else if (cmd.action === 'restore') {
    note('restoring the baseline roster ...');
    await publishRoster({
      peers: [
        { id: db.id, idPub: db.idPub, staticPub: db.staticPub, name: 'finance-db' },
        { id: alice.id, idPub: alice.idPub, staticPub: alice.staticPub, name: 'alice-laptop' },
      ],
      policy: [{ from: alice.id, to: db.id, port: 5432, allow: true }],
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    note('baseline restored', 'ok');
  }
  else if (cmd.action === 'tamper') {
    note('editing one line of the audit log ...');
    try {
      const lines = fs.readFileSync(DB_LOG, 'utf8').trim().split('\n');
      const i = Math.max(1, lines.findIndex((l) => l.includes('"deny"')));
      const e = JSON.parse(lines[i]);
      e.event = { type: 'flow', note: 'nothing to see here' };
      lines[i] = JSON.stringify(e);
      fs.writeFileSync(DB_LOG, lines.join('\n') + '\n');
      const v = zp.verifyLog(DB_LOG);
      broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
      note(v.ok ? 'verifier missed it (unexpected)' : `verifier CAUGHT IT - ${v.reason} at line ${v.line}`, 'deny');
    } catch (err) { note('tamper failed: ' + err.message, 'deny'); }
  }
  else if (cmd.action === 'verify') {
    const v = zp.verifyLog(DB_LOG);
    broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
    note(v.ok ? `chain intact - ${v.entries} entries recomputed` : `chain BROKEN - ${v.reason}`, v.ok ? 'ok' : 'deny');
  }
}

// ---------------------------------------------------------------- http
const server = http.createServer((req, res) => {
  const p = req.url.split('?')[0];
  if (p === '/' || p === '/index.html') {
    const html = fs.readFileSync(path.join(DIR, 'index.html'));
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(html);
  }
  res.writeHead(404); res.end('not found');
});

ws.attach(server, (conn) => {
  clients.add(conn);
  conn.on('close', () => clients.delete(conn));
  conn.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    handle(m).catch((e) => broadcast({ type: 'note', level: 'deny', message: 'error: ' + e.message }));
  });
  pushState();
  const v = zp.verifyLog(DB_LOG);
  conn.send(JSON.stringify({ type: 'audit', entries: log.slice(-40), chain: v }));
});

server.listen(HTTP_PORT, '127.0.0.1', async () => {
  console.log('');
  console.log('  ZeroPort Operations Console');
  console.log(`  open  http://127.0.0.1:${HTTP_PORT}`);
  console.log('');
  console.log('  Starting the real network...');
  await boot();
  console.log('  Network up. Every panel below is live data.');
  setInterval(readNewAudit, 700);
});

const bye = () => { kids.forEach((k) => k.kill()); process.exit(0); };
process.on('SIGINT', bye);
process.on('SIGTERM', bye);
