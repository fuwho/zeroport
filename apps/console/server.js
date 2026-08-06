'use strict';
// ZeroPort Operations Console.
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
const net = require('net');
const dgram = require('dgram');
const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');
const DIR = __dirname;
const REPO = path.join(DIR, '..', '..');
const NODES = path.join(REPO, 'src', 'nodes');
// Generated output goes to .runtime/, not next to the source.
const ROOT = path.join(REPO, '.runtime');
fs.mkdirSync(ROOT, { recursive: true });
const zp = require(path.join(REPO, 'src', 'domain', 'zeroport'));
const bip = require(path.join(REPO, 'src', 'crypto', 'bip340'));
const frost = require(path.join(REPO, 'src', 'crypto', 'frost'));
const nostr = require(path.join(REPO, 'src', 'protocol', 'nostr-event'));
const nclient = require(path.join(REPO, 'src', 'transport', 'relay-client'));
const ws = require(path.join(REPO, 'src', 'transport', 'websocket'));

function lanIP() {
  for (const a of Object.values(os.networkInterfaces()))
    for (const i of a || []) if (i.family === 'IPv4' && !i.internal) return i.address;
  return '127.0.0.1';
}
const NET_HOST = process.argv.includes('--local') ? '127.0.0.1' : lanIP();
const HTTP_PORT = 8080;
const RELAY_PORT = 8811;
const RDV_PORT = 8812;
const RELAY_WS = `ws://${NET_HOST}:${RELAY_PORT}`;
const RDV = `http://${NET_HOST}:${RDV_PORT}`;

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
let anchoredHead = null;        // the head we published to an outside witness
const log = [];                    // recent audit entries, newest last

function launch(file, args, name) {
  const p = spawn(process.execPath, [path.join(NODES, file), ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
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
    tags: [['d', 'zeroport-revocation']], content: { revoke: peerIds, rosterVersion: version },
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
    netHost: NET_HOST,
    officers: officerPubs.map((p) => p.slice(0, 16)),
    threshold: 2,
    roster,
    agents: Object.fromEntries(Object.entries(agents).map(([k, v]) => [k, { id: v.id, udp: v.udpPort }])),
  });
}

// ---------------------------------------------------------------- boot
async function boot() {
  broadcast({ type: 'boot', message: 'starting control plane' });
  const relay = launch('directory.js', [String(RELAY_PORT), NET_HOST], 'relay');
  const rdv = launch('rendezvous.js', [String(RDV_PORT), NET_HOST], 'rendezvous');
  await relay.waitReady(); await rdv.waitReady();

  const mk = (name, servicePort) => launch('agent.js', [JSON.stringify({
    name, host: NET_HOST, relay: RELAY_WS, rendezvous: RDV, groupPub: GROUP.groupPub, officerPubs,
    log: path.join(ROOT, `audit-${name}.log`), servicePort,
  })], name);

  const db = mk('finance-db', 5432);
  const alice = mk('officer-laptop', 0);
  const rogue = mk('unknown-device', 0);
  const [dbR, aliceR, rogueR] = await Promise.all([db.waitReady(), alice.waitReady(), rogue.waitReady()]);
  agents = {
    'finance-db': { proc: db, ...dbR },
    'officer-laptop': { proc: alice, ...aliceR },
    'unknown-device': { proc: rogue, ...rogueR },
  };

  await publishRoster({
    peers: [
      { id: dbR.id, idPub: dbR.idPub, staticPub: dbR.staticPub, name: 'finance-db' },
      { id: aliceR.id, idPub: aliceR.idPub, staticPub: aliceR.staticPub, name: 'officer-laptop' },
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
function logLines() {
  try { return fs.readFileSync(DB_LOG, 'utf8').trim().split('\n').filter(Boolean); } catch { return []; }
}
// The reason the DEFENDER wrote down, not the excuse the caller was given.
// Waits briefly for the entry to land so we never report a stale refusal.
async function denyReasonSince(mark) {
  for (let i = 0; i < 20; i++) {
    const lines = logLines();
    for (let j = lines.length - 1; j >= mark; j--) {
      try { const e = JSON.parse(lines[j]); if (e.event.type === 'deny') return e.event.reason; } catch {}
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  return '';
}

async function handle(cmd) {
  const db = agents['finance-db'], alice = agents['officer-laptop'], rogue = agents['unknown-device'];
  const note = (m, level = 'info') => broadcast({ type: 'note', level, message: m });

  const done = (o) => broadcast({ type: 'result', action: cmd.action, quiet: cmd.quiet || undefined, ...o });

  if (cmd.action === 'scan') {
    const probe = (port) => new Promise((r) => {
      const s = new net.Socket(); const fin = (v) => { s.destroy(); r(v); };
      s.setTimeout(300);
      s.once('connect', () => fin(true)); s.once('timeout', () => fin(false)); s.once('error', () => fin(false));
      s.connect(port, NET_HOST);
    });
    const ports = [22, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, agents['finance-db'].udpPort];
    for (let p = 8790; p <= 8815; p++) ports.push(p);
    const uniq = [...new Set(ports)];
    const open = [];
    for (const p of uniq) if (await probe(p)) open.push(p);
    const infra = { [RELAY_PORT]: 'the directory', [RDV_PORT]: 'the rendezvous', 8080: 'this console' };
    return done({
      host: NET_HOST, scanned: uniq.length,
      open: open.filter((p) => infra[p]).map((p) => `${p} (${infra[p]})`),
      other: open.filter((p) => !infra[p] && p !== 5432 && p !== agents['finance-db'].udpPort),
      servicePortOpen: open.includes(5432),
      agentPortOpen: open.includes(agents['finance-db'].udpPort),
      agentPort: agents['finance-db'].udpPort,
    });
  }

  if (cmd.action === 'rawPacket') {
    const sock = dgram.createSocket('udp4');
    const replied = await new Promise((r) => {
      const t = setTimeout(() => r(false), 900);
      sock.on('message', () => { clearTimeout(t); r(true); });
      sock.send(Buffer.from('GET / HTTP/1.1\r\n\r\n'), agents['finance-db'].udpPort, NET_HOST);
    });
    sock.close();
    return done({ replied });
  }

  if (cmd.action === 'pathCompare') {
    const db = agents['finance-db'], alice = agents['officer-laptop'] || agents['officer-laptop'];
    const med = (a) => a.sort((x, y) => x - y)[Math.floor(a.length / 2)] || 0;
    const rel = [], dir = [];
    for (let i = 0; i < 4; i++) {
      const r = await ask(alice.proc, { cmd: 'probe', target: db.id, route: 'relayed' }, (e) => e.t === 'result');
      if (r.ok) rel.push(r.rttMs);
      const d = await ask(alice.proc, { cmd: 'probe', target: db.id, route: 'direct' }, (e) => e.t === 'result');
      if (d.ok) dir.push(d.rttMs);
    }
    return done({ relayed: med(rel), direct: med(dir), samples: rel.length });
  }

  if (cmd.action === 'anchor') {
    const a = await ask(agents['finance-db'].proc, { cmd: 'anchor' }, (e) => e.t === 'anchor');
    const ext = await require(path.join(REPO, 'src', 'transport', 'opentimestamps')).submit(Buffer.from(a.head, 'hex'));
    anchoredHead = a.head;
    return done({ head: a.head, ok: ext.ok, calendar: ext.ok ? ext.calendar : null });
  }

  // The harder forgery: don't edit a line, rebuild the whole file so it is
  // internally perfect - then rehash it and compare against the head we
  // published to a witness we do not control.
  if (cmd.action === 'forge') {
    if (!anchoredHead) return done({ ok: false, needAnchor: true });
    const original = fs.readFileSync(DB_LOG, 'utf8');
    if (!fs.existsSync(DB_LOG + '.orig')) fs.writeFileSync(DB_LOG + '.orig', original);
    const all = original.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const kept = all.filter((e) => e.event.type !== 'deny');
    // rebuild the chain from GENESIS so every link is genuinely correct
    let prev = 'GENESIS', seq = 0, out = '';
    for (const e of kept) {
      const rec = { seq: ++seq, ts: e.ts, event: e.event, prev };
      const hash = crypto.createHash('sha256').update(zp.canon(rec)).digest('hex');
      prev = hash;
      out += JSON.stringify({ ...rec, hash }) + '\n';
    }
    fs.writeFileSync(DB_LOG, out);
    const v = zp.verifyLog(DB_LOG);                       // internal check only
    const vAnchored = zp.verifyLog(DB_LOG, anchoredHead); // check against the witness
    lastSize = 0; log.length = 0; readNewAudit();
    broadcast({ type: 'audit', entries: log.slice(-40), chain: vAnchored });
    return done({
      internallyOk: v.ok, removed: all.length - kept.length,
      head: v.head, anchored: anchoredHead, matches: vAnchored.ok,
    });
  }

  if (cmd.action === 'connect') {
    note('officer-laptop -> finance-db:5432 ...');
    const mark = logLines().length;
    const r = await ask(alice.proc, { cmd: 'connect', target: db.id, port: 5432, payload: 'SELECT 1' }, (e) => e.t === 'result');
    done({ ok: r.ok, rttMs: r.rttMs, reply: r.reply, reason: r.reason, logReason: r.ok ? null : await denyReasonSince(mark) });
  }
  else if (cmd.action === 'wrongPort') {
    note('officer-laptop -> finance-db:22 (no policy rule) ...');
    const mark = logLines().length;
    const r = await ask(alice.proc, { cmd: 'connect', target: db.id, port: 22 }, (e) => e.t === 'result');
    done({ ok: r.ok, reason: await denyReasonSince(mark) });
  }
  else if (cmd.action === 'rogue') {
    note('unknown-device -> finance-db:5432 (not on the roster) ...');
    const mark = logLines().length;
    const r = await ask(rogue.proc, { cmd: 'connect', target: db.id, port: 5432 }, (e) => e.t === 'result');
    done({ ok: r.ok, reason: await denyReasonSince(mark) });
  }
  else if (cmd.action === 'enrollOne') {
    note('publishing a roster signed by ONE officer share ...');
    const r = await publishRoster({
      peers: [...roster.peers, { id: rogue.id, idPub: rogue.idPub, staticPub: rogue.staticPub, name: 'unknown-device' }],
      policy: roster.policy,
    }, 1);
    done({ ok: r.ok, message: r.message });
  }
  else if (cmd.action === 'enrollTwo') {
    note('two officers co-sign the same roster ...');
    const r = await publishRoster({
      peers: [...roster.peers, { id: rogue.id, idPub: rogue.idPub, staticPub: rogue.staticPub, name: 'unknown-device' }],
      policy: [...roster.policy, { from: rogue.id, to: agents['finance-db'].id, port: 5432, allow: true }],
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    done({ ok: r.ok, message: r.message });
  }
  else if (cmd.action === 'revoke') {
    const target = cmd.peer || (agents['officer-laptop'] && agents['officer-laptop'].id);
    const r = await publishRevocation(0, [target]);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    done({ ok: r.ok });
  }
  else if (cmd.action === 'lease') {
    note('issuing alice a 6-second lease ...');
    await publishRoster({
      peers: roster.peers.map((p) => (p.id === alice.id ? { ...p, leaseExpires: Date.now() + 6000 } : p)),
      policy: roster.policy,
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    done({ ok: true });
  }
  else if (cmd.action === 'restore') {
    note('restoring the baseline roster ...');
    await publishRoster({
      peers: [
        { id: db.id, idPub: db.idPub, staticPub: db.staticPub, name: 'finance-db' },
        { id: alice.id, idPub: alice.idPub, staticPub: alice.staticPub, name: 'officer-laptop' },
      ],
      policy: [{ from: alice.id, to: db.id, port: 5432, allow: true }],
    }, 2);
    await ask(db.proc, { cmd: 'refresh' }, (e) => e.t === 'roster');
    done({ ok: true });
  }
  else if (cmd.action === 'tamper') {
    note('editing one line of the audit log ...');
    try {
      const original = fs.readFileSync(DB_LOG, 'utf8');
      fs.writeFileSync(DB_LOG + '.orig', original);   // so the console can be put back
      const lines = original.trim().split('\n');
      const i = Math.max(1, lines.findIndex((l) => l.includes('"deny"')));
      const e = JSON.parse(lines[i]);
      e.event = { type: 'flow', note: 'nothing to see here' };
      lines[i] = JSON.stringify(e);
      fs.writeFileSync(DB_LOG, lines.join('\n') + '\n');
      const v = zp.verifyLog(DB_LOG);
      broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
      done({ ok: v.ok, reason: v.reason, line: v.line });
    } catch (err) { note('tamper failed: ' + err.message, 'deny'); }
  }
  else if (cmd.action === 'verify') {
    const v = zp.verifyLog(DB_LOG, anchoredHead);
    broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
    done({ ok: v.ok, entries: v.entries, reason: v.reason });
  }
  else if (cmd.action === 'untamper') {
    if (fs.existsSync(DB_LOG + '.orig')) {
      fs.writeFileSync(DB_LOG, fs.readFileSync(DB_LOG + '.orig'));
      fs.unlinkSync(DB_LOG + '.orig');
      lastSize = 0; log.length = 0; readNewAudit();
    }
    const v = zp.verifyLog(DB_LOG);
    broadcast({ type: 'audit', entries: log.slice(-40), chain: v });
    done({ ok: v.ok, entries: v.entries });
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
