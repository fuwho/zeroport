'use strict';
// ZeroPort live proof run.
// Spawns a real control plane, a real rendezvous plane and real node agents,
// then proves six properties against them. Nothing here is animated: every
// number printed is measured, every allow/deny is a real code path.
const { spawn } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const zp = require('./lib/zp');
const bip = require('./lib/bip340');
const frost = require('./lib/frost');
const nostr = require('./lib/nostr');
const nclient = require('./lib/nclient');
const anchorSvc = require('./lib/anchor');

const DIR = __dirname;
const RELAY_WS = 'ws://127.0.0.1:8801';
const RDV = 'http://127.0.0.1:8802';
const kids = [];

// ---------- modes ----------
//   (no flags)   run straight through - verification, or recording a backup
//   --slow       presentation pace: stop for a keypress before each proof
//   --no-pause   keep the slow beats but never wait for a key (unattended video)
// If stdin is not a terminal (piped, CI) the keypress is disabled automatically
// so the run can never hang.
const SLOW = process.argv.includes('--slow');
const WAIT_KEY = SLOW && !process.argv.includes('--no-pause') && Boolean(process.stdin.isTTY);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const beat = (ms) => (SLOW ? sleep(ms) : Promise.resolve());

function keypress(label) {
  return new Promise((res) => {
    process.stdout.write(`\n  ---- ${label}   [ENTER to continue, q to quit] `);
    const s = process.stdin;
    if (s.setRawMode) s.setRawMode(true);
    s.resume();
    s.once('data', (b) => {
      if (s.setRawMode) s.setRawMode(false);
      s.pause();
      process.stdout.write('\n');
      if (b[0] === 3 || b[0] === 113 || b[0] === 81) {   // Ctrl-C, q, Q
        console.log('\n  (stopped by presenter)\n');
        kids.forEach((k) => k.kill());
        process.exit(0);
      }
      res();
    });
  });
}

// ---------- presentation helpers ----------
const bar = (c = '=') => console.log(c.repeat(78));
async function proof(n, title, proves) {
  if (WAIT_KEY) await keypress(`ready for PROOF ${n} of 6`);
  else await beat(900);
  console.log('');
  bar();
  console.log(`  PROOF ${n}  ${title}`);
  bar();
  console.log(`  What this proves: ${proves}`);
  console.log('');
  await beat(700);
}
async function step(s) { console.log(`  > ${s}`); await beat(450); }
const out = (s) => console.log(`      ${s}`);
async function verdict(s) {
  await beat(800);                       // let the result land before the claim
  console.log('');
  console.log(`  VERDICT: ${s}`);
}

// ---------- child process plumbing ----------
function launch(file, args, name) {
  const p = spawn(process.execPath, [path.join(DIR, file), ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  p.name = name; p.events = []; p.ready = null;
  let buf = '';
  const readyP = new Promise((res) => (p._res = res));
  p.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line.startsWith('#READY ')) { p.ready = JSON.parse(line.slice(7)); p._res(p.ready); }
      else if (line.startsWith('#EVT ')) p.events.push(JSON.parse(line.slice(5)));
    }
  });
  p.stderr.on('data', (d) => process.stderr.write(`[${name}] ${d}`));
  kids.push(p);
  p.waitReady = () => readyP;
  return p;
}
function send(p, obj) { p.stdin.write(JSON.stringify(obj) + '\n'); }
async function ask(p, obj, match, ms = 6000) {
  const start = p.events.length;
  send(p, obj);
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    for (let i = start; i < p.events.length; i++) if (match(p.events[i])) return p.events[i];
    await sleep(15);
  }
  return { t: 'timeout' };
}

// ---------- the SOC officers (the quorum) ----------
// The attacker is told nothing. The defender's log knows exactly why.
const DB_LOG = path.join(DIR, 'audit-finance-db.log');
function lastDeny() {
  try {
    const lines = fs.readFileSync(DB_LOG, 'utf8').trim().split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const e = JSON.parse(lines[i]);
      if (e.event.type === 'deny') return e.event.reason;
    }
  } catch {}
  return 'unknown';
}
const denied = (r) => (r.ok ? 'ALLOWED' : `DENIED (attacker sees: "${r.reason}")`);

// The SOC quorum is a real FROST 2-of-3 group: the three officers hold shares
// of ONE group key. Each officer also has an individual key, used only to
// revoke. Granting access needs the group; taking it away needs one officer.
const GROUP = frost.deal(2, 3);
const officers = [zp.newIdentity(), zp.newIdentity(), zp.newIdentity()];
const officerPubs = officers.map((o) => o.pub);
const THRESHOLD = 2;

let version = 0;
let relayConn = null;
const relayC = async () => (relayConn || (relayConn = await nclient.connect(RELAY_WS)));

// The roster is a real NIP-01 event signed by the threshold group key.
async function publishRoster(bodyFields, signerCount) {
  const body = { version: ++version, ...bodyFields };
  const ev = nostr.build({
    pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']], content: body,
    created_at: Math.floor(Date.now() / 1000) + version,
  }, (id) => frost.sign(id, GROUP.shares.slice(0, signerCount), GROUP.groupPub));
  const res = await (await relayC()).publish(ev);
  if (!res.ok) version--;
  return { ok: res.ok, message: res.message, version: body.version, signers: signerCount };
}

// An emergency revocation is signed by ONE officer's own key.
async function publishRevocation(officerIdx, peerIds) {
  const o = officers[officerIdx];
  const ev = nostr.build({
    pubkey: o.pub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-revocation']], content: { revoke: peerIds },
  }, (id) => bip.sign(id, o.priv));
  return (await relayC()).publish(ev);
}

// ---------- a real TCP connect scan ----------
function tcpProbe(host, port, ms = 300) {
  return new Promise((res) => {
    const s = new net.Socket();
    const done = (v) => { s.destroy(); res(v); };
    s.setTimeout(ms);
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
    s.connect(port, host);
  });
}
async function scan(host, ports) {
  const open = [];
  for (let i = 0; i < ports.length; i += 60) {
    const chunk = ports.slice(i, i + 60);
    const r = await Promise.all(chunk.map((p) => tcpProbe(host, p)));
    r.forEach((o, k) => { if (o) open.push(chunk[k]); });
  }
  return open;
}

// ---------- main ----------
(async () => {
  console.log('');
  bar('#');
  console.log('  ZEROPORT - LIVE PROOF RUN');
  console.log('  Identity : real BIP-340 Schnorr / secp256k1  (validated against the');
  console.log('             official spec test vectors - the exact scheme Nostr uses)');
  console.log('  Tunnel   : real Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s');
  console.log('             (WireGuard\'s own handshake - forward secrecy + replay window)');
  console.log('  Transport: real UDP sockets, separate OS processes, hash-chained audit');
  bar('#');

  // ----- bring the network up -----
  console.log('\n  Bringing the network up...');
  const relay = launch('nostr-relay.js', ['8801'], 'relay');
  const rdv = launch('rendezvous.js', ['8802'], 'rendezvous');
  await relay.waitReady(); await rdv.waitReady();
  out('control plane   (Plane 1, REAL Nostr relay, NIP-01 over WebSocket) : ws://127.0.0.1:8801');
  out(`FROST 2-of-3 group key: ${GROUP.groupPub.slice(0, 32)}...`);
  out('rendezvous      (Plane 2, stands in for a Tor onion service)        : 127.0.0.1:8802');

  const mk = (name, servicePort) => launch('agent.js', [JSON.stringify({
    name, relay: RELAY_WS, rendezvous: RDV, groupPub: GROUP.groupPub, officerPubs,
    log: path.join(DIR, `audit-${name}.log`), servicePort,
  })], name);

  const db = mk('finance-db', 5432);
  const alice = mk('alice-laptop', 0);
  const rogue = mk('rogue-node', 0);
  const dbR = await db.waitReady(), aliceR = await alice.waitReady(), rogueR = await rogue.waitReady();
  out(`agent finance-db   id=${dbR.id}  udp=${dbR.udpPort}  tcp listeners=0`);
  out(`agent alice-laptop id=${aliceR.id}  udp=${aliceR.udpPort}  tcp listeners=0`);
  out(`agent rogue-node   id=${rogueR.id}  (deliberately NOT enrolled)`);

  // enrol the two legitimate nodes with a real 2-of-3 quorum
  // The quorum-signed roster is what binds each Schnorr identity to the X25519
  // static key that the Noise handshake authenticates.
  const peers = [
    { id: dbR.id, idPub: dbR.idPub, staticPub: dbR.staticPub, name: 'finance-db' },
    { id: aliceR.id, idPub: aliceR.idPub, staticPub: aliceR.staticPub, name: 'alice-laptop' },
  ];
  const policy = [{ from: aliceR.id, to: dbR.id, port: 5432, allow: true }];
  const pub = await publishRoster({ peers, policy }, 2);
  out(`roster v${pub.version} published as a signed Nostr event - relay accepted: ${pub.ok}`);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  await ask(alice, { cmd: 'refresh' }, (e) => e.t === 'roster');

  // ================= PROOF 1 =================
  await proof(1, 'NOTHING TO SCAN - YET THE CONNECTION WORKS',
    'the protected service exposes no listening TCP port, so there is no door to knock on.');

  await step('Running a real TCP connect scan against the service node...');
  const ports = [22, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, dbR.udpPort, aliceR.udpPort];
  for (let p = 8790; p <= 8815; p++) ports.push(p);
  const open = await scan('127.0.0.1', [...new Set(ports)]);
  out(`scanned ${new Set(ports).size} TCP ports on 127.0.0.1`);
  out(`open TCP ports found: ${open.length ? open.join(', ') : 'NONE'}`);
  out(`finance-db service port 5432 : ${open.includes(5432) ? 'OPEN' : 'CLOSED - nothing is listening'}`);
  out(`finance-db agent UDP ${dbR.udpPort} : ${open.includes(dbR.udpPort) ? 'OPEN on TCP' : 'no TCP listener'}`);
  if (open.length) out(`(ports ${open.join(', ')} are the relay/rendezvous infrastructure, not the protected node)`);

  await step('Sending an unauthenticated UDP packet straight at the agent...');
  const raw = dgram.createSocket('udp4');
  const gotReply = await new Promise((res) => {
    const t = setTimeout(() => res(false), 900);
    raw.on('message', () => { clearTimeout(t); res(true); });
    raw.send(Buffer.from('GET / HTTP/1.1\r\n\r\n'), dbR.udpPort, '127.0.0.1');
  });
  raw.close();
  out(`reply to unauthenticated packet: ${gotReply ? 'GOT ONE' : 'NONE - silently dropped'}`);

  await step('Now connecting as the enrolled, policy-authorized peer...');
  const c1 = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432, payload: 'SELECT 1' }, (e) => e.t === 'result');
  out(`handshake: ${c1.ok ? 'ESTABLISHED' : 'FAILED - ' + c1.reason}`);
  if (c1.ok) out(`encrypted round trip returned: "${c1.reply}"`);
  await verdict(c1.ok && !open.includes(5432) && !gotReply
    ? 'A scan finds no way in, an unauthenticated packet is dropped, and yet an authorized peer connects and exchanges encrypted data.'
    : 'INCONCLUSIVE - see output above.');

  // ================= PROOF 2 =================
  await proof(2, 'THE PATH UPGRADE - RENDEZVOUS FIRST, THEN DIRECT',
    'the rendezvous is used only to introduce the peers; the data then flows directly, with fewer hops.');

  await step('Sending the SAME sealed packet over each route, five times each...');
  const med = (a) => a.sort((x, y) => x - y)[Math.floor(a.length / 2)];
  const rel = [], dir = [];
  for (let i = 0; i < 5; i++) {
    const r = await ask(alice, { cmd: 'probe', target: dbR.id, route: 'relayed', payload: 'SELECT 1' }, (e) => e.t === 'result');
    if (r.ok) rel.push(r.rttMs);
    const d = await ask(alice, { cmd: 'probe', target: dbR.id, route: 'direct', payload: 'SELECT 1' }, (e) => e.t === 'result');
    if (d.ok) dir.push(d.rttMs);
  }
  out(`via rendezvous (2 hops): median ${med(rel).toFixed(3)} ms`);
  out(`direct tunnel  (1 hop) : median ${med(dir).toFixed(3)} ms`);
  out(`the rendezvous is now out of the path entirely`);
  console.log('');
  out('NOTE - honest scale: every hop here is on loopback, so these millisecond');
  out('figures reflect process and HTTP framing overhead, not real network');
  out('distance. Over the internet the rendezvous hop would be a Tor circuit');
  out('(~300-400 ms) and the direct tunnel a single WAN hop (~5-15 ms), so the');
  out('real-world gap is far wider. What is proven here is the architecture:');
  out('the same sealed packet reaches the peer over two routes, and the fast');
  out('one carries no third party at all.');
  await verdict(med(dir) < med(rel)
    ? `Direct is measurably faster (${(med(rel) / med(dir)).toFixed(1)}x here) and needs no third party.`
    : 'Both routes work; timing on loopback is too close to separate.');

  // ================= PROOF 3 =================
  await proof(3, 'ONE ADMINISTRATOR CANNOT ENROL A ROGUE NODE',
    'changing the roster needs a real 2-of-3 cryptographic quorum, not a trusted process.');

  await step('A single officer signs a roster that adds the rogue node...');
  const rogueBody = {
    peers: [...peers, { id: rogueR.id, idPub: rogueR.idPub, staticPub: rogueR.staticPub, name: 'rogue-node' }],
    policy: [...policy, { from: rogueR.id, to: dbR.id, port: 5432, allow: true }],
  };
  const one = await publishRoster(rogueBody, 1);
  out(`relay responded: ${one.ok ? 'ACCEPTED' : 'REJECTED'} - "${one.message}"`);
  out('the signature a lone officer produces is not merely refused by policy -');
  out('it is not a valid signature for the group key at all, so it cannot exist.');

  await step('A second officer co-signs the same roster...');
  const two = await publishRoster(rogueBody, 2);
  out(`relay responded: ${two.ok ? 'ACCEPTED' : 'REJECTED'} - two shares combined into ONE valid signature`);

  await step('Rolling back to the safe roster (2-of-3)...');
  await publishRoster({ peers, policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  await verdict(!one.ok && two.ok
    ? 'A lone administrator is refused by cryptography. Two officers together succeed. No single person can betray the network.'
    : 'INCONCLUSIVE - see output above.');

  // ================= PROOF 4 =================
  await proof(4, 'ACCESS EXPIRES BY ITSELF',
    'authorization is a short lease; if it is not renewed the node loses access with nobody pressing revoke.');

  await step('Issuing alice a 3-second lease...');
  const shortLease = Date.now() + 3000;
  await publishRoster({ peers: peers.map((p) => (p.id === aliceR.id ? { ...p, leaseExpires: shortLease } : p)), policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  const inLease = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  out(`connection while the lease is valid: ${inLease.ok ? 'ALLOWED' : 'DENIED - ' + inLease.reason}`);

  await step('Waiting 4 seconds. Nobody touches the console, nothing is revoked...');
  await sleep(4000);
  const expired = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  out(`connection after the lease elapsed: ${denied(expired)}`);
  out(`finance-db's own audit log records why: "${lastDeny()}"`);
  await verdict(inLease.ok && !expired.ok
    ? 'Access ended on its own. A lost or offline device stops being trusted without any human action - fail-closed.'
    : 'INCONCLUSIVE - see output above.');

  // ================= PROOF 5 =================
  await proof(5, 'UNENROLLED IS REFUSED, AND REVOCATION IS IMMEDIATE',
    'the agent is default-deny: absence from the signed roster, or presence on the revoked list, both stop traffic.');

  await step('Restoring alice to a normal lease and having the rogue node attempt access...');
  await publishRoster({ peers, policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  const rogueTry = await ask(rogue, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  out(`rogue-node -> finance-db:5432 : ${denied(rogueTry)}`);
  out(`defender's log: "${lastDeny()}"`);

  await step('Checking alice can still reach the database, then testing a port she is NOT allowed...');
  const ok5 = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  out(`alice -> finance-db:5432 (permitted by policy) : ${ok5.ok ? 'ALLOWED' : 'DENIED'}`);
  const wrongPort = await ask(alice, { cmd: 'connect', target: dbR.id, port: 22 }, (e) => e.t === 'result');
  out(`alice -> finance-db:22   (no policy rule)      : ${denied(wrongPort)}`);
  out(`defender's log: "${lastDeny()}"`);

  await step('Revoking alice - emergency revocation needs only ONE officer signature...');
  const rev = await publishRevocation(0, [aliceR.id]);
  out(`relay accepted the revocation event: ${rev.ok}`);
  out('signed by ONE officer using their own individual key - no quorum needed to remove access');
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  const afterRevoke = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  out(`alice -> finance-db:5432 after revocation : ${denied(afterRevoke)}`);
  out(`defender's log: "${lastDeny()}"`);
  await verdict(!rogueTry.ok && ok5.ok && !wrongPort.ok && !afterRevoke.ok
    ? 'Unenrolled refused, wrong port refused, revoked node dead. Microsegmentation and revocation both hold.'
    : 'INCONCLUSIVE - see output above.');

  // ================= PROOF 6 =================
  await proof(6, 'THE AUDIT LOG CANNOT BE QUIETLY REWRITTEN',
    'entries are hash-chained and the head is publicly anchored, so an edit AND a file swap are both detectable.');

  const anchor = await ask(db, { cmd: 'anchor' }, (e) => e.t === 'anchor');
  const logPath = path.join(DIR, 'audit-finance-db.log');
  out(`the service node published its chain head as a public anchor:`);
  out(`  ${anchor.head}`);

  await step('Verifying the untouched log...');
  const v1 = zp.verifyLog(logPath, anchor.head);
  out(`result: ${v1.ok ? `INTACT - ${v1.entries} entries, head matches anchor` : 'BROKEN - ' + v1.reason}`);

  await step('Submitting the chain head to independent public timestamp servers...');
  const ext = await anchorSvc.submit(Buffer.from(anchor.head, 'hex'));
  if (ext.ok) {
    anchorSvc.save(logPath, Buffer.from(anchor.head, 'hex'), ext);
    out(`ANCHORED by a third party: ${ext.calendar}`);
    out(`proof received: ${ext.proof.length} bytes, saved as audit-finance-db.log.ots`);
    out('this digest is now committed into the Bitcoin blockchain by OpenTimestamps;');
    out('anyone can check it later with:  ots verify audit-finance-db.log.ots');
  } else {
    out('external anchoring unavailable right now (offline or blocked):');
    ext.attempts.forEach((a) => out(`  ${a.url} -> ${a.status || a.error}`));
    out('the local chain check above still holds; only the third-party witness is missing.');
  }

  await step('An attacker edits one line to erase a denial...');
  const original = fs.readFileSync(logPath, 'utf8');
  const lines = original.trim().split('\n');
  const target = lines.findIndex((l) => l.includes('"deny"'));
  const idx = target >= 0 ? target : 1;
  const e = JSON.parse(lines[idx]);
  e.event = { type: 'flow', note: 'nothing to see here' };
  lines[idx] = JSON.stringify(e);
  fs.writeFileSync(logPath, lines.join('\n') + '\n');
  const v2 = zp.verifyLog(logPath, anchor.head);
  out(`verifier: ${v2.ok ? 'MISSED IT' : `CAUGHT IT - ${v2.reason} at line ${v2.line}`}`);

  await step('The attacker gives up and replaces the whole file with a clean one...');
  const fresh = new zp.AuditLog(logPath);
  fresh.append({ type: 'agent_start', note: 'fabricated history' });
  fresh.append({ type: 'flow', note: 'all normal here' });
  const v3 = zp.verifyLog(logPath, anchor.head);
  out(`internally consistent? ${zp.verifyLog(logPath).ok ? 'yes - the chain itself is valid' : 'no'}`);
  out(`verifier vs public anchor: ${v3.ok ? 'MISSED IT' : `CAUGHT IT - ${v3.reason}`}`);
  fs.writeFileSync(logPath, original);
  await verdict(v1.ok && !v2.ok && !v3.ok
    ? 'One edited line breaks the chain. A whole replacement file fails against the published anchor. Tampering is always evident.'
    : 'INCONCLUSIVE - see output above.');

  // ----- attributed log -----
  console.log('');
  bar();
  console.log('  WHAT THE SECURITY TEAM ACTUALLY SEES');
  bar();
  const flows = fs.readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    .filter((e) => ['flow', 'deny', 'tunnel_established'].includes(e.event.type)).slice(-6);
  for (const f of flows) {
    const ev = f.event;
    if (ev.type === 'flow') out(`#${f.seq}  ALLOW  ${ev.peer} -> ${ev.service}  ${ev.bytes}B  via ${ev.path}`);
    else if (ev.type === 'deny') out(`#${f.seq}  DENY   ${ev.peer || 'unknown'}  reason: ${ev.reason}`);
    else out(`#${f.seq}  TUNNEL ${ev.peer} -> :${ev.port}  cipher ${ev.cipher}`);
  }
  console.log('');
  out('Every line is bound to a cryptographic identity and to the policy that allowed it.');

  bar('#');
  console.log('  RUN COMPLETE');
  bar('#');
  console.log('');
  kids.forEach((k) => k.kill());
  process.exit(0);
})().catch((e) => {
  console.error('DEMO ERROR:', e);
  kids.forEach((k) => k.kill());
  process.exit(1);
});
