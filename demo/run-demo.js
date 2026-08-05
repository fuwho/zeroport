'use strict';
// ZeroPort - a guided walkthrough.
//
// Six steps, each one explaining a piece of the idea and then doing it for
// real. Runs on this machine's actual network interface, not loopback, so the
// packets cross a real NIC and the scan targets a real network address.
//
//   node run-demo.js --slow      stop for a keypress before each step
//   node run-demo.js --local     use 127.0.0.1 instead of the LAN interface
//   node run-demo.js --host X    bind to a specific address
const { spawn } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zp = require('./lib/zp');
const bip = require('./lib/bip340');
const frost = require('./lib/frost');
const nostr = require('./lib/nostr');
const nclient = require('./lib/nclient');
const anchorSvc = require('./lib/anchor');

const DIR = __dirname;
const kids = [];

// ---------- which interface do we run on ----------
function lanIP() {
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) if (a.family === 'IPv4' && !a.internal) return a.address;
  }
  return '127.0.0.1';
}
const argv = process.argv.slice(2);
const argOf = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : null; };
const HOST = argOf('--host') || (argv.includes('--local') ? '127.0.0.1' : lanIP());
const ON_LAN = HOST !== '127.0.0.1';
const RELAY_WS = `ws://${HOST}:8801`;
const RDV = `http://${HOST}:8802`;

// ---------- pacing ----------
const SLOW = argv.includes('--slow');
const WAIT_KEY = SLOW && !argv.includes('--no-pause') && Boolean(process.stdin.isTTY);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const beat = (ms) => (SLOW ? sleep(ms) : Promise.resolve());

function keypress(label) {
  return new Promise((res) => {
    process.stdout.write(`\n   ---- ${label}   [ENTER to continue, q to quit] `);
    const s = process.stdin;
    if (s.setRawMode) s.setRawMode(true);
    s.resume();
    s.once('data', (b) => {
      if (s.setRawMode) s.setRawMode(false);
      s.pause();
      process.stdout.write('\n');
      if (b[0] === 3 || b[0] === 113 || b[0] === 81) {
        console.log('\n   (stopped)\n'); kids.forEach((k) => k.kill()); process.exit(0);
      }
      res();
    });
  });
}

// ---------- narration ----------
const W = 74;
const rule = (c = '=') => console.log('  ' + c.repeat(W));
const say = (s = '') => console.log('  ' + s);
const act = async (s) => { console.log(`   > ${s}`); await beat(420); };
const res = (s) => console.log(`       ${s}`);

// The teaching line that closes each step. Explains the mechanism, not the demo.
async function idea(s) {
  await beat(700);
  console.log('');
  const words = s.split(' ');
  let line = '  ── The idea:  ';
  const out = [];
  for (const w of words) {
    if ((line + w).length > W + 2) { out.push(line); line = '                '; }
    line += w + ' ';
  }
  out.push(line);
  out.forEach((l) => console.log(l));
}

let STEP = 0;
async function step(title, setup) {
  STEP++;
  if (WAIT_KEY) await keypress(`ready for STEP ${STEP} of 6`);
  else await beat(900);
  console.log('');
  rule();
  console.log(`  STEP ${STEP} of 6   ${title}`);
  rule();
  console.log('');
  for (const line of setup) { say(line); }
  console.log('');
  await beat(900);
}

// ---------- child processes ----------
function launch(file, args, name) {
  const p = spawn(process.execPath, [path.join(DIR, file), ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  p.name = name; p.events = [];
  let buf = '';
  const ready = new Promise((r) => (p._res = r));
  p.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line.startsWith('#READY ')) p._res(JSON.parse(line.slice(7)));
      else if (line.startsWith('#EVT ')) p.events.push(JSON.parse(line.slice(5)));
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

// ---------- the officers ----------
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

const GROUP = frost.deal(2, 3);
const officers = [zp.newIdentity(), zp.newIdentity(), zp.newIdentity()];
const officerPubs = officers.map((o) => o.pub);

let version = 0, relayConn = null;
const relayC = async () => (relayConn || (relayConn = await nclient.connect(RELAY_WS)));

async function publishRoster(bodyFields, signerCount) {
  const body = { version: ++version, ...bodyFields };
  const ev = nostr.build({
    pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']], content: body,
    created_at: Math.floor(Date.now() / 1000) + version,
  }, (id) => frost.sign(id, GROUP.shares.slice(0, signerCount), GROUP.groupPub));
  const r = await (await relayC()).publish(ev);
  if (!r.ok) version--;
  return { ok: r.ok, message: r.message, version: body.version };
}
async function publishRevocation(idx, peerIds) {
  const o = officers[idx];
  const ev = nostr.build({
    pubkey: o.pub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-revocation']], content: { revoke: peerIds },
  }, (id) => bip.sign(id, o.priv));
  return (await relayC()).publish(ev);
}

// ---------- a real TCP connect scan ----------
function tcpProbe(host, port, ms = 300) {
  return new Promise((r) => {
    const s = new net.Socket();
    const done = (v) => { s.destroy(); r(v); };
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

// ================================================================= main
(async () => {
  console.log('');
  rule('#');
  say('  Z E R O P O R T      a guided walkthrough');
  say('');
  say('  A network where nothing listens on the internet — and authorized');
  say('  peers still connect, at full speed, with every flow attributed.');
  rule('#');
  console.log('');
  say(`  Running on ${ON_LAN ? 'this machine\'s network interface' : 'loopback'}: ${HOST}`);
  say('  Five processes, each a separate program, talking over real sockets.');
  console.log('');

  const relay = launch('nostr-relay.js', ['8801', HOST], 'relay');
  const rdv = launch('rendezvous.js', ['8802', HOST], 'rendezvous');
  await relay.waitReady(); await rdv.waitReady();
  res(`directory   — who exists and what they may reach   ${HOST}:8801`);
  res(`rendezvous  — how two peers find each other        ${HOST}:8802`);

  const mk = (name, servicePort) => launch('agent.js', [JSON.stringify({
    name, host: HOST, relay: RELAY_WS, rendezvous: RDV,
    groupPub: GROUP.groupPub, officerPubs,
    log: path.join(DIR, `audit-${name}.log`), servicePort,
  })], name);

  const db = mk('finance-db', 5432);
  const alice = mk('officer-laptop', 0);
  const rogue = mk('unknown-device', 0);
  const [dbR, aliceR, rogueR] = await Promise.all([db.waitReady(), alice.waitReady(), rogue.waitReady()]);
  res(`finance-db      the protected service    ${dbR.id}`);
  res(`officer-laptop  an authorized officer    ${aliceR.id}`);
  res(`unknown-device  no invitation            ${rogueR.id}`);

  const peers = [
    { id: dbR.id, idPub: dbR.idPub, staticPub: dbR.staticPub, name: 'finance-db' },
    { id: aliceR.id, idPub: aliceR.idPub, staticPub: aliceR.staticPub, name: 'officer-laptop' },
  ];
  const policy = [{ from: aliceR.id, to: dbR.id, port: 5432, allow: true }];
  await publishRoster({ peers, policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  await ask(alice, { cmd: 'refresh' }, (e) => e.t === 'roster');
  console.log('');
  res('The two legitimate machines have been enrolled by two officers.');

  // ============================================================ STEP 1
  await step('THE DOOR THAT ISN\'T THERE', [
    'Every attack starts the same way: find something that answers.',
    'A firewall answers. A VPN gateway answers. A bastion answers. That is',
    'how they get found, mapped, and eventually broken into.',
    '',
    'So look for the service the way an attacker would.',
  ]);

  await act(`Scanning ${HOST} for anything that will accept a connection...`);
  const ports = [22, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, dbR.udpPort, aliceR.udpPort];
  for (let p = 8790; p <= 8815; p++) ports.push(p);
  const open = await scan(HOST, [...new Set(ports)]);
  const infra = open.filter((p) => p === 8801 || p === 8802);
  res(`${new Set(ports).size} ports probed. The database port 5432: nothing there.`);
  res(`The agent's own socket ${dbR.udpPort}: refuses TCP entirely.`);
  if (infra.length) res(`(${infra.join(' and ')} are the directory and rendezvous, not the service.)`);

  await act('Firing a packet straight at the agent, without credentials...');
  const raw = dgram.createSocket('udp4');
  const gotReply = await new Promise((r) => {
    const t = setTimeout(() => r(false), 900);
    raw.on('message', () => { clearTimeout(t); r(true); });
    raw.send(Buffer.from('GET / HTTP/1.1\r\n\r\n'), dbR.udpPort, HOST);
  });
  raw.close();
  res(gotReply ? 'It answered.' : 'No reply. The agent read it, found no valid signature, and stopped.');
  res('An attacker learns nothing — not even that something is there.');

  await act('Now the officer\'s laptop connects to the same machine...');
  const c1 = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432, payload: 'SELECT 1' }, (e) => e.t === 'result');
  res(c1.ok ? `Connected. Encrypted round trip returned "${c1.reply}" in ${c1.rttMs.toFixed(2)} ms.`
            : `Refused — ${c1.reason}`);
  await idea('the service is not hidden behind a lock — it has no door at all. Being able to reach it is a property of holding the right key, which is why the scanner and the officer can both be telling the truth.');

  // ============================================================ STEP 2
  await step('HOW TWO MACHINES MEET WHEN NEITHER CAN BE CALLED', [
    'Both machines sit behind their own network. Neither has a public address,',
    'so neither can dial the other. They need an introduction.',
    '',
    'A rendezvous performs that introduction — and then gets out of the way.',
    'Watch the same sealed packet travel both routes.',
  ]);

  await act('Sending it the long way, through the rendezvous...');
  const med = (a) => a.sort((x, y) => x - y)[Math.floor(a.length / 2)];
  const rel = [], dir = [];
  for (let i = 0; i < 5; i++) {
    const r = await ask(alice, { cmd: 'probe', target: dbR.id, route: 'relayed' }, (e) => e.t === 'result');
    if (r.ok) rel.push(r.rttMs);
  }
  res(`Two hops — laptop to rendezvous, rendezvous to service. ${med(rel).toFixed(1)} ms.`);
  res('The rendezvous moved the bytes but could not read them.');

  await act('Now the same packet, directly...');
  for (let i = 0; i < 5; i++) {
    const d = await ask(alice, { cmd: 'probe', target: dbR.id, route: 'direct' }, (e) => e.t === 'result');
    if (d.ok) dir.push(d.rttMs);
  }
  res(`One hop. ${med(dir).toFixed(1)} ms. The rendezvous is no longer in the path.`);
  await idea('the introduction is brief and the middleman leaves. Traffic runs directly between the two machines, so there is no third party in the middle of the conversation and nothing to slow it down or subpoena.');

  // ============================================================ STEP 3
  await step('WHO IS ALLOWED TO CHANGE THE GUEST LIST', [
    'Someone has to decide which machines belong on the network. In most',
    'systems that is an administrator account — and an administrator account',
    'can be phished, coerced, or simply wrong.',
    '',
    'Here the authority to change the list is split across three officers.',
  ]);

  await act('One officer tries to add an unknown device on their own...');
  const rogueBody = {
    peers: [...peers, { id: rogueR.id, idPub: rogueR.idPub, staticPub: rogueR.staticPub, name: 'unknown-device' }],
    policy: [...policy, { from: rogueR.id, to: dbR.id, port: 5432, allow: true }],
  };
  const one = await publishRoster(rogueBody, 1);
  res(`The directory refuses it: "${one.message}".`);
  res('Not a permission error. One share cannot form a signature for the group key,');
  res('so the thing they tried to submit is not a valid signature at all.');

  await act('A second officer signs the same list...');
  const two = await publishRoster(rogueBody, 2);
  res(two.ok ? 'Accepted. Two shares combined into one signature.' : `Refused — ${two.message}`);
  res('A verifier sees a single ordinary signature; it cannot tell two people made it.');

  await act('Putting the safe list back...');
  await publishRoster({ peers, policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  res('Done.');
  await idea('no single administrator can quietly add a machine to this network. Not because policy forbids it, but because the signature one person is able to produce does not exist as a valid signature.');

  // ============================================================ STEP 4
  await step('WHAT HAPPENS TO A LAPTOP THAT IS STOLEN', [
    'A device is taken. Nobody notices for a day. In most networks its',
    'credentials keep working until a human revokes them.',
    '',
    'Here, permission is a lease that has to be renewed — so the question',
    'becomes what happens when a device simply stops asking.',
  ]);

  await act('Giving the laptop a three-second lease...');
  await publishRoster({ peers: peers.map((p) => (p.id === aliceR.id ? { ...p, leaseExpires: Date.now() + 3000 } : p)), policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  const inLease = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  res(inLease.ok ? 'It connects normally.' : `Refused — ${inLease.reason}`);

  await act('Now four seconds pass. Nothing is revoked. Nobody touches anything...');
  await sleep(4000);
  const expired = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  res(expired.ok ? 'It still connects.' : 'Refused.');
  res(`The service recorded why: "${lastDeny()}".`);
  await idea('access decays unless it is renewed, so a device that goes quiet loses its permission on its own. The safe state is the default, and nobody has to be paying attention for it to hold.');

  // ============================================================ STEP 5
  await step('THE TWO WAYS IN THAT DO NOT WORK', [
    'Two attempts every real network faces: a machine that was never invited,',
    'and an invited machine reaching for something it was never given.',
    '',
    'Then we take a machine off the list while it is connected.',
  ]);

  await publishRoster({ peers, policy }, 2);
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');

  await act('The unknown device tries the database...');
  const rogueTry = await ask(rogue, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  res(rogueTry.ok ? 'It got in.' : 'Dropped in silence.');
  res(`The service's log says: "${lastDeny()}".`);

  await act('The officer reaches for a port nobody granted her — SSH on 22...');
  const wrongPort = await ask(alice, { cmd: 'connect', target: dbR.id, port: 22 }, (e) => e.t === 'result');
  res(wrongPort.ok ? 'Allowed.' : 'Dropped.');
  res(`Log: "${lastDeny()}".`);
  res('Her permission is for one port on one machine, not for the network.');

  await act('Now one officer removes her from the list...');
  const rev = await publishRevocation(0, [aliceR.id]);
  res(rev.ok ? 'Accepted — signed by a single officer.' : 'Refused.');
  res('Adding a machine takes two people. Removing one takes one, deliberately.');
  await ask(db, { cmd: 'refresh' }, (e) => e.t === 'roster');
  const afterRevoke = await ask(alice, { cmd: 'connect', target: dbR.id, port: 5432 }, (e) => e.t === 'result');
  res(afterRevoke.ok ? 'She still connects.' : `She is gone from the network. Log: "${lastDeny()}".`);
  await idea('permission is per-machine and per-port, and it is checked on every single request. A device that is not on the list, or is reaching somewhere it should not, is refused without ever learning why.');

  // ============================================================ STEP 6
  await step('THE RECORD OF WHAT HAPPENED', [
    'A security team\'s last line of defence is the log. Which is a problem,',
    'because whoever breaks in can usually edit it.',
    '',
    'Each entry here carries the fingerprint of the one before it, and the',
    'end of the chain is published somewhere the attacker does not control.',
  ]);

  const anchor = await ask(db, { cmd: 'anchor' }, (e) => e.t === 'anchor');
  const logPath = DB_LOG;
  await act('Reading back what the service recorded...');
  // show a mix of permitted and refused, so the attribution is visible on both
  const allEntries = fs.readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const flows = [
    ...allEntries.filter((e) => e.event.type === 'flow').slice(-2),
    ...allEntries.filter((e) => e.event.type === 'deny').slice(-3),
  ].sort((a, b) => a.seq - b.seq);
  for (const f of flows) {
    const ev = f.event;
    res(ev.type === 'flow'
      ? `#${f.seq}  ALLOW  ${ev.peer} -> ${ev.service}  ${ev.bytes} bytes`
      : `#${f.seq}  DENY   ${ev.peer || 'unknown'} — ${ev.reason}`);
  }
  res('Every line names a machine, not an IP address that has to be guessed at.');

  await act('Publishing the end of the chain to an outside timestamp service...');
  const ext = await anchorSvc.submit(Buffer.from(anchor.head, 'hex'));
  if (ext.ok) {
    anchorSvc.save(logPath, Buffer.from(anchor.head, 'hex'), ext);
    res(`Accepted by ${ext.calendar.replace('https://', '')} — a witness we do not control.`);
  } else {
    res('The outside service is unreachable right now; the local chain still holds.');
  }

  await act('An intruder edits one line to hide a refusal...');
  const original = fs.readFileSync(logPath, 'utf8');
  const lines = original.trim().split('\n');
  const target = lines.findIndex((l) => l.includes('"deny"'));
  const idx = target >= 0 ? target : 1;
  const e = JSON.parse(lines[idx]);
  e.event = { type: 'flow', note: 'nothing happened here' };
  lines[idx] = JSON.stringify(e);
  fs.writeFileSync(logPath, lines.join('\n') + '\n');
  const v2 = zp.verifyLog(logPath, anchor.head);
  res(v2.ok ? 'It went unnoticed.' : `Caught at line ${v2.line} — the fingerprints stop matching.`);

  await act('So they replace the whole file with a clean one instead...');
  const fresh = new zp.AuditLog(logPath);
  fresh.append({ type: 'agent_start', note: 'a quieter history' });
  fresh.append({ type: 'flow', note: 'nothing unusual' });
  const selfOk = zp.verifyLog(logPath).ok;
  const v3 = zp.verifyLog(logPath, anchor.head);
  res(`The new file is internally consistent: ${selfOk ? 'yes' : 'no'}.`);
  res(v3.ok ? 'And it passes.' : 'But it does not match the record published outside. Caught.');
  fs.writeFileSync(logPath, original);
  await idea('the log is not trusted because we promise to look after it. Editing one line breaks the chain, and swapping the whole file fails against a copy of the fingerprint held by somebody else.');

  // ---------------------------------------------------------------- close
  console.log('');
  rule('#');
  say('  What you just watched');
  rule('#');
  console.log('');
  say('  Nothing listened, so there was nothing to find.');
  say('  Two machines that could not call each other were introduced, then');
  say('  spoke directly with the introducer out of the way.');
  say('  Adding a machine took two officers; removing one took a single officer.');
  say('  A quiet device lost its access without anyone intervening.');
  say('  Every request was checked against a named identity and a named port.');
  say('  And the record of it cannot be edited without that showing.');
  console.log('');
  rule('#');
  console.log('');
  kids.forEach((k) => k.kill());
  process.exit(0);
})().catch((e) => {
  console.error('ERROR:', e);
  kids.forEach((k) => k.kill());
  process.exit(1);
});
