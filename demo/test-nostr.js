'use strict';
// Prove the relay really speaks NIP-01 over WebSocket, and that a FROST
// threshold signature is accepted as an ordinary Nostr event signature.
const { spawn } = require('child_process');
const path = require('path');
const nostr = require('./lib/nostr');
const frost = require('./lib/frost');
const bip = require('./lib/bip340');

const PORT = 8899;
const results = [];
const check = (n, ok) => results.push({ name: n, ok });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const relay = spawn(process.execPath, [path.join(__dirname, 'nostr-relay.js'), String(PORT)], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((res) => relay.stdout.on('data', (d) => { if (d.toString().includes('#READY')) res(); }));

  // --- the SOC quorum: a real 2-of-3 FROST group ---
  const grp = frost.deal(2, 3);
  const signWithQuorum = (id32) => frost.sign(id32, [grp.shares[0], grp.shares[1]], grp.groupPub);

  const sock = new WebSocket(`ws://127.0.0.1:${PORT}`);
  const inbox = [];
  sock.addEventListener('message', (e) => inbox.push(JSON.parse(e.data)));
  await new Promise((res, rej) => {
    sock.addEventListener('open', res);
    sock.addEventListener('error', rej);
    setTimeout(() => rej(new Error('ws timeout')), 5000);
  });
  check('WebSocket handshake completed (real RFC 6455)', sock.readyState === 1);

  // --- publish a roster event signed by the threshold group ---
  const roster = nostr.build({
    pubkey: grp.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']],
    content: { version: 1, peers: [{ id: 'zp1abc', name: 'finance-db' }] },
  }, signWithQuorum);

  check('roster event id binds its content', nostr.eventId(roster).toString('hex') === roster.id);
  check('roster signature is a valid BIP-340 signature over the id',
    bip.verify(Buffer.from(roster.id, 'hex'), Buffer.from(grp.groupPub, 'hex'), Buffer.from(roster.sig, 'hex')));
  check('the event validates under the standard NIP-01 verifier', nostr.verifyEvent(roster));

  inbox.length = 0;
  sock.send(JSON.stringify(['EVENT', roster]));
  await sleep(300);
  const ok = inbox.find((m) => m[0] === 'OK');
  check('relay ACCEPTED the FROST-signed roster (["OK", id, true])', Boolean(ok && ok[1] === roster.id && ok[2] === true));

  // --- a tampered event must be refused ---
  const bad = { ...roster, content: JSON.stringify({ version: 99, peers: [{ id: 'attacker' }] }) };
  inbox.length = 0;
  sock.send(JSON.stringify(['EVENT', bad]));
  await sleep(300);
  const rej = inbox.find((m) => m[0] === 'OK');
  check('relay REJECTED a tampered roster', Boolean(rej && rej[2] === false));

  // --- a forged signature must be refused ---
  const forgedSig = Buffer.from(roster.sig, 'hex'); forgedSig[5] ^= 0xff;
  inbox.length = 0;
  sock.send(JSON.stringify(['EVENT', { ...roster, sig: forgedSig.toString('hex') }]));
  await sleep(300);
  const rej2 = inbox.find((m) => m[0] === 'OK');
  check('relay REJECTED a forged signature', Boolean(rej2 && rej2[2] === false));

  // --- REQ / EVENT / EOSE round trip ---
  inbox.length = 0;
  sock.send(JSON.stringify(['REQ', 'sub1', { kinds: [nostr.ROSTER_KIND], authors: [grp.groupPub] }]));
  await sleep(300);
  const got = inbox.find((m) => m[0] === 'EVENT' && m[1] === 'sub1');
  check('REQ returned the stored event', Boolean(got && got[2].id === roster.id));
  check('REQ terminated with EOSE', inbox.some((m) => m[0] === 'EOSE' && m[1] === 'sub1'));

  // --- replaceable semantics: v2 supersedes v1 ---
  const roster2 = nostr.build({
    pubkey: grp.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']],
    content: { version: 2, peers: [] },
    created_at: roster.created_at + 10,
  }, (id) => frost.sign(id, [grp.shares[1], grp.shares[2]], grp.groupPub));   // a DIFFERENT pair of officers
  check('a different pair of officers produces a valid signature too', nostr.verifyEvent(roster2));

  inbox.length = 0;
  sock.send(JSON.stringify(['EVENT', roster2]));
  await sleep(300);
  sock.send(JSON.stringify(['REQ', 'sub2', { kinds: [nostr.ROSTER_KIND] }]));
  await sleep(300);
  const versions = inbox.filter((m) => m[0] === 'EVENT' && m[1] === 'sub2').map((m) => JSON.parse(m[2].content).version);
  check('replaceable event kept only the newest version', versions.length === 1 && versions[0] === 2);

  // --- live subscription push ---
  inbox.length = 0;
  const roster3 = nostr.build({
    pubkey: grp.groupPub, kind: nostr.ROSTER_KIND, tags: [['d', 'zeroport-roster']],
    content: { version: 3, peers: [] }, created_at: roster.created_at + 20,
  }, signWithQuorum);
  sock.send(JSON.stringify(['EVENT', roster3]));
  await sleep(400);
  check('live subscriber was pushed the new roster', inbox.some((m) => m[0] === 'EVENT' && m[1] === 'sub2' && m[2].id === roster3.id));

  sock.close();
  relay.kill();

  let p = 0, f = 0;
  for (const r of results) { console.log((r.ok ? '  PASS  ' : '  FAIL  ') + r.name); r.ok ? p++ : f++; }
  console.log('');
  console.log(`NIP-01 over WebSocket + FROST-signed events: ${p} passed, ${f} failed`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error('ERROR', e); process.exit(1); });
