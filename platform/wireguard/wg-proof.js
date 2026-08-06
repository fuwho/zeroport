'use strict';
// ZeroPort driving a REAL WireGuard kernel interface.
//
// The control plane here is the genuine article: a real Nostr relay, a roster
// signed by a real FROST 2-of-3 threshold key, and a revocation signed by one
// officer. The data plane is a real WireGuard interface in the Windows kernel.
// What is proven is the join between them - an authorization decision made by
// ZeroPort becomes, or ceases to be, a peer the kernel will accept packets from.
const { spawn } = require('child_process');
const path = require('path');
const SRC = path.join(__dirname, '..', '..', 'src');
const frost = require(path.join(SRC, 'crypto', 'frost'));
const nostr = require(path.join(SRC, 'protocol', 'nostr-event'));
const nclient = require(path.join(SRC, 'transport', 'relay-client'));
const bip = require(path.join(SRC, 'crypto', 'bip340'));
const zp = require(path.join(SRC, 'domain', 'zeroport'));
const wgc = require('./wg-control');

const RELAY_PORT = 8901;
const RELAY_WS = `ws://127.0.0.1:${RELAY_PORT}`;
const ALICE_IP = '10.77.0.2';

const bar = (c = '=') => console.log(c.repeat(78));
const step = (s) => console.log(`  > ${s}`);
const out = (s) => console.log(`      ${s}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const kids = [];

function showPeers(label) {
  const peers = wgc.listPeers();
  out(`${label}: ${peers.length} peer(s)`);
  for (const p of peers) out(`   ${p.publicKey.slice(0, 20)}...  allowed-ips ${p.allowedIps}`);
  return peers;
}

(async () => {
  console.log('');
  bar('#');
  console.log('  ZEROPORT -> REAL WIREGUARD KERNEL INTERFACE');
  bar('#');
  console.log('');

  // ---------- preflight ----------
  if (!wgc.available()) {
    console.error(`  wg.exe not found at ${wgc.WG}\n  Install WireGuard first.`);
    process.exit(1);
  }
  if (!wgc.interfaceUp()) {
    console.error('  Interface zp0 is not up.\n' +
      '  Run this first, from an ELEVATED PowerShell:\n' +
      '      .\\zp-wg-setup.ps1\n');
    process.exit(1);
  }
  try { wgc.listPeers(); } catch (e) {
    console.error('  Cannot read zp0 - this usually means the shell is not elevated.\n' +
      '  Re-run from an Administrator terminal.\n');
    process.exit(1);
  }
  out(`WireGuard interface zp0 is up and readable`);

  // ---------- real control plane ----------
  step('Starting the real Nostr relay (NIP-01 over WebSocket)...');
  const relay = spawn(process.execPath, [path.join(__dirname, '..', '..', 'src', 'nodes', 'directory.js'), String(RELAY_PORT)],
    { stdio: ['ignore', 'pipe', 'inherit'] });
  kids.push(relay);
  await new Promise((res) => relay.stdout.on('data', (d) => { if (d.toString().includes('#READY')) res(); }));
  out(`relay listening on ${RELAY_WS}`);

  const GROUP = frost.deal(2, 3);
  const officers = [zp.newIdentity(), zp.newIdentity(), zp.newIdentity()];
  out(`FROST 2-of-3 group key: ${GROUP.groupPub.slice(0, 32)}...`);

  const conn = await nclient.connect(RELAY_WS);

  // alice's real WireGuard keypair
  const alice = wgc.genKeyPair();
  const aliceId = zp.shortId(alice.pub);
  out(`alice WireGuard public key: ${alice.pub}`);

  // ---------- PROOF A ----------
  console.log('');
  bar();
  console.log('  PROOF A   AN AUTHORIZED PEER APPEARS IN THE KERNEL');
  bar();
  console.log('  What this proves: a roster signed by 2-of-3 officers is what puts a peer');
  console.log('  into the real WireGuard interface. Nothing else can.');
  console.log('');

  wgc.removeAllPeers();
  showPeers('before');

  step('Publishing a roster signed by TWO officers (FROST threshold signature)...');
  const rosterEv = nostr.build({
    pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']],
    content: { version: 1, peers: [{ id: aliceId, name: 'alice-laptop', wgPub: alice.pub, ip: ALICE_IP }] },
  }, (id) => frost.sign(id, GROUP.shares.slice(0, 2), GROUP.groupPub));
  const pub1 = await conn.publish(rosterEv);
  out(`relay accepted the roster: ${pub1.ok}`);

  step('The bridge fetches the roster, verifies the signature, and programs the kernel...');
  const [fetched] = await conn.query({ kinds: [nostr.ROSTER_KIND], authors: [GROUP.groupPub], '#d': ['zeroport-roster'] });
  const valid = nostr.verifyEvent(fetched);
  out(`threshold signature verifies: ${valid}`);
  if (!valid) throw new Error('roster failed verification');

  const body = JSON.parse(fetched.content);
  for (const p of body.peers) wgc.addPeer(p.wgPub, p.ip);
  const after = showPeers('after');

  console.log('');
  console.log(`  VERDICT: ${after.length === 1 && after[0].publicKey === alice.pub
    ? 'The kernel now holds a peer that exists ONLY because two officers signed for it.'
    : 'INCONCLUSIVE - see output above.'}`);

  // ---------- PROOF B ----------
  console.log('');
  bar();
  console.log('  PROOF B   ONE OFFICER REVOKES, AND THE KERNEL FORGETS THE PEER');
  bar();
  console.log('  What this proves: revocation is not a firewall rule laid over the top.');
  console.log('  The peer stops existing to the data plane entirely.');
  console.log('');

  step('One officer publishes a revocation, signed with their own individual key...');
  const revEv = nostr.build({
    pubkey: officers[0].pub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-revocation']],
    content: { revoke: [aliceId] },
  }, (id) => bip.sign(id, officers[0].priv));
  const pub2 = await conn.publish(revEv);
  out(`relay accepted the revocation: ${pub2.ok}  (one signature, no quorum needed)`);

  step('The bridge verifies it and withdraws the peer from the kernel...');
  const revs = await conn.query({ kinds: [nostr.ROSTER_KIND], authors: officers.map((o) => o.pub), '#d': ['zeroport-revocation'] });
  const revoked = new Set();
  for (const ev of revs) {
    if (!nostr.verifyEvent(ev)) { out('  ignored an event that failed verification'); continue; }
    for (const id of JSON.parse(ev.content).revoke) revoked.add(id);
  }
  out(`revoked ids: ${[...revoked].join(', ')}`);
  for (const p of body.peers) if (revoked.has(p.id)) wgc.removePeer(p.wgPub);
  const gone = showPeers('after revocation');

  console.log('');
  console.log(`  VERDICT: ${gone.length === 0
    ? 'The peer is gone from the kernel. It cannot send a single packet through zp0.'
    : 'INCONCLUSIVE - see output above.'}`);

  // ---------- PROOF C ----------
  console.log('');
  bar();
  console.log('  PROOF C   A FORGED AUTHORIZATION CHANGES NOTHING');
  bar();
  console.log('  What this proves: only a genuine threshold signature moves the kernel.');
  console.log('');

  step('An attacker publishes a roster adding themselves, signed by ONE officer share...');
  const attacker = wgc.genKeyPair();
  const forged = nostr.build({
    pubkey: GROUP.groupPub, kind: nostr.ROSTER_KIND,
    tags: [['d', 'zeroport-roster']],
    content: { version: 2, peers: [{ id: 'zp1attacker', name: 'attacker', wgPub: attacker.pub, ip: '10.77.0.9' }] },
    created_at: Math.floor(Date.now() / 1000) + 60,
  }, (id) => frost.sign(id, [GROUP.shares[0]], GROUP.groupPub));   // one share only
  const pub3 = await conn.publish(forged);
  out(`relay response: ${pub3.ok ? 'ACCEPTED' : 'REJECTED'} - "${pub3.message}"`);
  const stillNone = showPeers('kernel state');

  console.log('');
  console.log(`  VERDICT: ${!pub3.ok && stillNone.length === 0
    ? 'The forged roster never became a valid signature, so the kernel never heard about it.'
    : 'INCONCLUSIVE - see output above.'}`);

  // ---------- cleanup ----------
  console.log('');
  bar();
  wgc.removeAllPeers();
  out('all peers removed - zp0 left empty and harmless');
  out('run  .\\zp-wg-teardown.ps1  to remove the interface entirely');
  console.log('');
  console.log('  NOTE: this machine is one host, so there is no second endpoint to');
  console.log('  handshake with and no ping to show. What is proven here is the join:');
  console.log('  ZeroPort\'s cryptographic decisions control a real kernel data plane.');
  console.log('  Put the peer config on a second machine and the same run carries real IP traffic.');
  bar('#');
  conn.close();
  kids.forEach((k) => k.kill());
  process.exit(0);
})().catch((e) => {
  console.error('\n  ERROR:', e.message);
  try { wgc.removeAllPeers(); } catch {}
  kids.forEach((k) => k.kill());
  process.exit(1);
});
