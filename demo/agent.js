'use strict';
// THE AGENT - the only ZeroPort software that runs on a host.
//
// Identity      : real BIP-340 Schnorr over secp256k1 (the Nostr scheme)
// Tunnel        : real Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s (WireGuard's handshake)
// Enforcement   : default deny - roster membership, revocation, lease, policy
//
// It binds ONE UDP socket and NO TCP listener, so a port scan finds nothing.
// The roster (quorum-signed) is what binds a Schnorr identity to the X25519
// static key that Noise authenticates, so the two layers cannot be mixed up.
const dgram = require('dgram');
const readline = require('readline');
const crypto = require('crypto');
const zp = require('./lib/zp');
const noise = require('./lib/noise');
const nostr = require('./lib/nostr');
const nclient = require('./lib/nclient');

const cfg = JSON.parse(process.argv[2]);

const id = zp.newIdentity();                 // Schnorr identity
const stat = noise.newKeyPair();             // long-term X25519 static key
const ME = zp.shortId(id.pub);
const audit = new zp.AuditLog(cfg.log);

let roster = null;
const sessions = new Map();      // inbound  peerId -> { keys, ctr }
const outSessions = new Map();   // outbound targetId -> { keys, ep, ctr }
const pending = new Map();
const seenTimestamps = new Map();// Noise replay window, per peer static key

const emit = (o) => console.log('#EVT ' + JSON.stringify(o));
const sock = dgram.createSocket('udp4');

// ---------------- roster, fetched over real NIP-01 ----------------
//
// Authority model, enforced purely by signature checking:
//   * the ROSTER is signed by the FROST group key. Because a threshold
//     signature is only producible by t-of-n officers, the agent does not need
//     to count anything - one BIP-340 verification IS the quorum check.
//   * a REVOCATION may be signed by any single officer's own key. Taking
//     access away is deliberately easier than granting it.
let relayConn = null;
async function relay() {
  if (!relayConn) relayConn = await nclient.connect(cfg.relay);
  return relayConn;
}

async function refreshRoster() {
  const c = await relay();

  const [rosterEv] = await c.query({
    kinds: [nostr.ROSTER_KIND], authors: [cfg.groupPub], '#d': ['zeroport-roster'],
  });
  if (!rosterEv) return null;
  if (!nostr.verifyEvent(rosterEv)) {
    audit.append({ type: 'roster_rejected', reason: 'invalid threshold signature' });
    return null;
  }
  const body = JSON.parse(rosterEv.content);
  if (roster && body.version < roster.version) return roster;      // ignore stale
  roster = body;

  // apply any emergency revocations signed by an individual officer
  const revs = await c.query({
    kinds: [nostr.ROSTER_KIND], authors: cfg.officerPubs, '#d': ['zeroport-revocation'],
  });
  for (const ev of revs) {
    if (!nostr.verifyEvent(ev)) continue;                          // forged - ignore
    let payload; try { payload = JSON.parse(ev.content); } catch { continue; }
    for (const pid of payload.revoke || []) {
      const p = roster.peers.find((x) => x.id === pid);
      if (p && !p.revoked) {
        p.revoked = true;
        audit.append({ type: 'emergency_revocation_applied', peer: pid, officer: ev.pubkey.slice(0, 12) });
      }
    }
  }
  return roster;
}
const peerByStatic = (pubHex) => roster && roster.peers.find((p) => p.staticPub === pubHex);
const peerById = (pid) => roster && roster.peers.find((p) => p.id === pid);

// full admission decision; null = allow
function admit(peerId, port) {
  if (!roster) return 'no signed roster';
  const p = peerById(peerId);
  if (!p) return 'peer not enrolled on the signed roster';
  if (p.revoked) return 'peer revoked';
  if (p.leaseExpires && Date.now() > p.leaseExpires) return 'lease expired';
  const allowed = (roster.policy || []).some(
    (r) => r.from === peerId && r.to === ME && r.port === port && r.allow);
  if (!allowed) return `no policy permits ${peerId} -> ${ME}:${port}`;
  return null;
}

// ---------------- inbound ----------------
sock.on('message', async (buf, rinfo) => {
  let m;
  try { m = JSON.parse(buf.toString()); } catch {
    audit.append({ type: 'deny', reason: 'unparseable packet', from: `${rinfo.address}:${rinfo.port}` });
    emit({ t: 'dropped', reason: 'unparseable packet' });
    return;
  }
  const reply = (o) => sock.send(Buffer.from(JSON.stringify(o)), rinfo.port, rinfo.address);

  // ---- Noise handshake initiation ----
  if (m.t === 'init') {
    const res = noise.respond(m.msg, stat.priv, stat.pub, seenTimestamps,
      (pub) => Boolean(peerByStatic(pub.toString('hex'))));
    if (!res.ok) {
      audit.append({ type: 'deny', reason: res.reason, from: `${rinfo.address}:${rinfo.port}` });
      emit({ t: 'denied', reason: res.reason });
      return;                                       // silent drop - tell an attacker nothing
    }
    const peer = peerByStatic(res.theirStaticPub.toString('hex'));
    sessions.set(peer.id, { keys: res.keys, ctr: 0 });
    audit.append({ type: 'handshake', peer: peer.id, suite: 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s' });
    emit({ t: 'handshake', peer: peer.id });
    reply({ t: 'ok', cid: m.cid, msg: res.msg });
    return;
  }

  if (m.t === 'ok' || m.t === 'echo') {
    const p = pending.get(m.cid);
    if (p) { pending.delete(m.cid); p(m); }
    return;
  }

  // ---- encrypted request; the port lives inside the sealed payload ----
  if (m.t === 'data') {
    const s = sessions.get(m.from);
    if (!s) { audit.append({ type: 'deny', reason: 'no session', peer: m.from }); return; }
    let req;
    try {
      req = JSON.parse(noise.aeadOpen(s.keys.recv, m.ctr, Buffer.from(m.box, 'base64'), Buffer.alloc(0)).toString());
    } catch {
      audit.append({ type: 'deny', reason: 'AEAD authentication failed', peer: m.from });
      emit({ t: 'denied', reason: 'AEAD authentication failed' });
      return;
    }
    const why = admit(m.from, req.port);
    if (why) {
      audit.append({ type: 'deny', peer: m.from, port: req.port, reason: why });
      emit({ t: 'denied', peer: m.from, port: req.port, reason: why });
      return;                                       // silent drop
    }
    audit.append({
      type: 'flow', peer: m.from, service: `${ME}:${req.port}`,
      bytes: req.payload.length, policy: 'allow', path: 'direct',
    });
    emit({ t: 'flow', peer: m.from, bytes: req.payload.length });
    const ctr = ++s.ctr + 1000;
    reply({ t: 'echo', cid: m.cid, ctr, box: noise.aead(s.keys.send, ctr, Buffer.from('ACK:' + req.payload), Buffer.alloc(0)).toString('base64') });
  }
});

// ---------------- outbound ----------------
function ask(host, port, msg, ms = 4000) {
  return new Promise((resolve) => {
    const cid = crypto.randomBytes(8).toString('hex');
    const timer = setTimeout(() => { pending.delete(cid); resolve({ t: 'timeout' }); }, ms);
    pending.set(cid, (m) => { clearTimeout(timer); resolve(m); });
    sock.send(Buffer.from(JSON.stringify({ ...msg, cid })), port, host);
  });
}

async function handshake(targetId) {
  await refreshRoster();
  const target = peerById(targetId);
  if (!target) return { ok: false, reason: 'target not on roster' };
  const lr = await fetch(`${cfg.rendezvous}/lookup?id=${targetId}`);
  if (!lr.ok) return { ok: false, reason: 'peer endpoint unknown' };
  const ep = await lr.json();

  const a = noise.initiate(stat.priv, stat.pub, Buffer.from(target.staticPub, 'hex'));
  const res = await ask(ep.host, ep.port, { t: 'init', msg: a.msg });
  if (res.t === 'timeout') return { ok: false, reason: 'no response (dropped)' };
  const c = noise.complete(res.msg, a.state);
  if (!c.ok) return { ok: false, reason: c.reason };
  outSessions.set(targetId, { keys: c.keys, ep, ctr: 0 });
  return { ok: true, ep };
}

async function connect(targetId, port, payload) {
  const t0 = process.hrtime.bigint();
  const h = await handshake(targetId);
  if (!h.ok) return h;
  const t1 = process.hrtime.bigint();
  const r = await send(targetId, 'direct', port, payload);
  return r.ok
    ? { ok: true, handshakeMs: Number(t1 - t0) / 1e6, rttMs: r.rttMs, reply: r.reply }
    : r;
}

async function send(targetId, route, port, payload) {
  const s = outSessions.get(targetId);
  if (!s) return { ok: false, reason: 'no session' };
  const ctr = ++s.ctr;
  const box = noise.aead(s.keys.send, ctr, Buffer.from(JSON.stringify({ port, payload })), Buffer.alloc(0)).toString('base64');
  const packet = { t: 'data', from: ME, ctr, box };

  const t0 = process.hrtime.bigint();
  let r;
  if (route === 'direct') {
    r = await ask(s.ep.host, s.ep.port, packet);
    if (r.t === 'timeout') return { ok: false, reason: 'no response (dropped)' };
  } else {
    const hr = await fetch(`${cfg.rendezvous}/relay?to=${targetId}`, { method: 'POST', body: JSON.stringify(packet) });
    if (!hr.ok) return { ok: false, reason: 'relay failed' };
    r = (await hr.json()).reply;
    if (!r) return { ok: false, reason: 'no response' };
  }
  const t1 = process.hrtime.bigint();
  const clear = noise.aeadOpen(s.keys.recv, r.ctr, Buffer.from(r.box, 'base64'), Buffer.alloc(0)).toString();
  return { ok: true, route, hops: route === 'direct' ? 1 : 2, rttMs: Number(t1 - t0) / 1e6, reply: clear };
}

// ---------------- control ----------------
sock.bind(0, cfg.host || '127.0.0.1', async () => {
  const a = sock.address();
  await fetch(cfg.rendezvous + '/announce', {
    method: 'POST', body: JSON.stringify({ id: ME, host: a.address, port: a.port }),
  }).catch(() => {});
  audit.append({ type: 'agent_start', id: ME, udp: a.port, tcpListeners: 0 });
  console.log('#READY ' + JSON.stringify({
    name: cfg.name, id: ME, idPub: id.pub, staticPub: stat.pub.toString('hex'), udpPort: a.port,
  }));
});

readline.createInterface({ input: process.stdin }).on('line', async (line) => {
  let c;
  try { c = JSON.parse(line); } catch { return; }
  try {
    if (c.cmd === 'refresh') {
      const r = await refreshRoster();
      emit({ t: 'roster', ok: !!r, version: r && r.version });
    } else if (c.cmd === 'connect') {
      emit({ t: 'result', cmd: 'connect', ...(await connect(c.target, c.port, c.payload || 'SELECT 1')) });
    } else if (c.cmd === 'probe') {
      emit({ t: 'result', cmd: 'probe', ...(await send(c.target, c.route, c.port || 5432, c.payload || 'SELECT 1')) });
    } else if (c.cmd === 'anchor') {
      emit({ t: 'anchor', head: audit.head() });
    } else if (c.cmd === 'quit') process.exit(0);
  } catch (e) {
    emit({ t: 'error', error: String(e && e.message) });
  }
});
