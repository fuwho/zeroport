'use strict';
// Real Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s - the handshake WireGuard itself
// uses, implemented from the WireGuard whitepaper (section 5.4).
//
// This replaces the hand-rolled handshake and fixes both disclosed weaknesses:
//   * FORWARD SECRECY - a fresh ephemeral X25519 keypair per handshake, so
//     compromising a static key does not decrypt recorded past sessions.
//   * REPLAY PROTECTION - the initiator's encrypted TAI64N timestamp must be
//     strictly greater than the last one seen from that peer.
const crypto = require('crypto');

const CONSTRUCTION = 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s';
const IDENTIFIER = 'WireGuard v1 zx2c4 Jason@zx2c4.com';
const ZERO32 = Buffer.alloc(32);

const hash = (...b) => crypto.createHash('blake2s256').update(Buffer.concat(b)).digest();
const hmac = (key, ...b) => crypto.createHmac('blake2s256', key).update(Buffer.concat(b)).digest();

// HKDF as WireGuard defines it
function kdf(n, key, input) {
  const t0 = hmac(key, input);
  const out = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    prev = hmac(t0, prev, Buffer.from([i]));
    out.push(prev);
  }
  return out;
}

// X25519 with raw 32-byte keys
const rawPub = (kp) => kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
function importPub(raw) {
  const der = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw)]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}
function newKeyPair() {
  const kp = crypto.generateKeyPairSync('x25519');
  return { priv: kp.privateKey, pub: rawPub(kp) };
}
const dh = (priv, peerRaw) => crypto.diffieHellman({ privateKey: priv, publicKey: importPub(peerRaw) });

// AEAD with a 64-bit counter nonce, as WireGuard specifies
function aead(key, counter, plaintext, ad) {
  const iv = Buffer.alloc(12);
  iv.writeBigUInt64LE(BigInt(counter), 4);
  const c = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  c.setAAD(ad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}
function aeadOpen(key, counter, box, ad) {
  const iv = Buffer.alloc(12);
  iv.writeBigUInt64LE(BigInt(counter), 4);
  const d = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  d.setAAD(ad);
  d.setAuthTag(box.subarray(box.length - 16));
  return Buffer.concat([d.update(box.subarray(0, box.length - 16)), d.final()]);
}

// TAI64N timestamp - 12 bytes, as WireGuard uses.
// MUST be strictly monotonic: the responder rejects any handshake whose
// timestamp is not newer, so a non-monotonic clock would reject legitimate
// reconnections as replays. Seconds and nanoseconds are therefore derived from
// the SAME clock, with a counter to break sub-millisecond ties.
let lastNs = 0n;
function tai64n() {
  let ns = BigInt(Date.now()) * 1000000n;
  if (ns <= lastNs) ns = lastNs + 1n;          // guarantee strict increase
  lastNs = ns;
  const b = Buffer.alloc(12);
  b.writeBigUInt64BE(ns / 1000000000n + 0x400000000000000An, 0);
  b.writeUInt32BE(Number(ns % 1000000000n), 8);
  return b;
}

// ---------- initiator: build message 1 ----------
function initiate(myStaticPriv, myStaticPub, theirStaticPub) {
  let C = hash(Buffer.from(CONSTRUCTION));
  let H = hash(C, Buffer.from(IDENTIFIER));
  H = hash(H, theirStaticPub);

  const eph = newKeyPair();
  [C] = kdf(1, C, eph.pub);
  H = hash(H, eph.pub);

  let k;
  [C, k] = kdf(2, C, dh(eph.priv, theirStaticPub));
  const encStatic = aead(k, 0, myStaticPub, H);
  H = hash(H, encStatic);

  [C, k] = kdf(2, C, dh(myStaticPriv, theirStaticPub));
  const ts = tai64n();
  const encTs = aead(k, 0, ts, H);
  H = hash(H, encTs);

  return {
    msg: { ephemeral: eph.pub.toString('base64'), static: encStatic.toString('base64'), timestamp: encTs.toString('base64') },
    state: { C, H, eph, myStaticPriv },
  };
}

// ---------- responder: consume message 1, build message 2 ----------
// lastTimestamps: Map peerStaticB64 -> Buffer, enforcing the replay window
function respond(msg, myStaticPriv, myStaticPub, lastTimestamps, isKnownPeer) {
  let C = hash(Buffer.from(CONSTRUCTION));
  let H = hash(C, Buffer.from(IDENTIFIER));
  H = hash(H, myStaticPub);

  const theirEph = Buffer.from(msg.ephemeral, 'base64');
  [C] = kdf(1, C, theirEph);
  H = hash(H, theirEph);

  let k;
  [C, k] = kdf(2, C, dh(myStaticPriv, theirEph));
  const encStatic = Buffer.from(msg.static, 'base64');
  let theirStaticPub;
  try { theirStaticPub = aeadOpen(k, 0, encStatic, H); }
  catch { return { ok: false, reason: 'handshake authentication failed' }; }
  H = hash(H, encStatic);

  if (isKnownPeer && !isKnownPeer(theirStaticPub))
    return { ok: false, reason: 'peer static key not on the signed roster' };

  [C, k] = kdf(2, C, dh(myStaticPriv, theirStaticPub));
  const encTs = Buffer.from(msg.timestamp, 'base64');
  let ts;
  try { ts = aeadOpen(k, 0, encTs, H); }
  catch { return { ok: false, reason: 'timestamp authentication failed' }; }
  H = hash(H, encTs);

  // REPLAY PROTECTION: the timestamp must strictly increase for this peer
  const id = theirStaticPub.toString('base64');
  const prev = lastTimestamps.get(id);
  if (prev && Buffer.compare(ts, prev) <= 0)
    return { ok: false, reason: 'replayed handshake (timestamp not newer)' };
  lastTimestamps.set(id, ts);

  // ---- message 2 ----
  const eph = newKeyPair();
  [C] = kdf(1, C, eph.pub);
  H = hash(H, eph.pub);
  [C] = kdf(1, C, dh(eph.priv, theirEph));
  [C] = kdf(1, C, dh(eph.priv, theirStaticPub));

  const [C2, tau, k2] = kdf(3, C, ZERO32);          // psk2 (all-zero preshared key)
  H = hash(H, tau);
  const empty = aead(k2, 0, Buffer.alloc(0), H);
  H = hash(H, empty);

  const [recv, send] = kdf(2, C2, Buffer.alloc(0)); // responder: recv first
  return {
    ok: true,
    theirStaticPub,
    msg: { ephemeral: eph.pub.toString('base64'), empty: empty.toString('base64') },
    keys: { send, recv },
  };
}

// ---------- initiator: consume message 2 ----------
function complete(msg2, state, theirStaticPub) {
  let { C, H, eph, myStaticPriv } = state;
  const theirEph = Buffer.from(msg2.ephemeral, 'base64');
  [C] = kdf(1, C, theirEph);
  H = hash(H, theirEph);
  [C] = kdf(1, C, dh(eph.priv, theirEph));
  [C] = kdf(1, C, dh(myStaticPriv, theirEph));

  const [C2, tau, k2] = kdf(3, C, ZERO32);
  H = hash(H, tau);
  try { aeadOpen(k2, 0, Buffer.from(msg2.empty, 'base64'), H); }
  catch { return { ok: false, reason: 'response authentication failed' }; }

  const [send, recv] = kdf(2, C2, Buffer.alloc(0)); // initiator: send first
  return { ok: true, keys: { send, recv } };
}

module.exports = { newKeyPair, initiate, respond, complete, aead, aeadOpen, tai64n, dh };
