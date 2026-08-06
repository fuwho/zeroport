'use strict';
// ZeroPort core primitives. Real cryptography, no dependencies.
//   identity  : Ed25519  (sign / verify)
//   tunnel    : X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305  (WireGuard's data-plane suite)
//   audit log : SHA-256 hash chain + signed head anchor
const crypto = require('crypto');
const fs = require('fs');
const bip = require('../crypto/bip340');

// ---------- canonical JSON so signatures are deterministic ----------
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// ---------- key handling ----------
const expPub = (k) => k.export({ type: 'spki', format: 'der' }).toString('base64url');
const impPub = (b64) =>
  crypto.createPublicKey({ key: Buffer.from(b64, 'base64url'), format: 'der', type: 'spki' });

// Identity is a real BIP-340 Schnorr keypair over secp256k1 - the exact scheme
// Nostr uses, so these identities are genuine Nostr identities.
function newIdentity() {
  let sk;
  for (;;) {
    sk = crypto.randomBytes(32);
    const n = BigInt('0x' + sk.toString('hex'));
    if (n > 0n && n < bip.N) break;
  }
  return { priv: sk, privKey: sk, pub: bip.xOnlyPub(sk).toString('hex') };
}
function newTunnelKey() {                      // X25519 key agreement
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return { pub: expPub(publicKey), pubKey: publicKey, privKey: privateKey };
}

// short human-readable id, the equivalent of an npub
function shortId(pub) {
  return 'zp1' + crypto.createHash('sha256').update(pub).digest('hex').slice(0, 10);
}

// ---------- signatures: real BIP-340 Schnorr ----------
const msgHash = (obj) => crypto.createHash('sha256').update(canon(obj)).digest();
const sign = (obj, priv) => bip.sign(msgHash(obj), priv).toString('hex');
function verify(obj, sig, pubHex) {
  try {
    return bip.verify(msgHash(obj), Buffer.from(pubHex, 'hex'), Buffer.from(sig, 'hex'));
  } catch { return false; }
}

// ---------- tunnel: real ECDH + real AEAD ----------
function deriveKey(myPriv, theirPub, salt) {
  const shared = crypto.diffieHellman({ privateKey: myPriv, publicKey: impPub(theirPub) });
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('zeroport-v1'), 32));
}
function seal(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return { iv: iv.toString('base64url'), ct: ct.toString('base64url'), tag: c.getAuthTag().toString('base64url') };
}
function open(key, box) {
  const d = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.from(box.iv, 'base64url'), { authTagLength: 16 });
  d.setAuthTag(Buffer.from(box.tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(box.ct, 'base64url')), d.final()]).toString();
}

// ---------- roster: requires an M-of-N quorum of officer signatures ----------
function verifyRoster(roster, officerPubs, threshold) {
  const body = roster.body;
  const seen = new Set();
  let valid = 0;
  for (const s of roster.sigs || []) {
    if (!officerPubs.includes(s.officer) || seen.has(s.officer)) continue;
    if (verify(body, s.sig, s.officer)) { seen.add(s.officer); valid++; }
  }
  return { ok: valid >= threshold, valid, threshold };
}

// Deliberate asymmetry: WIDENING access needs the full quorum, but NARROWING
// it needs only one officer. A change counts as revocation-only if it adds no
// peers, widens no policy, extends no lease, un-revokes nobody, and actually
// revokes somebody. Both the relay and every agent enforce this same rule, so
// an emergency revocation propagates all the way to the enforcement point.
function isRevocationOnly(oldB, newB) {
  if (!oldB) return false;
  const oldIds = new Set(oldB.peers.map((p) => p.id));
  if (newB.peers.some((p) => !oldIds.has(p.id))) return false;
  if (canon(newB.policy || []) !== canon(oldB.policy || [])) return false;
  for (const np of newB.peers) {
    const op = oldB.peers.find((p) => p.id === np.id);
    if (!op) return false;
    if (op.revoked && !np.revoked) return false;
    if ((np.leaseExpires || 0) > (op.leaseExpires || 0)) return false;
  }
  return newB.peers.some((np) => {
    const op = oldB.peers.find((p) => p.id === np.id);
    return np.revoked && !op.revoked;
  });
}

// Accept a roster: full quorum, OR >=1 signature if it only removes access.
function acceptRoster(doc, officerPubs, threshold, currentBody) {
  const v = verifyRoster(doc, officerPubs, threshold);
  if (v.ok) return { ok: true, mode: 'quorum', valid: v.valid };
  if (v.valid >= 1 && isRevocationOnly(currentBody, doc.body))
    return { ok: true, mode: 'emergency-revocation', valid: v.valid };
  return { ok: false, valid: v.valid, threshold };
}

// ---------- hash-chained audit log ----------
class AuditLog {
  constructor(path) {
    this.path = path;
    fs.writeFileSync(path, '');
    this.prev = 'GENESIS';
    this.seq = 0;
  }
  append(event) {
    const e = { seq: ++this.seq, ts: new Date().toISOString(), event, prev: this.prev };
    e.hash = crypto.createHash('sha256').update(canon(e)).digest('hex');
    this.prev = e.hash;
    fs.appendFileSync(this.path, JSON.stringify(e) + '\n');
    return e;
  }
  head() { return this.prev; }
}

// Verify a log file: recompute every link, and compare the final head to a
// publicly anchored value. Catches an edited line AND a wholesale file swap.
function verifyLog(path, anchoredHead) {
  const lines = fs.readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
  let prev = 'GENESIS';
  for (let i = 0; i < lines.length; i++) {
    let e;
    try { e = JSON.parse(lines[i]); } catch { return { ok: false, reason: 'unparseable entry', line: i + 1 }; }
    const { hash, ...rest } = e;
    const recomputed = crypto.createHash('sha256').update(canon(rest)).digest('hex');
    if (e.prev !== prev) return { ok: false, reason: 'chain break: prev-hash mismatch', line: i + 1, seq: e.seq };
    if (recomputed !== hash) return { ok: false, reason: 'entry altered: hash mismatch', line: i + 1, seq: e.seq };
    prev = hash;
  }
  if (anchoredHead && prev !== anchoredHead)
    return { ok: false, reason: 'head does not match public anchor (file replaced or truncated)', line: lines.length };
  return { ok: true, entries: lines.length, head: prev };
}

module.exports = {
  canon, expPub, impPub, newIdentity, newTunnelKey, shortId,
  sign, verify, deriveKey, seal, open, verifyRoster, isRevocationOnly, acceptRoster,
  AuditLog, verifyLog,
};
