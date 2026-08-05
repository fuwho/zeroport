'use strict';
// Real FROST threshold Schnorr (RFC 9591 style) over secp256k1, BIP-340 encoded.
//
// The point of this file: t-of-n officers jointly produce ONE 64-byte signature
// that verifies with the ORDINARY BIP-340 verifier against a single group public
// key. A verifier cannot tell it came from several people, and fewer than t
// officers cannot produce it at all. That is genuine threshold signing - the
// previous version merely collected and counted separate signatures.
const crypto = require('crypto');
const bip = require('./bip340');

const N = bip.N;
const m = (a) => ((a % N) + N) % N;                  // mod the group order
const inv = (a) => bip.inv(a, N);

function randScalar() {
  for (;;) {
    const k = bip.num(crypto.randomBytes(32)) % N;
    if (k !== 0n) return k;
  }
}

// ---------- key generation (trusted dealer + Shamir over the scalar field) ----------
function deal(t, n) {
  let coeffs = [];
  for (let i = 0; i < t; i++) coeffs.push(randScalar());

  // BIP-340 needs the group key to have an even Y. Negating the whole
  // polynomial negates the secret AND every share consistently.
  let P = bip.mul(coeffs[0]);
  if (P[1] % 2n !== 0n) {
    coeffs = coeffs.map((a) => m(N - a));
    P = bip.mul(coeffs[0]);
  }

  const shares = [];
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i);
    let y = 0n, xp = 1n;
    for (const a of coeffs) { y = m(y + a * xp); xp = m(xp * x); }
    shares.push({ i, share: y });
  }
  return { groupPub: bip.bytes(P[0]).toString('hex'), shares, t, n };
}

// Lagrange coefficient at x=0 for participant i over the signing set S
function lambda(i, S) {
  let num = 1n, den = 1n;
  for (const j of S) {
    if (j === i) continue;
    num = m(num * BigInt(j));
    den = m(den * BigInt(j - i));
  }
  return m(num * inv(den));
}

// ---------- two-round signing ----------
// Round 1: every signer commits to a nonce pair (hiding, binding).
function round1() {
  const d = randScalar(), e = randScalar();
  return { secret: { d, e }, commitment: { D: bip.mul(d), E: bip.mul(e) } };
}

// Round 2: bind the commitments to the message, then each signer emits a
// partial scalar. The partials sum to a valid Schnorr s value.
function sign(msg32, signers, groupPubHex) {
  const S = signers.map((s) => s.i).sort((a, b) => a - b);
  const rounds = signers.map((s) => ({ i: s.i, share: s.share, ...round1() }));

  // canonical encoding of all commitments, so the binding factors are agreed
  const B = Buffer.concat(rounds.map((r) => Buffer.concat([
    Buffer.from([r.i]), bip.bytes(r.commitment.D[0]), bip.bytes(r.commitment.E[0]),
  ])));

  const rho = {};
  let R = null;
  for (const r of rounds) {
    rho[r.i] = m(bip.num(bip.taggedHash('FROST/rho', Buffer.from([r.i]), Buffer.from(msg32), B)));
    R = bip.add(R, bip.add(r.commitment.D, bip.mul(rho[r.i], r.commitment.E)));
  }
  if (!R) throw new Error('empty signing set');

  const evenR = R[1] % 2n === 0n;                  // BIP-340 needs even-Y R
  const Pbytes = Buffer.from(groupPubHex, 'hex');
  const c = m(bip.num(bip.taggedHash('BIP0340/challenge',
    bip.bytes(R[0]), Pbytes, Buffer.from(msg32))));

  let z = 0n;
  for (const r of rounds) {
    let k = m(r.secret.d + rho[r.i] * r.secret.e);
    if (!evenR) k = m(N - k);                      // flip nonces if R had odd Y
    const partial = m(k + m(m(lambda(r.i, S) * r.share) * c));
    z = m(z + partial);
  }
  return Buffer.concat([bip.bytes(R[0]), bip.bytes(z)]);
}

// ---------- self-test ----------
function selftest() {
  const out = [];
  const add = (name, ok) => out.push({ name, ok });
  const msg = crypto.createHash('sha256').update('revoke alice-laptop').digest();

  const grp = deal(2, 3);
  add('group public key is a valid 32-byte x-only key', /^[0-9a-f]{64}$/.test(grp.groupPub));

  // any 2 of the 3 officers must work
  const pairs = [[0, 1], [0, 2], [1, 2]];
  for (const [a, b] of pairs) {
    const sig = sign(msg, [grp.shares[a], grp.shares[b]], grp.groupPub);
    const ok = bip.verify(msg, Buffer.from(grp.groupPub, 'hex'), sig);
    add(`officers ${grp.shares[a].i}+${grp.shares[b].i} produce a valid BIP-340 signature`, ok);
    add(`  signature is exactly 64 bytes (indistinguishable from single-signer)`, sig.length === 64);
  }

  // a single officer must NOT be able to sign
  const lone = sign(msg, [grp.shares[0]], grp.groupPub);
  add('a lone officer CANNOT produce a valid signature', !bip.verify(msg, Buffer.from(grp.groupPub, 'hex'), lone));

  // signature must not transfer to another message
  const sig2 = sign(msg, [grp.shares[0], grp.shares[1]], grp.groupPub);
  const other = crypto.createHash('sha256').update('revoke someone-else').digest();
  add('a signature does not verify for a different message',
    !bip.verify(other, Buffer.from(grp.groupPub, 'hex'), sig2));

  // 3-of-5 as well, to show t and n are not hard-coded
  const g2 = deal(3, 5);
  const s3 = sign(msg, [g2.shares[0], g2.shares[2], g2.shares[4]], g2.groupPub);
  add('3-of-5 threshold also verifies', bip.verify(msg, Buffer.from(g2.groupPub, 'hex'), s3));
  const s2 = sign(msg, [g2.shares[0], g2.shares[2]], g2.groupPub);
  add('2 of a 3-of-5 group is refused', !bip.verify(msg, Buffer.from(g2.groupPub, 'hex'), s2));

  // freshly randomised each run
  const sigA = sign(msg, [grp.shares[0], grp.shares[1]], grp.groupPub);
  const sigB = sign(msg, [grp.shares[0], grp.shares[1]], grp.groupPub);
  add('nonces are fresh (two signings differ)', !sigA.equals(sigB));
  add('  but both still verify',
    bip.verify(msg, Buffer.from(grp.groupPub, 'hex'), sigA) &&
    bip.verify(msg, Buffer.from(grp.groupPub, 'hex'), sigB));

  return out;
}

module.exports = { deal, sign, lambda, selftest };
