'use strict';
// Real BIP-340 Schnorr signatures over secp256k1 - the exact scheme Nostr uses.
// Implemented from the specification with BigInt field arithmetic, validated
// against the official BIP-340 test vectors (see selftest()).
const crypto = require('crypto');

const P = 2n ** 256n - 2n ** 32n - 977n;                                    // field prime
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n; // group order
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

const mod = (a, m = P) => ((a % m) + m) % m;
function pow(b, e, m = P) {                       // modular exponentiation
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const inv = (a, m = P) => pow(mod(a, m), m - 2n, m);   // Fermat inverse

// --- point arithmetic in Jacobian-free affine form; null is the identity ---
function add(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && y1 !== y2) return null;             // P + (-P) = infinity
  const l = x1 === x2 && y1 === y2
    ? mod(3n * x1 * x1 * inv(2n * y1))                 // doubling (a = 0)
    : mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}
// Scalar multiplication in Jacobian coordinates (X/Z^2, Y/Z^3) so the inner
// loop needs no modular inverse - only one inverse at the very end. Affine
// doubling needed an inverse per bit, which was ~100x slower.
const JZERO = [0n, 1n, 0n];                          // point at infinity
function jDbl(p) {
  const [X, Y, Z] = p;
  if (Z === 0n || Y === 0n) return JZERO;
  const A = mod(X * X), B = mod(Y * Y), C = mod(B * B);
  const t = X + B;
  const D = mod(2n * (mod(t * t) - A - C));
  const E = mod(3n * A), F = mod(E * E);
  const X3 = mod(F - 2n * D);
  return [X3, mod(E * (D - X3) - 8n * C), mod(2n * Y * Z)];
}
function jAdd(p1, p2) {
  if (p1[2] === 0n) return p2;
  if (p2[2] === 0n) return p1;
  const Z1Z1 = mod(p1[2] * p1[2]), Z2Z2 = mod(p2[2] * p2[2]);
  const U1 = mod(p1[0] * Z2Z2), U2 = mod(p2[0] * Z1Z1);
  const S1 = mod(p1[1] * p2[2] * Z2Z2), S2 = mod(p2[1] * p1[2] * Z1Z1);
  if (U1 === U2) return S1 === S2 ? jDbl(p1) : JZERO;
  const H = mod(U2 - U1), I = mod(4n * H * H), J = mod(H * I);
  const r = mod(2n * (S2 - S1)), V = mod(U1 * I);
  const X3 = mod(r * r - J - 2n * V);
  const zs = p1[2] + p2[2];
  return [X3, mod(r * (V - X3) - 2n * S1 * J), mod((mod(zs * zs) - Z1Z1 - Z2Z2) * H)];
}
function mul(k, p = [Gx, Gy]) {
  k = mod(k, N);
  if (k === 0n || !p) return null;
  let R = JZERO, A = [p[0], p[1], 1n];
  while (k > 0n) { if (k & 1n) R = jAdd(R, A); A = jDbl(A); k >>= 1n; }
  if (R[2] === 0n) return null;
  const zi = inv(R[2]), zi2 = mod(zi * zi);
  return [mod(R[0] * zi2), mod(R[1] * zi2 * zi)];
}

const bytes = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');   // 32-byte BE
const num = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const hasEvenY = (pt) => pt[1] % 2n === 0n;

function taggedHash(tag, ...msgs) {                 // sha256(sha256(tag)||sha256(tag)||msg)
  const t = crypto.createHash('sha256').update(tag).digest();
  return crypto.createHash('sha256').update(Buffer.concat([t, t, ...msgs])).digest();
}

function liftX(x) {                                 // even-Y point with this x, or null
  if (x >= P) return null;
  const c = mod(x * x * x + 7n);
  const y = pow(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) return null;                // not on the curve
  return [x, y % 2n === 0n ? y : P - y];
}

// x-only public key from a 32-byte secret
function xOnlyPub(sk) {
  const d = num(sk);
  if (d <= 0n || d >= N) throw new Error('secret key out of range');
  return bytes(mul(d)[0]);
}

function sign(msg32, sk32, aux32 = Buffer.alloc(32)) {
  const d0 = num(sk32);
  if (d0 <= 0n || d0 >= N) throw new Error('secret key out of range');
  const Pt = mul(d0);
  const d = hasEvenY(Pt) ? d0 : N - d0;
  const t = bytes(d ^ num(taggedHash('BIP0340/aux', Buffer.from(aux32))));
  const rand = taggedHash('BIP0340/nonce', t, bytes(Pt[0]), Buffer.from(msg32));
  const k0 = mod(num(rand), N);
  if (k0 === 0n) throw new Error('nonce is zero');
  const R = mul(k0);
  const k = hasEvenY(R) ? k0 : N - k0;
  const e = mod(num(taggedHash('BIP0340/challenge', bytes(R[0]), bytes(Pt[0]), Buffer.from(msg32))), N);
  return Buffer.concat([bytes(R[0]), bytes(mod(k + e * d, N))]);
}

function verify(msg32, pub32, sig64) {
  try {
    const Pt = liftX(num(pub32));
    if (!Pt) return false;
    const r = num(sig64.subarray(0, 32));
    const s = num(sig64.subarray(32, 64));
    if (r >= P || s >= N) return false;
    const e = mod(num(taggedHash('BIP0340/challenge', sig64.subarray(0, 32), Buffer.from(pub32), Buffer.from(msg32))), N);
    const R = add(mul(s), mul(N - e, Pt));          // R = sG - eP
    if (!R || !hasEvenY(R) || R[0] !== r) return false;
    return true;
  } catch { return false; }
}

// ---------------- official BIP-340 test vectors ----------------
const VECTORS = [
  { sk: '0000000000000000000000000000000000000000000000000000000000000003',
    pk: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
    aux: '0000000000000000000000000000000000000000000000000000000000000000',
    msg: '0000000000000000000000000000000000000000000000000000000000000000',
    sig: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0' },
  { sk: 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
    pk: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    aux: '0000000000000000000000000000000000000000000000000000000000000001',
    msg: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    sig: '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A' },
  { sk: 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9',
    pk: 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
    aux: 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906',
    msg: '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    sig: '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7' },
  { sk: '0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710',
    pk: '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517',
    aux: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    msg: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    sig: '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3' },
];

function selftest() {
  const hx = (s) => Buffer.from(s, 'hex');
  const results = [];
  // 3*G is a well-known point - an independent check that the curve math is right
  results.push({ name: '3G x-coordinate', ok: bytes(mul(3n)[0]).toString('hex').toUpperCase() === VECTORS[0].pk });
  VECTORS.forEach((v, i) => {
    const pk = xOnlyPub(hx(v.sk)).toString('hex').toUpperCase();
    results.push({ name: `vector ${i} pubkey`, ok: pk === v.pk });
    const sig = sign(hx(v.msg), hx(v.sk), hx(v.aux)).toString('hex').toUpperCase();
    results.push({ name: `vector ${i} signature`, ok: sig === v.sig });
    results.push({ name: `vector ${i} verify`, ok: verify(hx(v.msg), hx(v.pk), hx(v.sig)) });
  });
  // a tampered signature must fail
  const bad = Buffer.from(VECTORS[1].sig, 'hex'); bad[10] ^= 0xff;
  results.push({ name: 'tampered signature rejected', ok: !verify(hx(VECTORS[1].msg), hx(VECTORS[1].pk), bad) });
  // wrong message must fail
  results.push({ name: 'wrong message rejected', ok: !verify(hx(VECTORS[2].msg), hx(VECTORS[1].pk), hx(VECTORS[1].sig)) });
  return results;
}

module.exports = { P, N, G: [Gx, Gy], mod, inv, add, mul, bytes, num, liftX,
  taggedHash, xOnlyPub, sign, verify, selftest };
