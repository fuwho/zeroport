'use strict';
// Verify the Noise IK handshake, with emphasis on the two properties the
// previous hand-rolled handshake did NOT have.
const noise = require('./lib/noise');

const results = [];
const check = (name, ok) => results.push({ name, ok });

// two peers with long-term static keys
const I = noise.newKeyPair();   // initiator
const R = noise.newKeyPair();   // responder
const seen = new Map();
const known = (pub) => Buffer.compare(pub, I.pub) === 0;

// ---- 1. full handshake ----
const a = noise.initiate(I.priv, I.pub, R.pub);
const b = noise.respond(a.msg, R.priv, R.pub, seen, known);
check('responder accepts a valid handshake', b.ok);
const c = noise.complete(b.msg, a.state);
check('initiator completes the handshake', c.ok);

// ---- 2. both sides derived the SAME session keys ----
check('initiator.send === responder.recv', c.ok && b.ok && c.keys.send.equals(b.keys.recv));
check('initiator.recv === responder.send', c.ok && b.ok && c.keys.recv.equals(b.keys.send));

// ---- 3. transport encryption actually works both ways ----
let ok3 = false;
try {
  const ct = noise.aead(c.keys.send, 1, Buffer.from('SELECT * FROM cases'), Buffer.alloc(0));
  const pt = noise.aeadOpen(b.keys.recv, 1, ct, Buffer.alloc(0));
  const ct2 = noise.aead(b.keys.send, 1, Buffer.from('42 rows'), Buffer.alloc(0));
  const pt2 = noise.aeadOpen(c.keys.recv, 1, ct2, Buffer.alloc(0));
  ok3 = pt.toString() === 'SELECT * FROM cases' && pt2.toString() === '42 rows';
} catch {}
check('encrypted traffic decrypts correctly in both directions', ok3);

// ---- 4. FORWARD SECRECY: same statics, different session keys ----
const a2 = noise.initiate(I.priv, I.pub, R.pub);
const b2 = noise.respond(a2.msg, R.priv, R.pub, seen, known);
check('second handshake succeeds', b2.ok);
check('FORWARD SECRECY - session keys differ from the previous session',
  b2.ok && !b2.keys.send.equals(b.keys.send) && !b2.keys.recv.equals(b.keys.recv));
check('FORWARD SECRECY - a fresh ephemeral key is used each time',
  a.msg.ephemeral !== a2.msg.ephemeral);

// old session key must not open new traffic
let leaked = false;
try {
  const ct = noise.aead(b2.keys.send, 5, Buffer.from('secret'), Buffer.alloc(0));
  noise.aeadOpen(b.keys.send, 5, ct, Buffer.alloc(0));
  leaked = true;
} catch {}
check('an old session key cannot decrypt a new session', !leaked);

// ---- 5. REPLAY PROTECTION ----
const replay = noise.respond(a.msg, R.priv, R.pub, seen, known);
check('REPLAY PROTECTION - the very first handshake replayed is rejected',
  !replay.ok && /replay/i.test(replay.reason || ''));

// ---- 6. unknown peer is rejected ----
const X = noise.newKeyPair();
const ax = noise.initiate(X.priv, X.pub, R.pub);
const bx = noise.respond(ax.msg, R.priv, R.pub, new Map(), known);
check('a peer not on the roster is rejected', !bx.ok && /roster/i.test(bx.reason || ''));

// ---- 7. tampering is detected ----
const at = noise.initiate(I.priv, I.pub, R.pub);
const bad = Buffer.from(at.msg.static, 'base64'); bad[3] ^= 0xff;
const bt = noise.respond({ ...at.msg, static: bad.toString('base64') }, R.priv, R.pub, new Map(), known);
check('a tampered handshake is rejected', !bt.ok);

// ---- 8. wrong responder key cannot complete ----
const W = noise.newKeyPair();
const aw = noise.initiate(I.priv, I.pub, R.pub);
const bw = noise.respond(aw.msg, W.priv, W.pub, new Map(), known);
check('an impostor responder cannot complete the handshake', !bw.ok);

let pass = 0, fail = 0;
for (const r of results) { console.log((r.ok ? '  PASS  ' : '  FAIL  ') + r.name); r.ok ? pass++ : fail++; }
console.log('');
console.log(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
