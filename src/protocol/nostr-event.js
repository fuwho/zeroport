'use strict';
// Real NIP-01 event construction and verification.
// id  = sha256(JSON.stringify([0, pubkey, created_at, kind, tags, content]))
// sig = BIP-340 Schnorr over that id, by `pubkey`
// Because the signature is plain BIP-340, a FROST threshold signature drops
// straight in: the roster event is signed by 2-of-3 officers yet looks like an
// ordinary single-key Nostr event to any standard client.
const crypto = require('crypto');
const bip = require('../crypto/bip340');

const ROSTER_KIND = 30078;          // parameterised replaceable app data

function serialize(ev) {
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
}
function eventId(ev) {
  return crypto.createHash('sha256').update(serialize(ev)).digest();
}

// signFn receives the 32-byte id and returns a 64-byte signature Buffer,
// so it works for both single-key and FROST threshold signing.
function build({ pubkey, kind, tags = [], content, created_at }, signFn) {
  const ev = {
    pubkey,
    created_at: created_at || Math.floor(Date.now() / 1000),
    kind,
    tags,
    content: typeof content === 'string' ? content : JSON.stringify(content),
  };
  const id = eventId(ev);
  ev.id = id.toString('hex');
  ev.sig = signFn(id).toString('hex');
  return ev;
}

function verifyEvent(ev) {
  try {
    if (!ev || typeof ev.id !== 'string' || typeof ev.sig !== 'string') return false;
    if (eventId(ev).toString('hex') !== ev.id) return false;           // id must bind the content
    return bip.verify(Buffer.from(ev.id, 'hex'), Buffer.from(ev.pubkey, 'hex'), Buffer.from(ev.sig, 'hex'));
  } catch { return false; }
}

// NIP-01 filter matching (the subset a relay needs here)
function matches(filter, ev) {
  if (filter.ids && !filter.ids.includes(ev.id)) return false;
  if (filter.kinds && !filter.kinds.includes(ev.kind)) return false;
  if (filter.authors && !filter.authors.includes(ev.pubkey)) return false;
  for (const k of Object.keys(filter)) {
    if (k[0] !== '#') continue;
    const tagName = k.slice(1);
    const want = filter[k];
    const has = ev.tags.some((t) => t[0] === tagName && want.includes(t[1]));
    if (!has) return false;
  }
  if (filter.since && ev.created_at < filter.since) return false;
  if (filter.until && ev.created_at > filter.until) return false;
  return true;
}

const dTag = (ev) => (ev.tags.find((t) => t[0] === 'd') || [])[1];

module.exports = { ROSTER_KIND, serialize, eventId, build, verifyEvent, matches, dTag };
