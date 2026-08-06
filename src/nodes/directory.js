'use strict';
// PLANE 1 - a REAL Nostr relay speaking NIP-01 over WebSocket.
//
// It is a dumb store with one rule: an event must carry a valid BIP-340
// signature over its own id, or it is rejected. The relay holds no authority -
// it cannot forge a roster, only refuse a malformed one. Whether a roster has
// enough officer authority is decided by the AGENTS, against the group key.
const http = require('http');
const ws = require('../transport/websocket');
const nostr = require('../protocol/nostr-event');

const PORT = Number(process.argv[2] || 8801);

const events = [];               // all accepted events
const replaceable = new Map();   // `${kind}:${pubkey}:${d}` -> event
const subs = new Map();          // conn -> Map(subId -> filters[])

function store(ev) {
  // NIP-01 parameterised replaceable events: keep only the newest per (kind,pubkey,d)
  if (ev.kind >= 30000 && ev.kind < 40000) {
    const key = `${ev.kind}:${ev.pubkey}:${nostr.dTag(ev) || ''}`;
    const prev = replaceable.get(key);
    if (prev && prev.created_at > ev.created_at) return false;
    if (prev) events.splice(events.indexOf(prev), 1);
    replaceable.set(key, ev);
  }
  events.push(ev);
  return true;
}

const server = http.createServer((req, res) => {
  // NIP-11 relay information document
  if (req.headers.accept === 'application/nostr+json') {
    res.writeHead(200, { 'content-type': 'application/nostr+json' });
    return res.end(JSON.stringify({
      name: 'zeroport-relay', description: 'ZeroPort self-hosted control plane',
      supported_nips: [1, 11], software: 'zeroport-demo',
    }));
  }
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('ZeroPort Nostr relay - connect over WebSocket (NIP-01)\n');
});

ws.attach(server, (conn) => {
  subs.set(conn, new Map());
  conn.on('close', () => subs.delete(conn));

  conn.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return conn.send(JSON.stringify(['NOTICE', 'invalid json'])); }
    if (!Array.isArray(msg)) return;

    if (msg[0] === 'EVENT') {
      const ev = msg[1];
      if (!nostr.verifyEvent(ev)) {
        console.log(`#EVT ${JSON.stringify({ t: 'event_rejected', id: ev && ev.id, reason: 'bad signature' })}`);
        return conn.send(JSON.stringify(['OK', ev && ev.id, false, 'invalid: signature verification failed']));
      }
      const kept = store(ev);
      console.log(`#EVT ${JSON.stringify({ t: 'event_accepted', kind: ev.kind, id: ev.id.slice(0, 12), d: nostr.dTag(ev) })}`);
      conn.send(JSON.stringify(['OK', ev.id, true, '']));
      if (kept) {                                   // fan out to live subscriptions
        for (const [c, m] of subs) {
          for (const [sid, filters] of m) {
            if (filters.some((f) => nostr.matches(f, ev))) c.send(JSON.stringify(['EVENT', sid, ev]));
          }
        }
      }
      return;
    }

    if (msg[0] === 'REQ') {
      const [, sid, ...filters] = msg;
      subs.get(conn).set(sid, filters);
      for (const ev of events) {
        if (filters.some((f) => nostr.matches(f, ev))) conn.send(JSON.stringify(['EVENT', sid, ev]));
      }
      return conn.send(JSON.stringify(['EOSE', sid]));
    }

    if (msg[0] === 'CLOSE') { subs.get(conn).delete(msg[1]); return; }
  });
});

server.listen(PORT, process.argv[3] || '127.0.0.1', () => {
  console.log(`#READY ${JSON.stringify({ plane: 'control', protocol: 'NIP-01 over WebSocket', port: PORT })}`);
});
