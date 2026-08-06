'use strict';
// PLANE 2 - Rendezvous.
// Stands in for a client-authorized Tor onion service. Two jobs only:
//   1. let peers that have NO public listener discover each other's endpoint
//   2. act as the fallback relay if a direct tunnel cannot be formed
// It only ever moves sealed ChaCha20-Poly1305 blobs. It holds no key and can
// read nothing. Once the peers are introduced it drops out of the path.
const http = require('http');
const dgram = require('dgram');

const PORT = Number(process.argv[2] || 8802);
const endpoints = new Map();     // shortId -> { host, port }

function body(req) {
  return new Promise((res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => res(b));
  });
}

// genuinely forward one datagram and wait for the peer's reply
function forward(ep, packet, ms = 2500) {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    const done = (v) => { try { s.close(); } catch {} resolve(v); };
    const timer = setTimeout(() => done(null), ms);
    s.on('message', (buf) => {
      clearTimeout(timer);
      try { done(JSON.parse(buf.toString())); } catch { done(null); }
    });
    s.on('error', () => { clearTimeout(timer); done(null); });
    s.send(Buffer.from(JSON.stringify(packet)), ep.port, ep.host);
  });
}

const server = http.createServer(async (req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  const url = new URL(req.url, 'http://x');

  if (req.method === 'POST' && url.pathname === '/announce') {
    const d = JSON.parse(await body(req));
    endpoints.set(d.id, { host: d.host, port: d.port });
    return send(200, { ok: true });
  }

  if (req.method === 'GET' && url.pathname === '/lookup') {
    const e = endpoints.get(url.searchParams.get('id'));
    if (!e) return send(404, { error: 'unknown peer' });
    return send(200, e);
  }

  // fallback route: client -> rendezvous -> service -> rendezvous -> client
  if (req.method === 'POST' && url.pathname === '/relay') {
    const to = url.searchParams.get('to');
    const ep = endpoints.get(to);
    if (!ep) return send(404, { error: 'unknown peer' });
    const packet = JSON.parse(await body(req));
    const reply = await forward(ep, packet);
    if (!reply) return send(504, { error: 'peer did not answer' });
    return send(200, { hops: 2, reply });
  }

  send(404, { error: 'not found' });
});

server.listen(PORT, process.argv[3] || '127.0.0.1', () => {
  console.log(`#READY ${JSON.stringify({ plane: 'rendezvous', port: PORT })}`);
});
