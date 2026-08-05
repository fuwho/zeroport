'use strict';
// Minimal SOCKS5 client (RFC 1928) - just enough to reach a .onion address
// through Tor. Node has no SOCKS support, and .onion names do not resolve in
// DNS, so the hostname must be handed to Tor as a DOMAIN address and resolved
// inside the Tor network.
const net = require('net');

function connect({ socksHost = '127.0.0.1', socksPort, host, port, timeout = 30000 }) {
  return new Promise((resolve, reject) => {
    const s = net.connect(socksPort, socksHost);
    let stage = 0;
    const fail = (e) => { s.destroy(); reject(e instanceof Error ? e : new Error(e)); };
    const t = setTimeout(() => fail('SOCKS timeout'), timeout);

    s.once('error', fail);
    s.on('connect', () => s.write(Buffer.from([0x05, 0x01, 0x00])));  // v5, 1 method, no auth

    s.on('data', (d) => {
      if (stage === 0) {
        if (d[0] !== 0x05 || d[1] !== 0x00) return fail('SOCKS handshake refused');
        const h = Buffer.from(host);
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h,
          Buffer.from([(port >> 8) & 0xff, port & 0xff]),
        ]);
        stage = 1;
        return s.write(req);
      }
      if (stage === 1) {
        if (d[0] !== 0x05) return fail('bad SOCKS reply');
        if (d[1] !== 0x00) {
          const why = {
            1: 'general failure', 2: 'connection not allowed', 3: 'network unreachable',
            4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
            7: 'command not supported', 8: 'address type not supported',
          }[d[1]] || ('code ' + d[1]);
          return fail('SOCKS connect failed: ' + why);
        }
        clearTimeout(t);
        stage = 2;
        s.removeListener('error', fail);
        return resolve(s);            // socket is now a tunnel to host:port
      }
    });
  });
}

// Decode HTTP/1.1 chunked transfer encoding.
function dechunk(s) {
  let out = '', i = 0;
  while (i < s.length) {
    const nl = s.indexOf('\r\n', i);
    if (nl < 0) break;
    const size = parseInt(s.slice(i, nl).trim(), 16);
    if (!Number.isFinite(size) || size <= 0) break;      // 0 terminates the body
    out += s.slice(nl + 2, nl + 2 + size);
    i = nl + 2 + size + 2;                               // skip the trailing CRLF
  }
  return out;
}

// A tiny HTTP client over a SOCKS tunnel. Enough for the rendezvous protocol.
async function request({ socksPort, host, port = 80, method = 'GET', path = '/', body = null, timeout = 40000 }) {
  const sock = await connect({ socksPort, host, port, timeout });
  return new Promise((resolve, reject) => {
    let raw = Buffer.alloc(0);
    const t = setTimeout(() => { sock.destroy(); reject(new Error('HTTP timeout over Tor')); }, timeout);

    sock.on('data', (d) => { raw = Buffer.concat([raw, d]); });
    sock.on('error', (e) => { clearTimeout(t); reject(e); });
    sock.on('end', () => {
      clearTimeout(t);
      const s = raw.toString();
      const i = s.indexOf('\r\n\r\n');
      if (i < 0) return reject(new Error('malformed HTTP response'));
      const head = s.slice(0, i);
      let payloadText = s.slice(i + 4);
      // Node's http server omits Content-Length and uses chunked framing, so
      // the body arrives as: <hex-size>CRLF<data>CRLF ... 0CRLFCRLF
      if (/transfer-encoding:\s*chunked/i.test(head)) payloadText = dechunk(payloadText);
      resolve({ status: Number((head.match(/HTTP\/1\.[01] (\d+)/) || [])[1] || 0), body: payloadText });
    });

    const payload = body ? Buffer.from(body) : null;
    const head =
      `${method} ${path} HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      'Connection: close\r\n' +
      (payload ? `Content-Length: ${payload.length}\r\nContent-Type: application/json\r\n` : '') +
      '\r\n';
    sock.write(head);
    if (payload) sock.write(payload);
  });
}

module.exports = { connect, request };
