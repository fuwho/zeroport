'use strict';
// Minimal RFC 6455 WebSocket server - enough to speak real NIP-01, no deps.
// Node ships a WebSocket *client* but no server, so the framing is done here.
const crypto = require('crypto');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const acceptKey = (k) => crypto.createHash('sha1').update(k + GUID).digest('base64');

function frame(payload, opcode = 0x1) {
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

function makeConn(socket) {
  const handlers = { message: [], close: [] };
  let buf = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      let mask;
      if (masked) { if (buf.length < off + 4) return; mask = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + len) return;                 // frame not complete yet

      const payload = Buffer.from(buf.subarray(off, off + len));
      if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      buf = buf.subarray(off + len);

      if (opcode === 0x8) { try { socket.end(frame(Buffer.alloc(0), 0x8)); } catch {} handlers.close.forEach((h) => h()); return; }
      if (opcode === 0x9) { socket.write(frame(payload, 0xa)); continue; }   // ping -> pong
      if (opcode === 0x1) handlers.message.forEach((h) => h(payload.toString()));
    }
  });
  socket.on('error', () => handlers.close.forEach((h) => h()));
  socket.on('close', () => handlers.close.forEach((h) => h()));

  return {
    on: (ev, fn) => handlers[ev] && handlers[ev].push(fn),
    send: (text) => { try { socket.write(frame(Buffer.from(text))); } catch {} },
    close: () => { try { socket.end(frame(Buffer.alloc(0), 0x8)); } catch {} },
  };
}

// attach to an http.Server
function attach(server, onConnection) {
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`);
    onConnection(makeConn(socket));
  });
}

module.exports = { attach, frame, acceptKey };
