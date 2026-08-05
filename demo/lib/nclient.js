'use strict';
// Minimal NIP-01 client over Node's built-in WebSocket.
// Used by the agents to fetch and watch the signed roster.

function connect(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const subs = new Map();          // subId -> { onEvent, onEose }
    const okWaiters = new Map();     // eventId -> resolver
    const t = setTimeout(() => reject(new Error('relay connect timeout')), timeoutMs);

    ws.addEventListener('error', (e) => { clearTimeout(t); reject(new Error('relay connection failed')); });
    ws.addEventListener('message', (e) => {
      let m; try { m = JSON.parse(e.data); } catch { return; }
      if (m[0] === 'EVENT') { const h = subs.get(m[1]); if (h) h.onEvent(m[2]); }
      else if (m[0] === 'EOSE') { const h = subs.get(m[1]); if (h && h.onEose) h.onEose(); }
      else if (m[0] === 'OK') { const w = okWaiters.get(m[1]); if (w) { okWaiters.delete(m[1]); w({ ok: m[2], message: m[3] }); } }
    });

    ws.addEventListener('open', () => {
      clearTimeout(t);
      resolve({
        publish: (ev) => new Promise((r) => {
          okWaiters.set(ev.id, r);
          ws.send(JSON.stringify(['EVENT', ev]));
          setTimeout(() => { okWaiters.delete(ev.id); r({ ok: false, message: 'no response' }); }, 3000);
        }),
        query: (filter) => new Promise((r) => {
          const sid = 'q' + Math.random().toString(36).slice(2, 9);
          const got = [];
          const done = () => { subs.delete(sid); try { ws.send(JSON.stringify(['CLOSE', sid])); } catch {} r(got); };
          subs.set(sid, { onEvent: (ev) => got.push(ev), onEose: done });
          ws.send(JSON.stringify(['REQ', sid, filter]));
          setTimeout(done, 3000);
        }),
        close: () => { try { ws.close(); } catch {} },
      });
    });
  });
}

module.exports = { connect };
