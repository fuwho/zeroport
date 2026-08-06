'use strict';
// Real external anchoring via OpenTimestamps.
//
// The audit chain head (a 32-byte SHA-256) is submitted to independent public
// calendar servers, which return a timestamp proof that is later committed into
// the Bitcoin blockchain. Only the digest leaves the machine - never log
// contents - which is the whole point of a hash anchor.
//
// Why this matters: a hash chain alone proves nobody edited a line. It does NOT
// stop someone discarding the whole file and generating a fresh, internally
// consistent one. An anchor held by a third party who has no reason to lie for
// you is what makes that substitution detectable.
const fs = require('fs');

const CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://alice.btc.calendar.opentimestamps.org',
];

async function submit(digest32, timeoutMs = 8000) {
  if (!Buffer.isBuffer(digest32) || digest32.length !== 32)
    throw new Error('anchor expects a 32-byte digest');
  const attempts = [];
  for (const url of CALENDARS) {
    try {
      const r = await fetch(url + '/digest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', Accept: 'application/octet-stream' },
        body: digest32,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!r.ok) { attempts.push({ url, ok: false, status: r.status }); continue; }
      const proof = Buffer.from(await r.arrayBuffer());
      attempts.push({ url, ok: true, bytes: proof.length });
      return { ok: true, calendar: url, proof, submittedAt: new Date().toISOString(), attempts };
    } catch (e) {
      attempts.push({ url, ok: false, error: String(e.message || e).slice(0, 60) });
    }
  }
  return { ok: false, attempts };
}

// Persist the receipt next to the log so it can be checked later with the
// standard `ots` tool:  ots verify <file>.ots
function save(path, digest32, res) {
  if (!res.ok) return null;
  fs.writeFileSync(path + '.ots', res.proof);
  fs.writeFileSync(path + '.anchor.json', JSON.stringify({
    digest: digest32.toString('hex'),
    calendar: res.calendar,
    submittedAt: res.submittedAt,
    proofBytes: res.proof.length,
    verifyWith: `ots verify ${path}.ots`,
  }, null, 2));
  return path + '.ots';
}

module.exports = { submit, save, CALENDARS };
