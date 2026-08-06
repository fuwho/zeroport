'use strict';
// Every check in one command. Exits non-zero if anything fails, so CI and a
// reviewer get the same answer.
const { execFileSync } = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const run = (label, file) => {
  try {
    const out = execFileSync(process.execPath, [path.join(ROOT, file)], { encoding: 'utf8' });
    const m = out.match(/(\d+) passed, (\d+) failed/);
    if (m) {
      const ok = Number(m[2]) === 0;
      console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label.padEnd(26)} ${m[1]}/${Number(m[1]) + Number(m[2])}`);
      return ok;
    }
    console.log(`  PASS  ${label}`);
    return true;
  } catch (e) {
    console.log(`  FAIL  ${label}`);
    process.stdout.write((e.stdout || '') + (e.stderr || ''));
    return false;
  }
};

console.log('\n  ZeroPort test suite\n');

const bip = require(path.join(ROOT, 'src/crypto/bip340')).selftest();
const frost = require(path.join(ROOT, 'src/crypto/frost')).selftest();
const tally = (label, r) => {
  const p = r.filter((x) => x.ok).length;
  console.log(`  ${p === r.length ? 'PASS' : 'FAIL'}  ${label.padEnd(26)} ${p}/${r.length}`);
  r.filter((x) => !x.ok).forEach((x) => console.log(`         failed: ${x.name}`));
  return p === r.length;
};

const results = [
  tally('BIP-340 Schnorr', bip),
  tally('FROST threshold', frost),
  run('Noise IK handshake', 'test/noise.test.js'),
  run('NIP-01 over WebSocket', 'test/nostr.test.js'),
  run('dependency rule', 'test/dependency-rule.js'),
];

const failed = results.filter((r) => !r).length;
console.log(`\n  ${results.length - failed}/${results.length} suites passed\n`);
process.exit(failed ? 1 : 0);
