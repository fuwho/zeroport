'use strict';
// Enforces the one architectural rule this repo actually has: dependencies
// point inward. crypto knows nothing of domain, domain knows nothing of
// protocol, and nothing under src/ knows that apps/ or platform/ exist.
//
// This runs in CI so the layering cannot rot silently. It is deliberately
// dumb -- it reads require() strings, nothing more.
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Innermost first. A layer may import anything INNER to it (lower index).
// It may never import something outer -- that is the whole rule.
const LAYERS = ['crypto', 'domain', 'protocol', 'transport', 'nodes'];

const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  const p = path.join(dir, e.name);
  return e.isDirectory() ? walk(p) : p.endsWith('.js') ? [p] : [];
});

const violations = [];

for (const file of walk(path.join(ROOT, 'src'))) {
  const layer = path.relative(path.join(ROOT, 'src'), file).split(path.sep)[0];
  const rank = LAYERS.indexOf(layer);
  if (rank < 0) continue;
  const src = fs.readFileSync(file, 'utf8');
  const rel = path.relative(ROOT, file).replace(/\\/g, '/');

  for (const m of src.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    const spec = m[1];
    if (!spec.startsWith('.')) continue;                       // node stdlib

    // src/ must never reach into a delivery mechanism or an OS adapter.
    if (/(^|\/)(apps|platform)\//.test(spec)) {
      violations.push(`${rel} reaches outward into ${spec}`);
      continue;
    }
    const target = LAYERS.find((l) => spec.includes(`../${l}/`));
    if (!target) continue;
    if (LAYERS.indexOf(target) > rank) {
      violations.push(`${rel} (${layer}) imports ${target}/, which is further out`);
    }
  }
}

if (violations.length) {
  console.error('\n  DEPENDENCY RULE VIOLATED\n');
  violations.forEach((v) => console.error('   ' + v));
  console.error('');
  process.exit(1);
}
console.log(`  dependency rule: OK  (${LAYERS.join(' <- ')})`);
