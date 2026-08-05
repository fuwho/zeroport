'use strict';
// Harness: verify the --slow keypress gate really blocks and really advances.
// Pretends stdin is a terminal, then presses ENTER each time a prompt appears.
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const shim = path.join(__dirname, '.tty-shim.js');
fs.writeFileSync(shim, 'try{Object.defineProperty(process.stdin,"isTTY",{value:true,configurable:true});}catch(e){}\n');

const p = spawn(process.execPath, ['--require', shim, path.join(__dirname, 'run-demo.js'), '--slow'],
  { stdio: ['pipe', 'pipe', 'inherit'] });

let prompts = 0, buf = '', lastPromptAt = 0;
p.stdout.on('data', (d) => {
  const s = d.toString();
  buf += s;
  process.stdout.write(s);
  if (s.includes('ENTER to continue')) {
    prompts++;
    lastPromptAt = Date.now();
    // deliberately wait, to prove the run is genuinely blocked on the key
    setTimeout(() => p.stdin.write('\n'), 600);
  }
});

p.on('exit', (code) => {
  fs.unlinkSync(shim);
  const ideas = (buf.match(/The idea:/g) || []).length;
  const inconclusive = (buf.match(/INCONCLUSIVE/g) || []).length;
  console.log('\n================ HARNESS RESULT ================');
  console.log('exit code        :', code);
  console.log('keypress prompts :', prompts, '(expected 6)');
  console.log('teaching lines   :', ideas, '(expected 6)');
  console.log('inconclusive     :', inconclusive, '(expected 0)');
  const ok = code === 0 && prompts === 6 && ideas === 6 && inconclusive === 0;
  console.log(ok ? 'PASS - the gate blocks and advances correctly' : 'FAIL');
  process.exit(ok ? 0 : 1);
});
