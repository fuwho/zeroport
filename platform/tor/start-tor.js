'use strict';
// Start a real Tor daemon with a real v3 onion service in front of the
// ZeroPort rendezvous plane.
//
// This replaces the stand-in rendezvous with the genuine article: the service
// gets a .onion address, it never binds a public port, and peers reach it
// through the Tor network over SOCKS.
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const TOR_EXE = process.env.TOR_EXE ||
  path.join(os.homedir(), 'OneDrive', 'Desktop', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe');

const HERE = __dirname;
const DATA = path.join(HERE, 'data');
const HS = path.join(HERE, 'hs');
const TORRC = path.join(HERE, 'torrc');

const SOCKS_PORT = Number(process.env.ZP_SOCKS_PORT || 9250);
const CONTROL_FREE = true;

const fwd = (p) => p.replace(/\\/g, '/');

function writeTorrc(targetPort, targetHost) {
  fs.mkdirSync(DATA, { recursive: true });
  fs.mkdirSync(HS, { recursive: true });
  const rc = [
    `SocksPort ${SOCKS_PORT}`,
    `DataDirectory ${fwd(DATA)}`,
    `HiddenServiceDir ${fwd(HS)}`,
    `HiddenServicePort 80 ${targetHost || '127.0.0.1'}:${targetPort}`,
    'Log notice stdout',
    'ClientOnly 0',
  ].join('\n') + '\n';
  fs.writeFileSync(TORRC, rc);
  return TORRC;
}

// Resolve when Tor has bootstrapped AND published the onion hostname.
function start(targetPort, { onLog, timeoutMs = 180000, host } = {}) {
  if (!fs.existsSync(TOR_EXE)) {
    return Promise.reject(new Error(
      `tor.exe not found at:\n  ${TOR_EXE}\nSet TOR_EXE to its full path.`));
  }
  writeTorrc(targetPort, host);

  return new Promise((resolve, reject) => {
    const proc = spawn(TOR_EXE, ['-f', TORRC], { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false, lastPct = -1;
    const t = setTimeout(() => {
      if (!done) { done = true; try { proc.kill(); } catch {} reject(new Error('Tor did not bootstrap in time')); }
    }, timeoutMs);

    const finish = () => {
      const f = path.join(HS, 'hostname');
      if (!fs.existsSync(f)) return false;
      const onion = fs.readFileSync(f, 'utf8').trim();
      if (!onion) return false;
      done = true; clearTimeout(t);
      resolve({ onion, socksPort: SOCKS_PORT, proc, stop: () => { try { proc.kill(); } catch {} } });
      return true;
    };

    proc.stdout.on('data', (d) => {
      const s = d.toString();
      if (onLog) onLog(s.trim());
      const m = s.match(/Bootstrapped (\d+)%/);
      if (m) {
        const pct = Number(m[1]);
        if (pct !== lastPct) { lastPct = pct; if (onLog) onLog(`bootstrap ${pct}%`); }
        if (pct === 100 && !done) {
          // the hostname file appears at or just after 100%
          let tries = 0;
          const poll = setInterval(() => {
            if (done || finish() || ++tries > 40) clearInterval(poll);
          }, 250);
        }
      }
    });
    proc.stderr.on('data', (d) => { if (onLog) onLog('[tor] ' + d.toString().trim()); });
    proc.on('exit', (code) => {
      if (!done) { done = true; clearTimeout(t); reject(new Error('Tor exited early with code ' + code)); }
    });
  });
}

module.exports = { start, TOR_EXE, SOCKS_PORT, HS };

// CLI:  node tor/start-tor.js [targetPort]
if (require.main === module) {
  const target = Number(process.argv[2] || 8802);
  console.log('  tor binary :', TOR_EXE);
  console.log('  forwarding : onion:80  ->  127.0.0.1:' + target);
  console.log('  starting Tor (first bootstrap can take a minute)...\n');
  start(target, { onLog: (l) => { if (/bootstrap|Opening|error|warn/i.test(l)) console.log('   ', l); } })
    .then((r) => {
      console.log('\n  ONION SERVICE LIVE');
      console.log('  address    : http://' + r.onion);
      console.log('  socks port : ' + r.socksPort);
      console.log('\n  Ctrl-C to stop.\n');
      process.on('SIGINT', () => { r.stop(); process.exit(0); });
    })
    .catch((e) => { console.error('\n  FAILED:', e.message, '\n'); process.exit(1); });
}
