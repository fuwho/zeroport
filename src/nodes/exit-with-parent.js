'use strict';
// Die when the process that started us dies.
//
// Every node here is spawned by a parent that holds it open - run-demo.js and
// the console server both use stdio ['pipe','pipe','pipe']. Nothing in that
// arrangement tells a child that its parent is gone, so an interrupted run
// leaves the whole set alive: a directory still holding 8801 and a rendezvous
// still holding 8802. The next `node apps/walkthrough/run-demo.js` then dies
// on EADDRINUSE before it prints a word, and the only cure is taskkill on a
// PID nobody wrote down. That is a miserable thing to hand someone who is
// just following the run instructions.
//
// The parent's death closes the write end of our stdin pipe, which reaches us
// as EOF. That is the signal - it costs nothing and needs no supervisor.
//
// The guard matters as much as the handler. Not every spawner gives us a
// pipe: test/nostr.test.js, platform/tor/test-onion.js and wg-proof.js all
// pass 'ignore', which hands the child NUL (or /dev/null), and reading that
// reports EOF within about two milliseconds. Wiring this up unconditionally
// would make those nodes exit before they ever finished starting. So we opt
// in only for a real pipe: Node models one as a net.Socket, while NUL, a
// redirected file and a closed descriptor all arrive as something else. A
// terminal is excluded too - tty.ReadStream extends net.Socket, and although
// a TTY never reports EOF until someone presses Ctrl-D, saying so explicitly
// keeps `node src/nodes/directory.js 8801` in a shell obviously safe.
const net = require('net');

function exitWithParent() {
  if (process.stdin.isTTY || !(process.stdin instanceof net.Socket)) return;
  process.stdin.resume();                      // EOF only arrives if we are reading
  process.stdin.on('end', () => process.exit(0));
  process.stdin.on('error', () => process.exit(0));   // pipe torn down mid-write
}

module.exports = { exitWithParent };
