# ZeroPort — guided walkthrough

A real, working implementation of the ZeroPort protocol. Not an animation.

Requires Node 18+ and **no dependencies at all**.

## Running it

```bash
node run-demo.js --slow
```

| Command | Behaviour | Use it for |
|---|---|---|
| `node run-demo.js` | straight through, ~11 s | verifying it still passes; a fast backup recording |
| `node run-demo.js --slow` | **presentation pace** — stops before each step and waits for a key | presenting on stage |
| `node run-demo.js --slow --no-pause` | slow pacing but never waits for a key, ~32 s | recording an unattended backup video |

At a pause, **ENTER** advances and **q** (or Ctrl-C) stops cleanly and kills the child processes.

> If stdin is not a terminal — piped, redirected, or CI — the keypress gate disables itself
> automatically, so the run can never hang. `run-demo.js --slow > out.txt` is safe.

**On stage:** the run prints `ready for STEP n of 6` and waits. It explains each step
itself, so your job is the context a judge needs — then press ENTER and let the output land.

It binds to this machine's network interface by default, so the scan targets a real network
address. `--local` forces loopback; `--host <ip>` binds somewhere specific.

`node test-tty.js` is a harness that simulates a terminal and asserts the gate really
blocks and really advances (6 prompts, 6 teaching lines).

---

## What is genuinely real here

| Element | Implementation | Tests |
|---|---|---|
| Node identity | **Real BIP-340 Schnorr over secp256k1** — the exact scheme Nostr uses | **15/15** official spec vectors |
| SOC quorum | **Real FROST threshold Schnorr.** 2-of-3 officers hold shares of ONE key and jointly produce ONE 64-byte signature that passes the *ordinary* BIP-340 verifier. A lone officer cannot produce a valid signature **at all** | **13/13** (2-of-3 and 3-of-5) |
| Control plane | **Real Nostr relay speaking NIP-01 over WebSocket** (RFC 6455 framing written from scratch — Node has no WS server). The roster is a signed, replaceable Nostr event | **12/12** |
| Handshake | **Real Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s** — WireGuard's own handshake, from the whitepaper | **13/13** |
| Forward secrecy | Fresh ephemeral X25519 keypair **per handshake**; an old session key cannot decrypt a new session | asserted |
| Replay protection | Encrypted **TAI64N** timestamp, strictly increasing per peer | asserted |
| Tunnel encryption | **ChaCha20-Poly1305** AEAD, 64-bit counter nonces | — |
| External anchoring | **Real OpenTimestamps submission.** The chain head is witnessed by independent public calendar servers and committed into Bitcoin. Verify later with `ots verify audit-finance-db.log.ots` | live |
| Transport | Real **UDP sockets**, five separate OS processes | — |
| Policy engine | Real default-deny: roster membership, revocation, lease expiry, per-port rule | — |
| Audit log | Real **SHA-256 hash chain** | — |
| Port scan | Real TCP connect scan | — |

**The authority model is enforced by mathematics, not by counting.** The roster is signed
by the FROST group key, so a single BIP-340 verification *is* the quorum check — an agent
never counts signatures and cannot be fooled by a counting bug. A revocation is signed by
one officer's individual key, so removing access stays deliberately easier than granting it.

## What is still substituted, and why

Only one thing remains, and it needs hardware rather than code:

- **No second host.** Everything runs on one machine, so NAT traversal is not exercised,
  and there is no ping or throughput figure. The *ratio* between the two routes in proof 2
  is real and measured; the absolute milliseconds are loopback milliseconds, and the run
  says so itself. One more host — a laptop, a VM, or a low-cost VPS — makes the identical
  code carry real IP traffic. Scripts for that are written and validated in `vps/`.

Everything else is now the genuine article:

- **Tor onion routing is real.** `tor/test-onion.js` — 4/4. The rendezvous plane runs
  behind a real v3 onion service, reached through real Tor circuits. See `tor/README.md`.
- **The WireGuard data plane is real.** `wg/wg-proof.js` — a real kernel interface whose
  peer list is controlled by threshold signatures. See `wg/README.md`.
- **The console is real.** `dashboard/server.js` — every panel is live data from the
  running network and every button issues a real agent command. See `dashboard/README.md`.
  *(The page hosted at zeroport.vercel.app is a static mockup and proves nothing — do not
  confuse the two.)*

## The six steps

1. **The door that isn't there.** A real TCP scan of the service finds nothing; an
   unauthenticated packet is dropped without a reply; then an enrolled peer connects and
   exchanges encrypted data.
2. **How two machines meet when neither can be called.** The same sealed packet travels via
   the rendezvous and then directly, so the introduction and the conversation are visibly
   separate things.
3. **Who is allowed to change the guest list.** One officer's roster is refused — the thing
   they can produce is not a valid signature for the group key. Two officers succeed.
4. **What happens to a laptop that is stolen.** A short lease is issued, then nobody renews
   it and nobody revokes anything. Access ends on its own.
5. **The two ways in that do not work.** An uninvited machine, and an invited machine
   reaching for a port it was never granted. Then one officer removes a live peer.
6. **The record of what happened.** An edited line breaks the chain; a wholly replaced file
   is internally consistent but fails against the head published outside.

## A note on the deny messages

An attacker is told nothing — denied packets are dropped silently, so the client only ever sees `no response (dropped)`. The **defender's** log records the exact reason. The run prints both side by side, which is the whole visibility argument in one line.

## Files

| File | Role |
|---|---|
| `lib/zp.js` | crypto primitives, roster rules, hash-chained log |
| `nostr-relay.js` | Plane 1 — real NIP-01 relay over WebSocket |
| `lib/bip340.js` | BIP-340 Schnorr (spec vectors in `selftest()`) |
| `lib/frost.js` | FROST threshold Schnorr |
| `lib/noise.js` | Noise IK handshake |
| `lib/ws.js` / `lib/nclient.js` | WebSocket server / Nostr client |
| `lib/anchor.js` | OpenTimestamps anchoring |
| `rendezvous.js` | Plane 2 — rendezvous / fallback relay |
| `agent.js` | the node agent: one UDP socket, zero TCP listeners |
| `run-demo.js` | orchestrator and the six proofs |
| `audit-*.log` | hash-chained audit logs written during a run |
| `tor/` | real v3 onion service for the rendezvous plane |
| `wg/` | real WireGuard kernel data plane |
| `dashboard/` | the live operations console |
| `vps/` | second-host scripts (not yet run) |
| `lib/socks.js` | SOCKS5 client so Node can reach .onion addresses |
