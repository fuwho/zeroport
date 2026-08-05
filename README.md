# ZeroPort

### Zero ports. Zero trust. Zero blind spots.

A private network with **no listening port on the internet** — nothing to scan, flood or
exploit — where no single administrator can betray it, access expires on its own, and every
flow is bound to a cryptographic identity.

This repository is the **implementation**. Concept documents, the poster, the executive
summary and the presentation script are kept separately.

> **[zeroport.vercel.app](https://zeroport.vercel.app)** — an interactive explainer of the
> idea. It is a teaching tool and makes no network calls. The evidence is the code here.

---

## Run it

```bash
cd demo
node run-demo.js --slow      # six proofs, stops for a keypress before each
node dashboard/server.js     # live operations console at http://127.0.0.1:8080
```

No dependencies to install. Node 18+.

The console is not a mockup — it boots the real network and every button issues a real
command to a real agent process.

| | |
|---|---|
| [`demo/README.md`](demo/README.md) | full map of the implementation |
| [`demo/transcript.txt`](demo/transcript.txt) | captured output from a real run |
| [`demo/tor/`](demo/tor/) | real v3 onion service for the rendezvous plane |
| [`demo/wg/`](demo/wg/) | real WireGuard kernel data plane |
| [`demo/vps/`](demo/vps/) | second-host scripts (not yet run) |

## What is built and tested

| Component | Evidence |
|---|---|
| **BIP-340 Schnorr** identities on secp256k1 — the scheme Nostr uses | **15/15** against the official specification test vectors |
| **FROST threshold signing** — 2-of-3 officers emit ONE 64-byte signature that passes the ordinary verifier | **13/13** (2-of-3 and 3-of-5) |
| **Noise IK handshake** — WireGuard's own, with per-session forward secrecy and a replay window | **13/13** |
| **NIP-01 over WebSocket** — a real Nostr relay; RFC 6455 framing written from scratch | **12/12** |
| **Tor v3 onion service** — reached through real Tor circuits | **4/4** |
| **WireGuard kernel interface** — peers added and removed by threshold signatures | **3/3** on a live interface |
| **OpenTimestamps anchoring** — the audit head committed into Bitcoin | live |
| **Six-proof run** | **6 verdicts, 0 inconclusive** |

Every primitive is either Node's own audited implementation, or written against a published
specification and checked against that specification's own test vectors.

```bash
node test-noise.js
node test-nostr.js
node -e "const r=require('./lib/bip340').selftest(); console.log(r.filter(x=>x.ok).length+'/'+r.length)"
node -e "const r=require('./lib/frost').selftest();  console.log(r.filter(x=>x.ok).length+'/'+r.length)"
```

## The result worth dwelling on

WireGuard has no access control of its own — it forwards for whoever is in its peer list.
ZeroPort supplies the identity, quorum, policy, leases and revocation it lacks.

Against a real kernel interface: a roster signed by **two officers** put a real peer into the
Windows kernel; a revocation signed by **one officer** removed it; and a roster signed by a
**single share** was rejected as *invalid: signature verification failed*.

A lone administrator is not stopped by a policy check that could be misconfigured or
bypassed — the signature they are able to produce is not a valid signature at all. It cannot
be made to exist.

## What is not proven

- **No second host.** Everything runs on one machine, so NAT traversal is not exercised and
  there is no ping or throughput figure. The latency *ratio* in proof 2 is measured; the
  absolute milliseconds are loopback milliseconds, and the run says so itself.
- **A compromised endpoint remains compromised.** Its blast radius is bounded by per-port
  policy, short leases and auto-quarantine — not eliminated.
- **Scale.** A handful of nodes proves the mechanism, not the load of a national deployment.

## Layout

```
demo/          the implementation
  lib/         cryptography: bip340, frost, noise, socks, nostr, ws
  tor/         real onion service
  wg/          real WireGuard kernel bridge
  dashboard/   live operations console
  vps/         second-host scripts
index.html     the interactive explainer (deployed to Vercel)
```

## Status

A hackathon proposal with a working prototype. Not production software, and not audited.

*Independent proposal. Not an official Ministry of Interior publication.*
