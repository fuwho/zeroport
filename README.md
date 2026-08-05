# ZeroPort

### Zero ports. Zero trust. Zero blind spots.

A private network with **no listening port on the internet** — nothing to scan, flood or
exploit — where no single administrator can betray it, access expires on its own, and every
flow is bound to a cryptographic identity.

> **[Interactive explainer →](https://zeroport.vercel.app)** — how it works, in four minutes.
> It is a teaching tool, not a live network. The working system is in [`demo/`](demo/).

---

## Two things in this repo, and they are different

| | What it is |
|---|---|
| **[zeroport.vercel.app](https://zeroport.vercel.app)** | An **interactive explainer**. Illustrates the mechanism — the paradox, the connection lifecycle, the three guarantees. It makes no network calls and proves nothing on its own. |
| **[`demo/`](demo/)** | The **working implementation**. Real cryptography, real sockets, real Tor, a real kernel tunnel. This is the evidence. |

Presenting the explainer as a live network would be a mistake — and unnecessary, because the
real thing runs from a terminal in about eleven seconds.

## The idea — four planes

| Plane | Built on | Role |
|---|---|---|
| **1 · Identity & Policy** | Nostr | Threshold-signed roster, per-peer/per-port policy, instant revocation |
| **2 · Rendezvous** | Tor onion service | Client-authorized meeting point for peers with no public address — seconds only |
| **3 · Transport** | WireGuard | Direct, encrypted tunnel at native speed; the rendezvous leaves the path |
| **4 · Assurance & Operations** | Console + verifier | Where the security team works: enrol, policy, live topology, tamper-evident audit, kill switch |

Peers prove identity on the signed directory, meet briefly through a client-authorized onion
service, then carry traffic over a direct encrypted tunnel. Every flow is attributed and
written to a hash-chained log whose head is anchored with an independent third party.

## What is actually built and tested

| Component | Evidence |
|---|---|
| **BIP-340 Schnorr** identities on secp256k1 — the exact scheme Nostr uses | **15/15** against the official specification test vectors |
| **FROST threshold signing** — 2-of-3 officers emit ONE 64-byte signature that passes the ordinary verifier | **13/13** (2-of-3 and 3-of-5) |
| **Noise IK handshake** — WireGuard's own, with per-session forward secrecy and a replay window | **13/13** |
| **NIP-01 over WebSocket** — a real Nostr relay; RFC 6455 framing written from scratch | **12/12** |
| **Tor v3 onion service** — the rendezvous plane, reached through real Tor circuits | **4/4** |
| **WireGuard kernel interface** — peers added and removed by threshold signatures | **3/3** on a live interface |
| **OpenTimestamps anchoring** — the audit head committed into Bitcoin | live |
| **Six-proof run** | **6 verdicts, 0 inconclusive** |

No third-party dependencies are installed for any of it. Every primitive is either Node's own
audited implementation, or written against a published specification and checked against that
specification's own test vectors.

## Documents

Presentation material lives in [`docs/`](docs/):

| File | What it is |
|---|---|
| [`executive-summary.pdf`](docs/executive-summary.pdf) | One page for judges — the problem, the innovation, what actually runs |
| [`poster.pdf`](docs/poster.pdf) | A4 poster |
| [`architecture.pdf`](docs/architecture.pdf) | The four planes and the connection upgrade |
| [`threat-model.pdf`](docs/threat-model.pdf) | How four architectures answer the same ten attacks |
| [`presentation-script.md`](docs/presentation-script.md) | The full talk track — idea to demo, with timings and Q&A |

## Run it

```bash
cd demo
node run-demo.js --slow      # six proofs, stops for a keypress before each
node dashboard/server.js     # live operations console at http://127.0.0.1:8080
```

The console is not a mockup: it boots the real network and every button issues a real command
to a real agent process. See [`demo/README.md`](demo/README.md) for the full map, and
[`demo/transcript.txt`](demo/transcript.txt) for captured output from a real run.

## The result worth dwelling on

WireGuard has no access control of its own — it forwards for whoever is in its peer list.
ZeroPort supplies the identity, quorum, policy, leases and revocation it lacks.

Run against a real kernel interface: a roster signed by **two officers** put a real peer into
the Windows kernel; a revocation signed by **one officer** removed it; and a roster signed by
a **single share** was rejected as *invalid: signature verification failed*.

That last point is the whole argument. A lone administrator is not stopped by a policy check
that could be misconfigured or bypassed — the signature they are able to produce is not a
valid signature at all. It cannot be made to exist.

## What is not proven

- **No second host.** Everything runs on one machine, so NAT traversal is not exercised and
  there is no ping or throughput figure. The latency *ratio* in proof 2 is measured; the
  absolute milliseconds are loopback milliseconds, and the run says so itself. Scripts for a
  second host are written and validated in [`demo/vps/`](demo/vps/).
- **A compromised endpoint remains compromised.** Its blast radius is bounded by per-port
  policy, short leases and auto-quarantine — not eliminated.
- **Scale.** A handful of nodes proves the mechanism, not the load of a national deployment.

## Status

A hackathon proposal with a working prototype. Not production software, and not audited.

*Independent proposal. Not an official Ministry of Interior publication.*
