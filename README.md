# ZeroPort

### Zero ports. Zero trust. Zero blind spots.

A private company network with **no listening port on the internet** — nothing to scan, flood, or exploit — operated from a single security-operations console, and built so **no single admin can betray it**.

> **[▶ Open the live demo](https://zeroport.vercel.app)** — click the six numbered proofs, or press Auto-play.

---

## The idea — four planes

| Plane | Built on | Role |
|---|---|---|
| **1 · Identity & Policy** | Nostr | Threshold-signed roster, per-peer/per-port policy, instant revocation |
| **2 · Rendezvous** | Tor onion service | Client-authorized meeting point for peers with no public address — seconds only, and the fallback |
| **3 · Transport** | WireGuard | Direct, hole-punched, encrypted tunnel at native speed; Tor drops out |
| **4 · Assurance & Operations** | Console + SIEM + verifier | Where the security team lives: enroll, policy, live topology, tamper-proof audit, kill switch |

Peers prove identity on the signed directory, meet through a client-authorized Tor onion for a few seconds, then hole-punch a direct WireGuard tunnel — Tor leaves the path and latency falls from ~384 ms to ~8 ms. Every flow is bound to a cryptographic identity and written to a hash-chained, publicly anchored audit log.

## The demo proves it — six clicks, ~six minutes

1. **Scan finds nothing, yet the link works** — no listening port on the internet.
2. **Path upgrades onion → direct, 384 ms → 8 ms** — rendezvous over Tor, then native-speed WireGuard.
3. **A lone admin can't enroll a rogue node** — enrollment needs a 2-of-3 quorum.
4. **An offline node loses access on its own** — leases expire; fail-closed by default.
5. **Unenrolled node refused; a live node revoked in seconds** — default-deny and instant revocation.
6. **One edited line and a swapped file both flagged** — hash-chained, publicly anchored audit log.

## Three "max-safe" guarantees

- **No single betrayal** — the roster authority is a 2-of-3 threshold (FROST) key.
- **Access expires** — short-lived leases; a lost or offline device loses access automatically.
- **Tamper-proof log** — hash-chained, publicly anchored, and mirrored to your SIEM.

## This repo

`index.html` is a self-contained, dependency-free interactive mockup of the ZeroPort operations console (the "Assurance & Operations" plane). It runs anywhere a static file can be served. Deployed on Vercel.

## Status

Concept + interactive MVP console for a hackathon. Not production software.
