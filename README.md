# ZeroPort

**Zero ports. Zero trust. Zero blind spots.**

A private network with no listening port on the internet — nothing to scan, flood or exploit — where no single administrator can betray it, access expires on its own, and every flow is bound to a cryptographic identity.

Interactive explainer: **[zeroport.vercel.app](https://zeroport.vercel.app)**

> The site explains the mechanism and makes no network calls. This repository is the working implementation. Presentation material, the concept documents and the run instructions live in the project's Drive, not here.

## Run it

Node 18 or newer. **There is nothing to install.**

```bash
git clone https://github.com/fuwho/zeroport.git && cd zeroport
npm run console      # browser console at http://127.0.0.1:8080
npm run demo         # same six steps, in the terminal
npm test             # every suite
```

Both apps do the same real work: five processes, real sockets, real cryptography.

## Layout

```
src/          the implementation. dependencies point inward, only.
  crypto/       BIP-340 Schnorr, FROST, Noise IK      (Node stdlib only)
  domain/       identity, roster, policy, audit chain (-> crypto)
  protocol/     NIP-01 event build and verify         (-> crypto)
  transport/    WebSocket, SOCKS5, relay client, OpenTimestamps
  nodes/        agent, directory, rendezvous — the runnable processes

apps/         delivery mechanisms. own no logic.
  walkthrough/  the terminal walkthrough
  console/      the browser console

platform/     OS-specific adapters, swappable
  tor/  wireguard/  vps/

test/         suites, plus the dependency-rule check
index.html    the deployed page — Vercel serves the repo root
```

`npm run check:layers` fails if anything under `src/` imports outward. A layering that is not enforced is a layering that rots.

## What is built, and tested

No third-party dependencies. Every primitive is written from its specification against Node's standard library, which is the point — a reviewer can read all of it.

| Component | Evidence |
| :-- | :-- |
| BIP-340 Schnorr on secp256k1 — the scheme Nostr uses | **15/15** against the specification's own test vectors |
| FROST threshold signing — 2-of-3 emit ONE valid signature | **13/13** (2-of-3 and 3-of-5) |
| Noise IK handshake — WireGuard's own, forward secrecy + replay window | **13/13** |
| NIP-01 over WebSocket — a real relay, roster as a signed event | **12/12** |
| Tor v3 onion rendezvous — over real circuits | **4/4** (opt-in, `--tor`) |
| WireGuard kernel interface — peers controlled by threshold signatures | **3/3** on a real interface |
| OpenTimestamps anchoring — audit head committed into Bitcoin | live |

The strongest single result: **WireGuard has no access control of its own.** ZeroPort supplies the identity, quorum, policy, leases and revocation it lacks. A roster signed by two officers puts a real peer into the Windows kernel; a revocation signed by one removes it; a roster signed by a single share is rejected and the kernel never hears about it.

```bash
node platform/wireguard/wg-proof.js      # requires Administrator
```

## What is not proven

- **No second host.** Everything runs on one machine, so NAT traversal is not exercised and there is no ping or throughput figure. The latency *ratio* is measured; the absolute milliseconds are loopback. Provisioning scripts for a second host are in `platform/vps/` and have not been run.
- **A compromised endpoint stays compromised.** Per-port policy, short leases and revocation bound the blast radius; they do not eliminate it.
- **Scale.** A handful of nodes proves the mechanism, not national load.

## Licence

MIT — see [LICENSE](LICENSE).

*Independent hackathon proposal. Not an official Ministry of Interior publication.*
