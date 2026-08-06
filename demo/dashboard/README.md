# ZeroPort Operations Console

This is the fourth plane, and it is **not a mockup**.

```bash
node dashboard/server.js
```

then open **http://127.0.0.1:8080**

Starting the server starts the real network: the Nostr relay, the rendezvous plane and
three agents, each in its own operating-system process. Everything the page shows is read
from that running system.

## Why this matters

The page hosted at zeroport.vercel.app is a self-contained mockup — it makes no network
calls and proves nothing. This console is the opposite: **every number on it is measured
and every button issues a real command to a real agent process.**

If a judge asks "is this actually doing anything?", this is the answer.

## What is real on the screen

- **Signing authority** — the actual FROST 2-of-3 group public key generated at boot
- **Enrolled peers** — parsed from the roster event the relay is holding, after its
  threshold signature verifies
- **Peer identities** (`zp1…`) — real BIP-340 Schnorr identities, derived from real keys
- **The flow log** — tailed from the agent's hash-chained audit file on disk, showing the
  real cipher suite name and the real deny reasons
- **CHAIN INTACT / BROKEN** — an actual re-computation of every SHA-256 link, not a label

## What the buttons do

| Button | What actually happens |
|---|---|
| Connect alice → finance-db:5432 | A real Noise IK handshake and an encrypted round trip. The measured RTT is printed. |
| Try a port with no policy | Real request to `:22`; the agent's policy engine refuses it. |
| Unenrolled node attempts access | The rogue agent tries; its static key is not on the roster, so the handshake is dropped in silence. |
| Enrol with ONE officer | Publishes a roster signed by a single FROST share. The relay rejects it — *the signature is not valid for the group key at all.* |
| Enrol with TWO officers | The same roster, two shares combined into one signature. Accepted. |
| Issue a 6-second lease | A real short lease. Watch it expire on its own. |
| Revoke alice-laptop | A revocation event signed by one officer's individual key. |
| Verify audit chain | Recomputes the whole hash chain. |
| Tamper with the log | Edits one line on disk. The badge flips to BROKEN and names the line. |

## Verified working

Driven through a real browser on 5 August 2026:

- Connect → `ALLOWED - encrypted round trip 2.75 ms, reply "ACK:SELECT 1"`
- Unenrolled → `DENIED`, logged as *peer static key not on the signed roster*
- One officer → `REJECTED by the relay - "invalid: signature verification failed"`
- Tamper → `verifier CAUGHT IT - entry altered: hash mismatch at line 4`, badge went red
- The flow log showed `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` as the negotiated suite

## Presenting with it

Leave it open on a second screen while you run `run-demo.js --slow` on the first. The
terminal proves the mechanism step by step; the console shows the security team's view of
the same events as they happen.

Ctrl-C stops the server and kills every child process.

---

*Independent hackathon proposal. Not an official Ministry of Interior publication.*
