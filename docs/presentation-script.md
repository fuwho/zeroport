# ZeroPort — presentation script

Everything from the idea to the demo. Written to be spoken, not read out.

**Golden rule:** the terminal is the proof, the website is the explanation. Never present the
website as a live network. You do not need to — the real thing runs in eleven seconds.

---

## Before you speak — 5 minute setup

1. **Terminal 1**, large font, dark background:
   ```
   cd C:\Users\stnal\Projects\zeroport\demo
   node run-demo.js --slow
   ```
   It prints the banner and waits at *"ready for PROOF 1 of 6"*. **Leave it there.**

2. **Terminal 2** (if you have a second screen):
   ```
   node dashboard/server.js
   ```
   Open `http://127.0.0.1:8080`.

3. **Browser tab** on `zeroport.vercel.app` — only if you want the visual explainer.

4. Have `docs/executive-summary.pdf` printed, one per judge.

5. Silence notifications. Close everything else.

**If anything fails on the night:** `demo/transcript.txt` is a captured real run. Show that
and say plainly that you are showing a recording. Never fake a live result.

---

## THE SCRIPT — 6 minutes

### 0:00 · The problem (40 seconds)

*[Stand still. No screen yet. Say this slowly.]*

> "To defend a network today, we first have to expose one.
>
> Every VPN gateway, every firewall, every bastion host has to sit on a public address and
> listen. And anything that listens can be found. Attackers scan the entire internet in
> minutes — they map what answers, fingerprint it, flood it, and exploit it before a patch
> exists.
>
> The commercial answer to this is zero-trust, and it works — but it moves the control plane
> into a vendor's cloud. A cloud we don't own, can't audit, and can't keep inside the Kingdom.
>
> So we asked a different question. Not *how do we guard the door better* — but **why is
> there a door at all?**"

*[Pause.]*

---

### 0:40 · The idea (60 seconds)

*[Now show the architecture diagram — `docs/architecture.pdf` — or the explainer site.]*

> "ZeroPort removes the door. Nothing listens on the internet. There is no address to scan.
>
> It works in four steps.
>
> **One — identify.** Every device carries a cryptographic identity on a signed directory.
> Not a password, not a certificate from a vendor: a key.
>
> **Two — meet.** Two machines that both have no public address still need to find each
> other. They meet for a few seconds through a Tor onion service — an address derived from
> its own key, which nobody assigned and nobody can scan for.
>
> **Three — connect.** Once introduced, they open a direct encrypted tunnel, and the
> middleman drops out of the path completely. Full speed, no third party.
>
> **Four — govern.** Every flow is authorized by policy, attributed to a named identity, and
> written to a log that cannot be quietly rewritten.
>
> The result: nothing to scan, and a security team that reads names instead of guessing at
> IP addresses."

---

### 1:40 · The proof begins (20 seconds)

*[Switch to Terminal 1. This is the moment the pitch changes gear.]*

> "That's the idea. Now I'd rather show you than tell you.
>
> What you're about to see is not a video and not a mockup. It starts five real processes —
> a real relay, a real rendezvous, and three agents — and proves six things against them.
> Every number on this screen is measured."

*[Press ENTER.]*

---

### 2:00 · PROOF 1 — nothing to scan (30 seconds)

*[Let the output land, then read the result.]*

> "First, a real port scan of the protected service. Thirty-seven ports — nothing open.
> Then I fire an unauthenticated packet straight at the agent: no reply at all, silently
> dropped.
>
> And then the authorized peer connects, completes a handshake, and exchanges encrypted
> data.
>
> A scanner finds no way in. Reachability here is a property of holding a key, not of an
> open port."

*[ENTER.]*

---

### 2:30 · PROOF 2 — the path upgrade (30 seconds)

> "The same sealed packet, sent two ways. Through the rendezvous — two hops. Then directly —
> one hop, and measurably faster.
>
> I'll be straight with you about this number: everything here runs on one laptop, so these
> are loopback milliseconds. The *ratio* is real and measured; the absolute figures are not
> wide-area figures. Over the internet the gap is far wider, because the first path is a Tor
> circuit and the second is a single hop."

*[ENTER. — Saying this before a judge asks buys you enormous credibility.]*

---

### 3:00 · PROOF 3 — no single administrator (40 seconds)

*[This is your strongest moment. Slow down.]*

> "Now the one I care about most.
>
> A single officer signs a roster that adds a rogue node. Watch — **rejected**. *Invalid
> signature.*
>
> And this is the important part: it was not refused by a policy check that someone could
> misconfigure, or disable, or be pressured into bypassing. The signing key is split across
> three officers. The signature a lone officer is able to produce **is not a valid signature
> for the group key at all.** It cannot be made to exist.
>
> Now two officers co-sign — and their shares combine into a single signature. Accepted.
>
> No single administrator can betray this network. Not because we told them not to. Because
> the mathematics won't let them."

*[ENTER.]*

---

### 3:40 · PROOF 4 — access expires (25 seconds)

> "Access here is a short lease, not a membership. I issue one, the connection works.
>
> Now four seconds pass. Nobody touches the console. Nobody presses revoke — and it's
> refused.
>
> That's a stolen laptop, switched off in a bag. It loses its access on its own. The default
> state of this network is *no access*; you have to keep earning it."

*[ENTER.]*

---

### 4:05 · PROOFS 5 & 6 — default deny and the audit (40 seconds)

> "An unenrolled node tries: refused and logged. A port with no policy rule: refused. Then
> one officer revokes a live device — and it's dead.
>
> Notice what the attacker sees: *no response*. Nothing. We tell them nothing. But the
> defender's log records the exact reason — *peer revoked*. That's the whole visibility
> argument in one line.
>
> Finally I tamper with the audit log. One edited line breaks the chain. And when the
> attacker gives up and replaces the whole file with a clean one — that fails too, because
> the chain head is published to an independent timestamp service. A fabricated history no
> longer matches the public record."

---

### 4:45 · What is actually real (40 seconds)

*[Turn back to the judges. This is the credibility close.]*

> "So that you know exactly what you just watched:
>
> The identities are real BIP-340 Schnorr — the same scheme Nostr uses — checked against the
> specification's own test vectors, fifteen of fifteen. The quorum is real FROST threshold
> signing. The handshake is WireGuard's own Noise protocol, with forward secrecy and a replay
> window. The rendezvous is a real Tor onion service — I published one and read data back
> through real Tor circuits. The audit head is anchored into Bitcoin through OpenTimestamps.
>
> And it drives a **real WireGuard interface in the Windows kernel.** WireGuard has no access
> control of its own — it forwards for whoever is in its peer list. ZeroPort supplies the
> identity, the quorum, the policy and the revocation it lacks.
>
> Two officers signed, and a peer appeared in the kernel. One officer revoked, and it was
> gone. A forged roster was rejected, and the kernel never heard about it."

---

### 5:25 · The limits (20 seconds)

> "Three things I am not claiming.
>
> Everything runs on one machine, so I have not shown you NAT traversal or a real ping —
> that needs a second host, and the scripts for it are written.
>
> A compromised endpoint is still compromised. We bound the blast radius with per-port
> policy and short leases; we don't eliminate it.
>
> And the website is an explainer, not a live network. The terminal is the evidence."

---

### 5:45 · Close (15 seconds)

> "For the Ministry, this means directorates and border posts connected with no public
> surface to attack. Officer devices whose access dies with the device. Critical systems
> reachable only by enrolled, policy-authorized nodes — every access attributed. And relays
> hosted inside the Kingdom, with no foreign coordinator.
>
> Zero ports. Zero trust. Zero blind spots.
>
> Thank you — I'm happy to take it apart for you."

---

## If you only get 60 seconds

> "Every system we defend has to expose a door to the internet, and anything that listens can
> be scanned and exploited. ZeroPort removes the door — nothing listens, so a scan returns
> nothing, yet authorized officers connect instantly over tunnels bound to a cryptographic
> identity.
>
> No single administrator can betray it: the signing key is split three ways, and one
> officer's signature is not merely refused — it is not a valid signature at all. Access
> expires by itself if a device is lost. Every action lands in a log that cannot be rewritten.
>
> It's implemented and tested — real Schnorr identities, real threshold signatures, a real Tor
> onion service, and a real WireGuard kernel tunnel. I can run it for you in eleven seconds."

---

## The optional finale — if you have a projector and 2 more minutes

*[Elevated PowerShell. Only do this if you have rehearsed it.]*

```
cd demo\wg
.\zp-wg-setup.ps1
node wg-proof.js
```

> "This is a real WireGuard interface in the Windows kernel. Watch the peer list.
>
> Two officers sign — a peer appears. One officer revokes — it's gone. Not firewalled off:
> gone. And a roster signed by a single share is rejected, so the kernel never hears about it.
>
> The kernel now holds a peer that exists only because two officers signed for it."

*[Afterwards: `.\zp-wg-teardown.ps1`]*

---

## Questions they will ask

**"Is this real or a mockup?"**
> "The website is an explainer — I'll say that plainly. The protocol underneath is real and
> I just ran it. Real BIP-340 Schnorr validated against the specification's test vectors,
> real FROST threshold signatures, WireGuard's own handshake, a real onion service, and a
> real kernel interface."

**"Isn't this just a VPN?"**
> "A VPN concentrator has to listen on a public IP — that's the exact thing we remove. And we
> bind every flow to an identity, which a VPN tunnel doesn't."

**"Is it port-knocking?"**
> "Stronger. Port-knocking and single-packet authorization still need a daemon listening to
> receive the knock — there's still a surface, and still a packet to replay or fuzz. We have
> no listening surface at all."

**"How do you know the cryptography is correct?"**
> "It's checked against published test vectors — fifteen of fifteen for BIP-340. Building it
> also caught three real bugs, including an emergency revocation that the control plane
> accepted but the enforcement point rejected, so a revoked device kept its access. The tests
> earned their keep."

**"Show me it carrying real traffic."**
> "Not on one machine — there's no second endpoint, so there's no ping and no throughput
> number, and I won't pretend otherwise. Add one more host and the same code carries real IP
> packets. What I can show you is that the kernel's peer list is controlled by a threshold
> signature."

**"What about Tor being slow, or blocked?"**
> "Tor is used for seconds, only for the introduction — bulk traffic never touches it. And
> there are three independent bootstrap paths: LAN discovery, a self-hosted relay, and the
> onion service. Any one is enough."

**"What does it cost?"**
> "The infrastructure is nearly free — a few small relay servers. There's no per-seat
> licensing, which is the dominant cost of commercial zero-trust at national scale."

**"What's still not solved?"** *(volunteer this before they ask)*
> "A compromised endpoint is still compromised. Direct tunnels expose peer IPs to an
> observer, which is why sensitive flows can be pinned to the slower path. And the whole
> design trusts a small agent — which is exactly why we keep it small enough to audit."

---

## Delivery notes

- **Slow down on proof 3.** It's the strongest thing you have. Let the word *"rejected"* sit.
- **Volunteer the limits.** Saying "these are loopback numbers" before a judge spots it turns
  a weakness into evidence of rigour.
- **Never say "live" about the website.**
- If a proof misbehaves, say so and move on. `transcript.txt` is your backup, clearly labelled
  as a recording.
- Read the VERDICT lines aloud — they're written as spoken sentences.

*Independent proposal. Not an official Ministry of Interior publication.*
