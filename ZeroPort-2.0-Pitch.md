# ZeroPort 2.0

### Zero ports. Zero trust. Zero blind spots.

**A private company network with no listening port on the internet — nothing to scan, flood, or exploit — that your security team runs from a single console, and that no single admin can betray.**

---

## The 30-second problem

Every service a company exposes is a door an attacker can knock on. Firewalls, VPN concentrators, bastion hosts — all of them *listen* on a public IP, which means all of them can be scanned, fingerprinted, flooded, and exploited. The vendor's answer (a cloud "coordinator") just moves the trust to a third party you don't control and can't audit.

ZeroPort removes the doors. There is **no listening port on the internet** to attack. Peers still reach each other — but through cryptographic identity and a client-authorized rendezvous, not an open port.

> **Scope, stated first:** ZeroPort covers **internal and partner access** — employee-to-service, site-to-site, company-to-company. It is *not* for public web/email; those still need conventional exposure. We say this up front so the claim stays honest.

---

## What ZeroPort is — four planes

The original design had three planes that move packets. ZeroPort 2.0 adds a **fourth plane: the one your security team actually lives in.** That is the difference between a clever network and a product a cybersecurity department can operate.

| Plane | Built on | What it does |
|---|---|---|
| **1 · Identity & Policy** | Nostr (signed events) | Threshold-signed roster, per-peer/per-port policy, key exchange, instant revocation |
| **2 · Rendezvous** | Tor onion service | Client-authorized meeting point so peers with no public IP can find and authenticate each other — used for *seconds*, and the fallback when all else fails |
| **3 · Transport** | WireGuard | After rendezvous, peers hole-punch a **direct** encrypted tunnel at native speed; Tor drops out of the path |
| **4 · Assurance & Operations** | Console + SIEM + verifier | **Where the SOC works:** enroll, write policy, watch live topology, read the tamper-proof audit, hit the kill switch |

> *The first three planes move the packets. The fourth plane is where your security team lives.*

**Three independent bootstrap paths** mean no single dependency: LAN discovery, a self-hosted Nostr relay, and the onion rendezvous. Any one of them is enough to come online.

---

## The headline: visibility becomes *better*, not worse

In a normal network your IDS sees `10.0.4.12 → 10.0.9.3:5432` and you *guess* who that was. In ZeroPort every connection is cryptographically bound to an identity, so the log line reads:

```
alice-laptop(npub1x…) → finance-db:5432 · allowed by policy #7 · via direct · 14.2 MB
```

You didn't lose inspection — you **replaced packet-guessing with cryptographically attributed flow authorization.** That is exactly what zero-trust vendors sell for a lot of money, and here it falls out of the architecture for free.

---

## The five upgrades that make it "max safe" and easy to run

### 1 · No single admin can betray the network  *(control-plane hardening)*

In v1, whoever held the roster-signing key *owned* the network — one compromised admin could enroll rogue nodes, revoke real ones, and forge policy.

**ZeroPort 2.0 makes the signing authority an *M-of-N threshold key*** using **FROST threshold Schnorr over secp256k1 — the exact curve Nostr already uses**, so it's native, not bolted on. Enrolling a device, changing policy, or revoking now takes a **quorum** of SOC officers (e.g., 2-of-3). No single key. No single traitor.

**Deliberate asymmetry — fail toward safety:** enrollment and policy changes are *hard* (2-of-3), but **revocation is easy** (1-of-N). Pulling the emergency cord should always be easier than granting access.

Two compliance wins fall out for free:
- **Separation of duties** — a real, named control auditors look for.
- **Console RBAC** — *enroller* proposes, *approver* co-signs, *auditor* can read every log but change nothing.

### 2 · Access that expires, and a log nobody can quietly rewrite  *(fail-safe & audit)*

**Leases, not permanent membership.** Every peer authorization is a **short-lived signed lease (~60 min)**, auto-renewed while the node stays healthy and policy-compliant. Revocation now works *two* ways — an instant push **and** passive non-renewal.

> The property that matters: **if the control plane can't reach a node, that node's access simply expires.** A stolen laptop taken offline loses access with nobody pressing a button. The default state of the whole network becomes *"no access — you must keep earning it."*

**A tamper-proof audit log.** v1's log was hash-chained, so editing one line was detectable. ZeroPort 2.0 goes further:
- **Hash chain** — each entry embeds the previous entry's hash → *can't edit one line.*
- **Public anchor** — the chain head (a signed Merkle root) is published to the Nostr relay and a public timestamp on a schedule → *can't swap the whole file either; the head won't match.*
- **SIEM mirror** — every entry streams to an append-only SIEM in real time → *there are always two copies.*

**Break-glass + auto-quarantine.** If every relay is down, nodes fall back to a cached signed roster with a hard TTL and then **fail closed**; re-issue requires an offline quorum. And on an anomaly signal — failed posture check, impossible-travel, a storm of policy violations — a peer's lease **auto-narrows to nothing** pending SOC review. Blast-radius containment that happens on its own.

### 3 · The metadata weakness becomes a feature  *(metadata & compliance)*

Honest admission from v1: a *direct* WireGuard tunnel exposes both peers' IPs to a network observer — you traded anonymity for speed.

ZeroPort 2.0 makes that trade a **per-policy choice**, set by the SOC:

| Tier | Behavior | Use for |
|---|---|---|
| **Tier 0 — normal** | Upgrade onion → direct WireGuard. Native speed. *(default)* | File shares, internal apps, bulk transfer |
| **Tier 1 — sensitive** | **Stay on the onion path — never upgrade.** Peer IPs never touch a wire an observer can read. Optional padding/cover traffic. | Crown-jewel DBs, admin planes, anything an observer shouldn't map |

> *"Your crown-jewel database stays dark; your file share goes fast."* — the trade is now something you *chose*, per flow, and can defend.

**Compliance mapping** (see table below) — because the architecture *produces* these controls rather than documenting around them.

### 4 · Easy to use — zero-touch onboarding, policy as pictures

- **QR / one-time-token enrollment.** SOC clicks *Add device* → gets a single-use, time-boxed token (QR). The device runs one installer / scans it. The agent **self-generates its keys** (Nostr + WireGuard, in hardware where the device supports it), publishes an *encrypted* peer record, and lands in a **Pending queue** the SOC approves by quorum. **No human ever sees or touches a private key.**
- **Visual policy editor.** Microsegmentation as a drag-a-line graph: nodes are identities or groups, edges are allowed ports (`alice-laptop → finance-db:5432`). It compiles to signed policy events. The SOC never edits raw config.
- **One console.** Live topology (who ↔ who, direct vs onion, throughput), the pending queue, the policy graph, the audit stream with a live **"chain intact ✓"** badge, and one big red **REVOKE**.

### 5 · Legacy and same-site handling *(operability details judges will ask about)*

- **Gateway nodes** proxy for devices that can't run an agent (printers, IoT, VoIP) — declared *explicitly* in the roster with narrow port allowlists, so the exception is visible, not a backdoor.
- **Path selection always prefers same-site** — local traffic never gets routed around the world.
- **Minimal agent, non-root where possible** — the agent is the only listener and drops anything not on the signed roster (default-deny). Small enough to audit is a design goal, not an afterthought.

---

## Problem → fix, at a glance

| Original problem | Fix in ZeroPort 2.0 |
|---|---|
| Tor latency kills usability | Tor only for rendezvous; WireGuard carries data. Onion is a fallback, not the norm. |
| Security team goes blind | Fourth plane: identity-attributed flow logs to your SIEM. Better than perimeter IDS. |
| No audit trail / fails compliance | Hash-chained + **publicly anchored** + SIEM-mirrored log. Retention configurable. |
| Single admin owns everything | **Threshold (M-of-N) signing.** No single compromised admin can enroll, revoke, or forge policy. |
| Revocation depends on the network being up | **Leases expire on their own.** Offline = access ends. Fail-closed by default. |
| Tor is a single dependency | Three independent bootstrap paths: LAN, self-hosted relay, onion. Any one works. |
| Agent on every host = new CVEs | Minimal, non-root, default-deny agent; drops anything not on the signed roster. |
| Legacy devices can't run it | Gateway nodes with explicit, narrow allowlists in the roster. |
| Local traffic routed round the world | Path selection prefers same-site. |
| Metadata leak from direct tunnels | **Per-flow sensitivity tier** — Tier 1 stays on onion; peer IPs never exposed. |
| Public web/email still needs exposure | Out of scope *by design.* Internal + partner access only. Say it first. |
| Insider threat | Per-peer/per-port microsegmentation + short leases + auto-quarantine + instant revoke. Bounded, not eliminated. |

---

## Compliance mapping (the auditor's cheat sheet)

| ZeroPort feature | Maps to |
|---|---|
| Identity-bound, policy-authorized flows | **NIST SP 800-207** ZTA tenets 1–4 (per-request, per-session access decisions) |
| Per-peer / per-port microsegmentation | **PCI-DSS Req. 1** (network segmentation); **NIST 800-207** tenet 5 |
| Threshold signing + RBAC (enroller/approver/auditor) | **ISO 27001** A.5.15 / A.5.18 (access control), **SoD**; **SOC 2 CC6.1–CC6.3** |
| Hash-chained + anchored + SIEM-mirrored audit log | **ISO 27001** A.8.15 (logging); **SOC 2 CC7.2–CC7.3** (monitoring); tamper-evidence for any auditor |
| Short-lived leases, fail-closed | **NIST 800-207** tenet 6 (dynamic auth); **SOC 2 CC6.2** (timely deprovisioning) |

*Every row cites a real control. The architecture produces them; it doesn't paper over them.*

---

## Abstract

**Version A — full (558 characters).** Use where length is unconstrained.

> ZeroPort gives a company a private network with no listening port on the internet — nothing to scan, flood, or exploit. A threshold-signed Nostr directory handles identity, policy, and revocation, so no single admin can betray the network; Tor onion services rendezvous peers with no public address; WireGuard then carries traffic at native speed. Access is leased, so it expires if unrenewed; every flow is attributed to a cryptographic identity and written to a tamper-proof, publicly anchored log. Your security team gains visibility instead of losing it.

**Version B — fits a 500-character limit (497 characters).** Matches the original submission's constraint; keeps all four claims.

> ZeroPort gives a company a private network with no listening port on the internet — nothing to scan, flood or exploit. A threshold-signed Nostr directory handles identity, policy and revocation, so no single admin can betray it; Tor onion rendezvous connects peers with no public address; WireGuard carries traffic at full speed. Access is leased and expires on its own, and every flow is bound to a cryptographic identity in a tamper-proof log. Your security team gains visibility, not blindness.

---

## The demo — six proofs in six minutes

*Judges remember what they see move. Two beats are the "wow": the live latency drop (proof 2) and access dying by itself (proof 4).*

| # | Action | What the judge sees |
|---|---|---|
| **1** | `nmap` the company's public IP, then connect anyway | Scan returns **nothing** — no open ports. The connection still **works.** The core claim, proven in ten seconds. |
| **2** | Watch the path upgrade **onion → direct** | A live latency counter **drops** (e.g., 380 ms → 8 ms) the instant WireGuard takes over. The whole speed thesis in one number. |
| **3** | One admin tries to enroll a rogue node *alone* | **Refused** — enrollment needs 2-of-3. Then a second officer co-signs and it succeeds. *No single admin can betray you.* |
| **4** | Take a node offline / cut the control plane | Its lease **expires and access dies on its own** — nobody pressed revoke. Fail-closed, proven. |
| **5** | Unenrolled node attempts access, then revoke a real node | First is **refused and logged**; the revoked node **dies in seconds.** |
| **6** | Tamper the audit log — edit one line, *and* swap the whole file | The verifier **flags both**: the edit breaks the chain, the file swap fails against the public anchor. |

---

## Still not solved — we say it before you ask

Judges reward honesty. Here is what ZeroPort does **not** fix, each with its mitigation:

- **A compromised endpoint is still compromised.** But its blast radius is now bounded by per-port policy, short lease TTLs, and auto-quarantine. *Mitigated, not solved.*
- **Metadata resistance is weaker than pure-Tor** for Tier-0 flows, because direct tunnels expose peer IPs. But it's now a **per-flow choice** (Tier 1 stays dark) — a trade we made deliberately and can defend.
- **The whole system trusts the agent's correctness.** So we scope the agent small, keep it memory-safe, ship signed reproducible builds, and make it default-deny — small enough to audit is the point.
- **Threshold quorum adds coordination overhead.** Mitigated by console UX and the "revoke is easier than enroll" asymmetry, so the safety-critical action is never the slow one.

---

## MVP roadmap

**Phase 1 — prove the concept.** Two VMs, no inbound firewall rules. Agent generates Nostr + WireGuard keys, publishes an encrypted peer record, discovers the peer, connects over the onion service, upgrades to a direct WireGuard tunnel. *Show the latency drop live* — that one moment demonstrates the whole thesis.

**Phase 2 — the security layer.** Threshold-signed roster with quorum enrollment and revocation. Per-peer port policy. Onion client authorization. Leases with auto-expiry. Hash-chained + anchored flow log with a verifier that detects both a tampered entry and a swapped file. The fourth-plane console over the top.

**Phase 3 — federation.** Second company, second relay, cross-signed rosters, one service selectively shared across the boundary — with the same identity-attributed logging on both sides.

---

*ZeroPort 2.0 — internal & partner access with nothing to scan, everything attributed, and no single point of betrayal.*
