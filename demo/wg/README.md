# ZeroPort → real WireGuard kernel interface

This closes the last big gap. Everywhere else in the demo the tunnel is
WireGuard's *cryptography* in userspace; here the packets are handled by the
real WireGuard driver in the Windows kernel, and ZeroPort decides who is in it.

## Why this is the interesting part

WireGuard has **no access control of its own.** It forwards for whoever is in
its peer list and refuses everyone else — it has no notion of identity, policy,
leases, quorum or revocation. That gap is precisely what ZeroPort fills.

So the integration is not "ZeroPort talks to WireGuard". It is:

> An authorization decision made by ZeroPort — against a roster carrying a real
> 2-of-3 FROST threshold signature — **becomes, or ceases to be, a peer the
> kernel will accept packets from.**

Revocation here is not a firewall rule laid over the top. The peer stops
existing to the data plane.

## Running it

Both steps need an **elevated** terminal (creating a network device requires it).

```powershell
cd C:\Users\stnal\Projects\zeroport\demo\wg
.\zp-wg-setup.ps1
```

Creates interface `zp0` on `10.77.0.1/24`, listening on UDP 51820, **with no
peers**. Then:

```powershell
node wg-proof.js
```

When you are finished:

```powershell
.\zp-wg-teardown.ps1
```

This removes the tunnel service and the adapter, leaving the machine exactly as
it was.

## What the proof shows

| | |
|---|---|
| **A** | A roster signed by **two officers** puts a peer into the real kernel interface — visible in `wg show zp0`. |
| **B** | A revocation signed by **one officer** removes it. The peer is gone from the kernel entirely. |
| **C** | A roster signed by **one share** is not a valid threshold signature, so the relay rejects it and the kernel never hears about it. |

The control plane in this run is genuine: a real Nostr relay speaking NIP-01
over WebSocket, a real FROST 2-of-3 group, real BIP-340 signatures.

## Safety

- **`AllowedIPs` is confined to `10.77.0.0/24` and the code refuses anything
  else.** A tunnel carrying `0.0.0.0/0` toward a peer that is not there would
  black-hole every packet leaving this machine. `wg-control.js` rejects
  `0.0.0.0/0`, other subnets, and even the interface's own `.1` address.
- No default route is ever created, and your existing networking is untouched.
- The generated private key is handed to the WireGuard service (which keeps its
  own encrypted copy) and the plaintext `zp0.conf` is deleted immediately.
- `wg-proof.js` removes every peer it added before exiting, and on error.
- Teardown is a single script and complete.

## Honest limit

This is **one machine**, so there is no second endpoint to complete a handshake
with, and therefore no ping and no throughput figure. What is proven is the
join between ZeroPort's cryptography and a real kernel data plane.

Put the peer half on a second host — a laptop, a VM, a small VPS — add its
endpoint, and the identical code carries real IP traffic. That second host is
also the only way to exercise NAT traversal, which cannot be shown on loopback.

## Files

| File | Role |
|---|---|
| `zp-wg-setup.ps1` | elevated: create `zp0` |
| `zp-wg-teardown.ps1` | elevated: remove it completely |
| `wg-control.js` | the bridge — add/remove peers, with the subnet guard |
| `wg-proof.js` | proofs A, B and C against the live interface |
