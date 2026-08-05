# ZeroPort — second host

This closes the last gap. Everything else in the project runs on one machine, which
means loopback timings, no NAT, and no ping. A second host on the public internet
gives you the numbers you cannot fake.

Cost is about **$4–6 for a month**, and you can destroy the server the moment the
presentation is over. Any provider works: Hetzner, DigitalOcean, Vultr, Linode.
Pick **Ubuntu 22.04 or 24.04**, the smallest instance.

---

## What this gets you

- **A real ping** through a real WireGuard tunnel, over the real internet.
- **Real wide-area latency**, so proof 2 stops being a loopback ratio.
- **A genuinely remote control plane** — the Nostr relay runs on the VPS, so the
  roster really is fetched across the network and its threshold signature really is
  verified at a distance.
- **A real `nmap` target.** You can scan a genuine internet host in front of judges.

---

## Be precise about two things on stage

**1. This is NAT traversal, but it is not hole-punching.**
Your laptop is behind NAT and has no public address, and it still gets a working
tunnel — that part is real and worth saying. But because the VPS *has* a public
address, the client simply connects outbound. True hole-punching is when **both**
peers are behind NAT and neither can be dialled. To demonstrate that you need two
NATed hosts — your laptop plus a friend's machine on a different home network, or two
VPSs deliberately placed behind NAT. Do not call the VPS setup hole-punching.

**2. The VPS does bind a WireGuard port.**
ZeroPort's "no listening port" claim rests on rendezvous plus hole-punching, so that
neither side needs a public endpoint. The VPS shortcut trades that away for
simplicity. Say so if asked — and then say the thing that rescues it:

> WireGuard never answers an unauthenticated packet. A port scan of that UDP port
> returns nothing at all, because the daemon is silent to anyone without a valid key.
> There is a socket bound, but there is nothing to fingerprint and nothing to exploit.

That is true, it is checkable live with `nmap -sU -p 51820 <vps-ip>`, and it is a
stronger answer than pretending the port is not there.

---

## Procedure

### 1 — On the VPS

```bash
scp -r demo root@<vps-ip>:/opt/zeroport/demo     # from your laptop first
ssh root@<vps-ip>
bash /opt/zeroport/demo/vps/provision.sh
```

It installs WireGuard and Node, configures the firewall, brings up interface `zp0`
on `10.77.0.1/24`, runs the Nostr relay as a systemd service, and prints the server
public key and endpoint.

> The script allows SSH **before** enabling the firewall. That ordering matters: get
> it wrong by hand and you lock yourself out of the machine for good.

### 2 — On Windows, from an elevated PowerShell

```powershell
cd C:\Users\stnal\Projects\zeroport\demo\vps
.\client-setup.ps1 -ServerPublicKey "<key from step 1>" -Endpoint "<vps-ip>:51820"
```

It prints **this machine's** public key.

### 3 — Back on the VPS, authorise the client

```bash
wg set zp0 peer <CLIENT_PUBLIC_KEY> allowed-ips 10.77.0.2/32
wg show zp0
```

### 4 — The moment that matters

```powershell
ping 10.77.0.1
```

A reply is a real IP packet, encrypted, across the public internet, through a tunnel
whose peer list ZeroPort controls.

### 5 — Real numbers

```powershell
node wan-measure.js --public <vps-ip>
```

Compares the same endpoint reached two ways — over the open internet and through the
tunnel — and reports the true encryption overhead. It then publishes a FROST-signed
roster to the remote relay and times the round trip.

---

## Teardown

On Windows:

```powershell
.\client-teardown.ps1
```

On the VPS: destroy the instance from the provider's console. That is the cleanest
removal there is, and it stops the billing.

---

## Safety

- **`AllowedIPs` is pinned to `10.77.0.0/24` and never `0.0.0.0/0`.** A default-route
  tunnel would push every packet this machine sends through the VPS — that is a
  different product, it costs bandwidth, and it breaks your connectivity if the far
  end disappears. `client-setup.ps1` refuses to configure it.
- Inputs are validated, not trusted: the key must look like a WireGuard key, the
  endpoint must be `host:port`, and the client address must sit inside the subnet and
  must not be the server's `.1`.
- The firewall opens only UDP 51820 and the relay port, plus SSH.
- Private keys are handed to the tunnel service, which keeps its own encrypted copy;
  the plaintext `.conf` is deleted immediately on both sides.
- The relay on the VPS is a demo service on a public port. Take the instance down
  when you are finished rather than leaving it running.

---

## What this still does not prove

Even with two hosts:

- **Hole-punching between two NATed peers** — needs two NATed hosts, as above.
- **Tor onion routing** — not installed, and the self-hosted rendezvous is arguably
  the better sovereignty answer anyway.
- **Scale.** Two nodes prove the mechanism, not the operational load of a national
  deployment.

Say these before a judge finds them.
