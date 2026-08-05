# Plane 2 — a real Tor onion service

The rendezvous plane is no longer a stand-in. It runs behind a genuine v3 onion
service, using the Tor daemon from the Tor Browser bundle.

```bash
node tor/test-onion.js       # the proof
node tor/start-tor.js 8802   # just bring the onion service up
```

## What the proof shows

Verified on 5 August 2026 — **4/4 checks passed**:

- **The rendezvous is not reachable on a public interface.** It binds `127.0.0.1` only.
- **A real v3 onion address was issued** — 56 base32 characters, derived from the
  service's own Ed25519 key. Nobody assigned it; it *is* the key.
- **A write went through the Tor network** — `POST /announce` returned `200 {"ok":true}`
- **The data round-tripped** — `GET /lookup` returned the announced endpoint

Every one of those requests travelled through real Tor circuits to a real hidden service.

## Why this is the strongest form of "no listening port"

The onion address is the hash of the service's public key. There is nothing to scan,
because there is no address in the ordinary sense — the service is only reachable by
peers that already know the key, through circuits neither end can see the whole of.

A WireGuard endpoint on a public IP still binds a port (silent, but bound). An onion
service binds nothing routable at all.

## How it works here

`start-tor.js` writes a `torrc` that maps `onion:80 → 127.0.0.1:<rendezvous>`, starts
the daemon, waits for `Bootstrapped 100%`, then reads the generated hostname.

Node cannot reach `.onion` names — they do not exist in DNS. `lib/socks.js` is a small
SOCKS5 client that hands the hostname to Tor as a DOMAIN address so it is resolved
*inside* the Tor network, plus just enough HTTP to speak the rendezvous protocol.

## Two things that will bite you

**Descriptor publication takes time.** After `Bootstrapped 100%` the service still has to
publish its descriptor to the directory hashring, and the client has to fetch it and build
a rendezvous circuit. The first connection can take 30–60 seconds and may need a retry;
`test-onion.js` retries six times with backoff. This is normal Tor behaviour, not a fault.

**Chunked encoding.** Node's HTTP server omits `Content-Length` and uses chunked framing.
The first version of the SOCKS client returned the raw chunk markers and the test failed
even though the data was correct. `lib/socks.js` now decodes it.

## ⚠️ The private key

`tor/hs/hs_ed25519_secret_key` **is** the service's identity. Anyone holding it can
impersonate your onion address. It is in `.gitignore` along with `tor/data/` and `torrc` —
verified with `git check-ignore`. Do not commit it, and do not paste the contents anywhere.

Deleting `tor/hs/` gives you a brand-new onion address on the next run.

## Custom Tor location

The path is auto-detected at
`~/OneDrive/Desktop/Tor Browser/Browser/TorBrowser/Tor/tor.exe`. Override with:

```bash
set TOR_EXE=C:\path\to\tor.exe
```

---

*Independent hackathon proposal. Not an official Ministry of Interior publication.*
