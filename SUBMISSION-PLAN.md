# ZeroPort — 7-Day Submission Plan

**Deadline:** ~1 week · **Target:** working 2-VM demo + React console · **Poster:** A1 portrait PDF

## Required by the form

| # | Asset | Required | Our source |
|---|---|---|---|
| 1 | **Project Photo** | ✅ | Composite hero shot of the SOC console (network projects have nothing physical — the console *is* the product shot) |
| 2 | **Poster or Brochure** | ✅ | A1 portrait PDF, built HTML → print-to-PDF |
| 3 | **Demonstration Video** | "Optional" — **treat as mandatory** | ≤5 min screen recording of the six proofs |
| 4 | **Google Drive Link** | ✅ (marked `*` despite saying "optional") | Structured folder, link-shareable |

> ⚠️ **Format conflict:** our demo script runs 6 minutes; the video cap is **5**. It needs a re-cut (timing below).

---

## The schedule — code freezes Day 5

| Day | Focus | Output |
|---|---|---|
| **1** | Infra + primitives (Phase 0) | 2 cloud VMs in different regions, all inbound ports closed. Tor onion + WireGuard proven **manually**. |
| **2** | **Phase 1 agent** ← critical path | keygen → Nostr publish/discover → onion rendezvous → WireGuard up → latency probe. **Unlocks proofs 1 & 2.** |
| **3** | Phase 2 + 3 | Roster, 2-of-3 enrollment, 60-second leases, revocation, hash-chained log + verifier. **Proofs 3–6.** |
| **4** | Console | React/Vite/Tailwind v3 reading real agent events over SSE. **Unlocks the Project Photo.** |
| **5** | 🔒 **CODE FREEZE — asset capture day** | Screenshots, hero image, record video (multiple takes). No new features. |
| **6** | Production | Poster → PDF, video edit to ≤5 min, Drive folder assembled, pitch doc → PDF. |
| **7** | Buffer + **submit early** | Never submit on the final day. Reserve for upload failures and link testing. |

**Go/no-go checkpoint — end of Day 3:** if the onion→direct upgrade isn't working, stop adding features. Fall back to console-driven-by-recorded-data and reframe the video as a walkthrough. Decide this on Day 3, not Day 6.

---

## Asset 1 — Project Photo

**One composite hero image** that carries three proofs at once:

- **Main frame:** the SOC console — dark theme, topology graph mid-upgrade (onion → direct), one identity-attributed flow line legible:
  `alice-laptop(npub1x…) → finance-db:5432 · allowed by policy #7 · via direct · 14.2 MB`
- **Inset (bottom-right):** terminal showing `nmap` returning **0 open ports**, and the latency counter caught mid-drop (e.g. **384 ms → 9 ms**).

Rules: export PNG at 2× DPI, 1920×1080 minimum, and **check it reads as a thumbnail** — judges see it small first. This is a design constraint on the console: high contrast, big numbers, no clutter.

## Asset 2 — Poster (A1 portrait, 594 × 841 mm)

Built as HTML with exact A1 CSS dimensions → Chrome **Print → Save as PDF**. Three-column academic layout:

- **Header:** ZeroPort · *Zero ports. Zero trust. Zero blind spots.* · team names
- **Col 1:** Problem · Objectives
- **Col 2:** **Four-plane architecture diagram (centerpiece — largest element)** · Methodology
- **Col 3:** Results (six proofs + measured latency) · Risks & limits · Compliance mapping · Future work
- **Footer:** **QR code** linking to the demo video / Drive folder

Type sizes for A1 legibility at 1–2 m: title ~100 pt, section heads ~40 pt, body ~24–28 pt.

## Asset 3 — Demo video (re-cut to ≤5:00)

| Time | Beat |
|---|---|
| 0:00–0:20 | Problem + what ZeroPort is, over the architecture diagram |
| 0:20–1:05 | **Proof 1** — `nmap` → nothing. Connect anyway → works |
| 1:05–1:55 | **Proof 2** — onion → direct upgrade, latency drops *(hero moment — let it breathe)* |
| 1:55–2:35 | **Proof 3** — lone admin refused; second signature approves |
| 2:35–3:15 | **Proof 4** — lease expires, access dies on its own |
| 3:15–3:50 | **Proof 5** — unenrolled refused + logged; revoke → dies in seconds |
| 3:50–4:35 | **Proof 6** — verifier catches both an edited line and a swapped file |
| 4:35–5:00 | Honest limits + close |

Record with **OBS Studio** (free, Windows) at 1080p, console and terminal side by side. Do several takes.

> **The successful recording doubles as your live-demo fallback.** Hackathon wifi + Tor bootstrap is a genuine failure mode — if the live run stalls on stage, cut to tape and keep talking.

## Asset 4 — Google Drive folder

```
ZeroPort-Submission/
├── 00-README.pdf              ← 1-page index of everything
├── 01-Poster-A1.pdf
├── 02-Project-Photo.png
├── 03-Demo-Video-5min.mp4
├── 04-Full-Pitch-Document.pdf
├── 05-Source-Code/            ← agent + console (or repo link)
├── 06-Architecture-Diagrams/  ← SVG + PNG
├── 07-Setup-Reproduce.md      ← how a judge could rerun it
└── 08-Extended-Demo-Uncut.mp4 ← the full 6-min version
```

> 🚨 **Set sharing to "Anyone with the link can view," then open the link in an incognito window to confirm.** A restricted Drive link that judges can't open is one of the most common — and most fatal — submission failures.

---

## Split of work

**I can produce:** four-plane architecture diagram (SVG), the A1 poster (HTML→PDF), the console UI, the Phase 1 agent scaffold, the video script + narration, the Drive README, and the pitch doc → PDF.

**You must do:** provision and run the VMs, record the video and narration, capture the final screenshots from the real system, upload and verify sharing.
