# Nector

**Authorized website security posture checks — “See the risk. Know the next move.”**

Nector is a polished security posture and vulnerability scanning platform,
integrating ProjectDiscovery Nuclei scanning and Google Gemini AI remediation.
A visitor enters a website URL, confirms they are authorized to assess it,
and receives a readable security assessment: a risk score, explained findings, and
recommended next steps.

It is a **defensive** tool. It performs safe, non-destructive checks only — no exploit
attempts, no credential attacks, no denial-of-service testing, no unauthorized access.
It does not replace a professional security assessment, and manual review may be
required for anything important.

---

## Highlights

- **One-action flow** — enter URL, confirm authorization, *Check Website*.
- **Live progress** — six assessment stages derived from real backend check completions,
  with elapsed time, status badges, and honest failure states.
- **Explainable results** — score ring, severity breakdown, posture-by-area summary,
  filterable findings with observation / evidence / recommendation per row.
- **Transparent scoring** — the deduction model is disclosed in the UI, not hidden.
- **Downloadable report** — a dedicated print stylesheet turns results into a clean
  PDF report (all findings expanded, chrome stripped).
- **Accessible** — semantic landmarks, skip link, `aria-live` status regions,
  `aria-valuenow` progress, keyboard-operable accordion/rows, visible focus states,
  and full `prefers-reduced-motion` support.
- **Zero frameworks** — hand-written HTML, CSS, and vanilla JavaScript. No build step.
- **No mock data** — every finding is derived from live backend responses.

## Quick start

```bash
# Terminal 1 — backend (port 3000)
git apply ~/.zcode/tmp/server-js-windows-esm-fix.patch   # Windows only, see note below
node server.js

# Terminal 2 — frontend with security headers (port 8080)
node threatforge/serve.mjs
```

Open **http://127.0.0.1:8080**. The API base is resolved automatically:

1. `?api=` query parameter (e.g. `index.html?api=http://localhost:3000`)
2. same origin, when served from port 3000 itself
3. fallback: `http://localhost:3000`

> **Windows note.** The committed `server.js` uses `import(path.join(...))`, which fails
> on Windows with `ERR_UNSUPPORTED_ESM_URL_SCHEME`. The one-line-class fix
> (`fileURLToPath` / `pathToFileURL`) is kept at
> `~/.zcode/tmp/server-js-windows-esm-fix.patch` — apply it before starting the backend.
> On Linux/macOS the committed server runs as-is.

## Architecture

```
┌────────────────────────┐         ┌─────────────────────────────┐
│  threatforge/          │  HTTP   │  server.js (Express, :3000) │
│  index.html            │───────▶ │  auto-registers GET routes  │
│  styles.css            │  fetch  │  from api/*.js              │
│  script.js             │         │  /api/<check>?url=<target>  │
└────────────────────────┘         └──────────────┬──────────────┘
       vanilla JS derives           ▲             │ safe, non-destructive
       score · findings · stages     └────────────┘ public-response requests
                                                   ▼
                                            target website
```

- **No scan logic lives in the frontend.** Every finding, the score, and the stage
  progress are derived from responses of the *existing* handlers.
- **No backend file was modified** for this frontend (`git diff HEAD -- server.js` is empty).

### Endpoint mapping

| Existing endpoint | What the UI derives from it |
| --- | --- |
| `/api/status` | reachability, response code, timing |
| `/api/redirects` | redirect chain; whether traffic upgrades to HTTPS |
| `/api/ssl` | certificate validity, issuer, expiry window |
| `/api/hsts` | HSTS presence and baseline compliance |
| `/api/headers` | CSP, framing, MIME-sniffing, referrer, permissions policies; server/`X-Powered-By` disclosure |
| `/api/cookies` | `Secure` / `HttpOnly` / `SameSite` attributes from observed `Set-Cookie` headers |
| `/api/security-txt` | published security policy (`RFC 9116`) |

## Scoring model (transparent by design)

`100 − (critical×25 + high×15 + medium×8 + low×3)`, floored at 0.

Risk label: **≥85 Low · 60–84 Medium · 35–59 High · <35 Critical**.
Passed and skipped checks never deduct points. Severity mapping examples:
cookies without `Secure` → High; missing CSP or HSTS → Medium; server version
disclosure → Low; unpublished `security.txt` → Informational.

## Project structure

```
threatforge/
├── index.html   # single page: landing, progress panel, results panel
├── styles.css   # design tokens, components, motion, print stylesheet
├── script.js    # form gating, scan orchestration, mapping, rendering
└── README.md
```

## Design system

Warm editorial surface (`#FAF9F4`) with white cards, near-black ink, thin warm
borders, and a salmon marker highlight (`#F6A988`) for headline keywords.
Dark-green monospace eyebrows (`#1D5C4A`), pill controls, 12–16px radii.
Semantic risk colors (`#1F7A44` / `#A16207` / `#C2410C` / `#B91C1C` / `#52525B`)
appear **only** in dots, badges, rules, bars, and the score ring — never as
large backgrounds.

## Accessibility

- Semantic landmarks, skip-to-content link, labeled controls.
- URL validation linked via `aria-describedby`; status regions via `aria-live`.
- Progress bar exposes `aria-valuemin/max/now`; state never relies on color alone.
- Findings expand via `aria-expanded`; accordion and filters are keyboard-operable.
- `prefers-reduced-motion` disables reveals, pulses, scan lines, and count-ups;
  content is never hidden when JavaScript fails (`html.js` gating).

## Security model

The frontend is hardened for hostile embedding and transport scenarios:

| Control | Where | What it does |
| --- | --- | --- |
| Content-Security-Policy | `serve.mjs` header **and** `<meta>` fallback | `default-src 'none'`; scripts/styles only from the site itself; API calls only to `localhost:3000`. Blocks injected scripts, inline handlers, and exfiltration via the `?api=` parameter. |
| `X-Frame-Options: DENY` + `frame-src 'none'` | header | Prevents clickjacking. A JS frame-guard in `script.js` is the fallback when headers cannot be set. |
| `X-Content-Type-Options: nosniff` | header | Stops MIME-type sniffing. |
| `Referrer-Policy: no-referrer` | header + meta | The page never leaks referrer data. |
| `Permissions-Policy` | header + meta | Camera, microphone, geolocation, payment, USB disabled. |
| `COOP` / `CORP: same-origin` | header | Process and resource isolation against cross-origin attacks. |
| Path traversal protection | `serve.mjs` | Requests are decoded, normalized, and must resolve inside `threatforge/`; no directory listing; GET/HEAD only; binds to `127.0.0.1` by default (`HOST=0.0.0.0` to expose). |
| Input hardening | `script.js` | Targets require an `http(s)` URL with a dotted hostname, no embedded credentials, no whitespace, ≤2048 chars. |
| No injection surface | `script.js` | All dynamic content is rendered with `textContent`; no user data ever enters `innerHTML`, `eval`, or URL-loaded resources; no cookies, no `localStorage`, no third-party code. |
| Request hygiene | `script.js` | In-flight assessment requests are aborted via `AbortController` when the page closes; duplicate submissions are locked out while a scan runs. |

**Residual items that need deployment decisions (frontend cannot fix):** the API's
CORS policy is `*` (existing backend config — restrict via `API_CORS_ORIGIN` if
desired), the API is plain HTTP on localhost (serve behind TLS + HSTS in
production), and `API_ENABLE_RATE_LIMIT=true` is available on the backend but off
by default. The `connect-src` CSP allowlist must be extended if you host the API
on a remote origin.

## Honest scope

- Reviews **public responses only**; it does not test login-protected areas,
  attempt exploitation, or perform load testing.
- Findings are signals from sampled responses — **manual verification may be required**.
- The score is a prioritization aid computed in the browser; it does not prove
  exploitation and does not guarantee a website is free from vulnerabilities.
