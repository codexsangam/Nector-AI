# Nector — Architecture

AI-powered web vulnerability tester: scans a permitted website with OWASP ZAP and Nuclei, normalizes the raw findings, and has GLM Flash turn them into a clean, actionable report.

## Stack

| Layer         | Choice                  |
|---------------|-------------------------|
| Frontend      | Next.js + React + Tailwind |
| Backend       | Python FastAPI          |
| Database      | MongoDB                 |
| Scanners      | OWASP ZAP, Nuclei       |
| AI            | GLM Flash API           |
| Reports       | HTML / PDF              |

## System flow

```
User
  → Next.js frontend          (form, permission gate, progress, report)
    → FastAPI backend         (validation, orchestration, persistence)
      → ZAP + Nuclei          (raw scanner processes, run in parallel)
        → Normalizer          (scanner output → one internal shape)
          → GLM Flash         (findings in → structured report out)
            → MongoDB         (final report stored)
              → Dashboard / report page / PDF download
```

## Module decomposition

One monorepo, two apps. Nothing in the frontend talks to MongoDB, scanners, or GLM directly — every external system is reachable only through the backend API.

### `backend/` (FastAPI)

| Module                | Owns                                   | Depends on        |
|-----------------------|----------------------------------------|-------------------|
| `api/`                | HTTP routes only: request/response schemas, auth-lite, polling endpoints | services |
| `core/validation.py`  | URL format + scheme validation; rejects private/localhost targets | — |
| `core/scan_service.py`| Scan lifecycle state machine: `created → scanning → analyzing → completed/failed`; the **single owner** of scan state. Creates scan records, advances states, exposes status | `db`, runners, `normalizer`, `ai_reporter` |
| `scanners/zap_runner.py` | Spawn + drive ZAP, return raw ZAP findings | — |
| `scanners/nuclei_runner.py` | Spawn + drive Nuclei, return raw Nuclei findings | — |
| `scanners/normalizer.py` | ZAP + Nuclei raw output → one internal `Finding` model (id, title, severity, description, evidence, remediation, source) | — |
| `ai/glm_reporter.py`  | Pure function: normalized findings → GLM Flash → structured report JSON. **No subprocess, no network targets, no scanner logic.** Only capability: HTTPS call to the GLM endpoint | `normalizer` (types only) |
| `reports/render.py`   | Report JSON → HTML → PDF                | — |
| `db/store.py`         | All MongoDB access; scan records, findings, final reports. Nothing else touches Mongo | — |
| `models/schemas.py`   | Shared Pydantic types: `Finding`, `ScanRequest`, `ScanStatus`, `FinalReport` | — |

### `frontend/` (Next.js)

| Piece                  | Owns                                    |
|------------------------|-----------------------------------------|
| `ScanForm`             | URL input + **permission checkbox (required before submit)** |
| `ScanProgress`         | Polls `GET /scans/{id}`; renders phase + live progress; owns no authoritative state |
| `ReportPage`           | Fetches final report; severity badges, security score, findings list |
| `ReportExport`         | Download button → backend-rendered PDF |
| `lib/api.ts`           | The only place that knows the backend URL; typed client for the 3 endpoints |

The frontend never stores scan truth: it displays what the backend returns. A refresh must lose nothing.

## API contract (3 endpoints, nothing more)

```
POST /scans            { url, permission: true }  → { scan_id }         (400 on bad URL / missing permission)
GET  /scans/{id}       → { status, phase, progress_pct, error? }
GET  /scans/{id}/report → final report JSON        (404 until completed)
GET  /scans/{id}/report.pdf → PDF bytes
```

## Data model

One scan document in MongoDB is the source of truth:

```js
{
  _id, url, created_at,
  status: "created" | "scanning" | "analyzing" | "completed" | "failed",
  progress_pct, error,
  findings: [ Finding ],        // normalized, before AI
  report: FinalReport | null,   // { summary, security_score, findings: [ { severity, title, impact, fix } ] }
  report_html_path, report_pdf_path
}
```

## The AI boundary (hard rule)

GLM Flash must not perform scanning. This is enforced structurally, not by convention:

1. `glm_reporter` receives already-normalized `Finding` objects as its only input — it has no URL, no scanner subprocess access, and no code path that could probe anything.
2. Its only side-effect is one HTTPS call to the GLM API; its only output is the report JSON, validated against `FinalReport` before storage.
3. If GLM fails or returns malformed output, the scan still completes with the normalized findings — AI failure degrades the *report quality*, never the *scan results*.
4. Scanners (`zap_runner`, `nuclei_runner`) and the AI (`glm_reporter`) are siblings under `scan_service`; the AI never calls back into the scanner layer.

## State ownership summary

- **Scan state**: backend `scan_service`, persisted in Mongo. Frontend mirrors it via polling.
- **Findings**: produced by normalizer, stored unmodified.
- **Report**: written once by `glm_reporter` output + renderer; immutable after storage.
- **UI state**: purely derived from `GET /scans/{id}` and `GET /scans/{id}/report`.
