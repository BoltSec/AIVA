# Dependency Risk Platform

Dual-purpose security tooling:

- **Component A — Dependency Risk Dashboard** (`dashboard/`): FastAPI web app.
  Upload `requirements.txt` / `package.json`, get an A–F risk grade + PDF report.
- **Component B — AIVA** (`aiva/`): LangGraph CLI pipeline. Digests Nessus /
  OpenVAS XML, enriches with NVD + EPSS + CISA KEV, outputs a prioritized
  remediation plan (JSON + PDF).

Both share `shared/` (models, grading formulas, PDF generation).

## Where to put your credentials (read this)

There is exactly **one secret** in this project: your NVD API key. Everything
else is keyless.

1. Copy `.env.example` to `.env` and edit it:
   ```
   cp .env.example .env
   ```
2. **NVD key** → put your rotated key on the `NVD_API_KEY` line in `.env`.
   The code reads it via `os.getenv("NVD_API_KEY")` — never hard-code it.
3. **CISA KEV file** → drop your downloaded
   `known_exploited_vulnerabilities.json` into `config/`, then point
   `AIVA_KEV_FILE` at it in `.env`. AIVA uses that local file instead of
   re-downloading from CISA. (A small `config/sample_kev.json` is included so
   you can test the path immediately.)
4. Load the file before running, e.g. `set -a; source .env; set +a`.

OSV, EPSS, and the live CISA fetch need no credentials at all.

## Turning on the AI agent (FREE)

By default AIVA's recommendations are deterministic templates. To make the
Recommendation agent *reason* — tailored remediation per CVE/host plus an
executive summary — point it at a free LLM provider. Gemini's free tier is the
most generous (no credit card):

```
AIVA_LLM_PROVIDER=gemini          # gemini | groq | openrouter | ollama | openai
GEMINI_API_KEY=...                # free at https://aistudio.google.com
```

Other free options: `groq` (fastest, key at console.groq.com), `openrouter`
(many free models), or `ollama` (fully local, no key, no network). Switching
providers is one env var — the code is provider-agnostic (OpenAI-compatible).

What stays deterministic: parsing, scoring, and ranking. The LLM never decides
priority — it only explains and advises — so rankings remain reproducible and
auditable. With no key, AIVA falls back to the template recommendations and
still runs (and all tests pass).

## Setup

```bash
pip install -r requirements.txt
```

## Test (offline, no network/keys)

```bash
pytest -q          # 10 tests, full pipeline + API
```

## Run AIVA

```bash
# offline (uses aiva/fixtures/offline_intel.json)
python -m aiva.cli scan aiva/fixtures/sample_openvas.xml \
    --asset 10.0.1.21=2.0 --json plan.json --pdf plan.pdf

# live threat intel (needs outbound network; NVD key optional)
export AIVA_INTEL_MODE=live
export NVD_API_KEY=...        # optional, raises rate limit
python -m aiva.cli scan report.nessus --mode live --pdf plan.pdf
```

`--asset host=criticality` weights ranking (0.5 low … 2.0 crown-jewel).

## Run Dashboard

```bash
uvicorn dashboard.main:app --reload
# open http://127.0.0.1:8000   (demo key: dev-key-001)
```

Live OSV.dev instead of fixtures:

```bash
export DASH_OSV_MODE=live
uvicorn dashboard.main:app
```

Demo API keys (`dashboard/auth.py`): `dev-key-001` (developer),
`admin-key-001` (admin). Send as `X-API-Key` header.

## How the pieces connect

```
shared/models.py    one vocabulary for both components
shared/grading.py   grade_scan()  -> A–F   |   priority_score() -> ranking
shared/pdf_report.py both PDF outputs

aiva/parsers.py     Nessus + OpenVAS XML -> Finding[]
aiva/clients.py     NVD / EPSS / KEV   (offline | live)
aiva/agents.py      5 agent node functions
aiva/pipeline.py    LangGraph StateGraph wiring + run_pipeline()
aiva/cli.py         Typer CLI

dashboard/parsers.py  requirements.txt / package.json -> Package[]
dashboard/osv.py      OSV.dev          (offline | live)
dashboard/auth.py     RBAC + audit log
dashboard/main.py     FastAPI: /scan, /report/{id}.pdf, /audit
```

## Before production (hardening checklist)

- Replace in-memory `_scans`, `_audit`, `_USERS` with a real DB + user store.
- Add `defusedxml` for parsing untrusted scanner XML.
- Add retry/backoff + response caching on the NVD/EPSS/OSV clients (they
  rate-limit hard at scale).
- Rate-limit `/scan`; scan uploads for zip-bombs beyond the 2 MB cap.
- The priority score clamps at 100 — lift the cap in `shared/grading.py` if you
  want finer separation among top KEV findings.
```
