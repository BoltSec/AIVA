"""Component A — Dependency Risk Dashboard API (FastAPI).

Run: uvicorn dashboard.main:app --reload
Auth via X-API-Key header (see dashboard/auth.py for demo keys).
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from shared.grading import grade_scan
from shared.models import Asset, DependencyScan, PackageFinding
from shared.pdf_report import dependency_report, remediation_report

from aiva.pipeline import run_pipeline
from aiva.chat import run_chat

from . import parsers
from .auth import audit_log, log_event, require
from .osv import build_osv

MAX_BYTES      = 2  * 1024 * 1024   # 2 MB  — dependency manifests
MAX_SCAN_BYTES = 25 * 1024 * 1024   # 25 MB — scanner exports

# Allowed MIME types for the two upload endpoints
_MANIFEST_ALLOWED_EXT  = {".txt", ".json"}
_SCAN_ALLOWED_EXT      = {".xml", ".nessus"}

# Regex that matches only safe filename characters for log sanitisation
_SAFE_FNAME_RE = re.compile(r"[^\w.\-]")


def _safe_fname(name: str | None) -> str:
    """Strip characters that could be used for log injection."""
    if not name:
        return "<unnamed>"
    sanitised = _SAFE_FNAME_RE.sub("_", name)
    return sanitised[:120]   # cap length


app = FastAPI(title="Dependency Risk Platform")
_scans: dict[str, DependencyScan] = {}   # demo store; replace with DB
_plans: dict[str, object] = {}           # AIVA remediation plans


# ---------------------------------------------------------------------------
# Security headers middleware (A05)
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # CSP: allow inline scripts/styles (required by the single-file SPA),
        # Google Fonts, and same-origin fetch — block everything else.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    html = (Path(__file__).parent / "static" / "index.html").read_text(
        encoding="utf-8")
    return HTMLResponse(content=html, media_type="text/html; charset=utf-8")


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    ident: dict = Depends(require("developer")),
):
    # Validate file extension (A05 — restrict accepted file types)
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _MANIFEST_ALLOWED_EXT:
        raise HTTPException(400, "Unsupported file type — upload requirements.txt or package.json")

    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 2 MB limit")
    try:
        eco, packages, skipped = parsers.parse(file.filename, content)
    except (ValueError, UnicodeError) as e:
        raise HTTPException(400, f"Parse error: {e}")

    vulns = await build_osv().query(packages)
    findings = [
        PackageFinding(package=p,
                       vulnerabilities=vulns.get(
                           f"{p.ecosystem}:{p.name}:{p.version}", []))
        for p in packages
    ]
    scan_id = uuid.uuid4().hex[:12]
    result = grade_scan(DependencyScan(
        scan_id=scan_id, filename=file.filename, ecosystem=eco,
        findings=findings))
    _scans[scan_id] = result
    log_event(ident["user"], "scan",
              f"{_safe_fname(file.filename)} grade={result.grade.value} "
              f"vulns={result.total_vulnerabilities}")
    return {
        "scan_id": scan_id, "grade": result.grade.value, "score": result.score,
        "ecosystem": eco, "packages": len(packages),
        "vulnerable_packages": result.vulnerable_packages,
        "total_vulnerabilities": result.total_vulnerabilities,
        "skipped": skipped,
        "report_url": f"/report/{scan_id}.pdf",
    }


@app.get("/report/{scan_id}.pdf")
def report(scan_id: str, ident: dict = Depends(require("developer"))):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Unknown scan id")
    log_event(ident["user"], "download", scan_id)
    return Response(dependency_report(scan), media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="{scan_id}.pdf"'})


@app.post("/aiva/scan")
async def aiva_scan(
    file: UploadFile = File(...),
    ident: dict = Depends(require("developer")),
):
    """Run the AIVA pipeline on a Nessus / OpenVAS export (Component B, web)."""
    # Validate file extension (A05)
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _SCAN_ALLOWED_EXT:
        raise HTTPException(400, "Unsupported file type — upload a .nessus or .xml export")

    content = await file.read()
    if len(content) > MAX_SCAN_BYTES:
        raise HTTPException(413, "Scan file too large")
    try:
        plan = await run_pipeline(content)   # mode from AIVA_INTEL_MODE env
    except ValueError as e:
        raise HTTPException(400, f"Unrecognised scan format: {e}")
    except Exception:
        # Do not expose internal exception details to the client (A05/A09)
        raise HTTPException(502, "Enrichment pipeline failed — check server logs")

    plan_id = uuid.uuid4().hex[:12]
    _plans[plan_id] = plan
    log_event(ident["user"], "aiva_scan",
              f"{_safe_fname(file.filename)} source={plan.scan_source} "
              f"findings={len(plan.findings)}")
    ranked = plan.ranked
    return {
        "plan_id": plan_id, "source": plan.scan_source,
        "summary": plan.summary,
        "findings": [
            {"host": f.host, "cve": f.cve, "service": f.service, "cvss": f.cvss,
             "epss": round(f.epss, 3), "in_kev": f.in_kev,
             "score": f.priority_score, "action": f.recommendation}
            for f in ranked
        ],
        "report_url": f"/aiva/report/{plan_id}.pdf",
    }


@app.get("/aiva/report/{plan_id}.pdf")
def aiva_report(plan_id: str, ident: dict = Depends(require("developer"))):
    plan = _plans.get(plan_id)
    if not plan:
        raise HTTPException(404, "Unknown plan id")
    log_event(ident["user"], "aiva_download", plan_id)
    return Response(remediation_report(plan), media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="aiva-{plan_id}.pdf"'})


@app.post("/chat")
async def chat(payload: dict = Body(...),
               ident: dict = Depends(require("developer"))):
    """Interactive agent grounded in a scan's findings."""
    plan = _plans.get(payload.get("plan_id"))
    if not plan:
        raise HTTPException(404, "Unknown plan id — run a scan first")

    # Validate message list structure (A08 — data integrity)
    history = payload.get("messages", [])
    if not isinstance(history, list):
        raise HTTPException(400, "messages must be a list")
    if not history:
        raise HTTPException(400, "No message")
    validated: list[dict] = []
    for msg in history:
        if not isinstance(msg, dict):
            raise HTTPException(400, "Each message must be an object")
        role    = msg.get("role",    "")
        content = msg.get("content", "")
        if role not in ("user", "assistant"):
            raise HTTPException(400, f"Invalid message role: {role!r}")
        if not isinstance(content, str):
            raise HTTPException(400, "Message content must be a string")
        if len(content) > 4000:
            raise HTTPException(400, "Message content exceeds 4000 characters")
        validated.append({"role": role, "content": content})

    answer = await run_chat(plan, validated)
    # Log only a safe excerpt of the last user message (A09)
    last_user = next((m["content"] for m in reversed(validated)
                      if m["role"] == "user"), "")
    log_event(ident["user"], "chat", last_user[:80])
    return {"answer": answer}


@app.get("/audit")
def audit(ident: dict = Depends(require("admin"))):
    return audit_log()
