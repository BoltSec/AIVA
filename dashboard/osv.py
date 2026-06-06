"""OSV.dev client — maps packages to known vulnerabilities.

live    : POST https://api.osv.dev/v1/querybatch  (needs network)
offline : dashboard/fixtures/offline_osv.json     (test tonight)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from cvss import CVSS2, CVSS3, CVSS4

from shared.grading import severity_from_cvss
from shared.models import Package, Vulnerability

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns"
_FIXTURE = Path(__file__).parent / "fixtures" / "offline_osv.json"

# Map OSV's qualitative database_specific.severity to a representative score.
_QUAL = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5,
         "LOW": 2.5, "NONE": 0.0}


def _score_from_vector(vector: str) -> float:
    """Compute a CVSS base score from a vector string (v2/v3/v4)."""
    vector = (vector or "").strip()
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).scores()[0])
        if vector.startswith("AV:") or vector.startswith("CVSS:2"):
            return float(CVSS2(vector).scores()[0])
    except Exception:
        pass
    # Some feeds put a bare number in score; accept that too.
    try:
        return max(0.0, min(10.0, float(vector)))
    except (TypeError, ValueError):
        return 0.0


def _cvss_from_record(raw: dict) -> float:
    """Best available CVSS: parse vector(s), else fall back to qualitative."""
    best = 0.0
    for s in raw.get("severity", []) or []:
        best = max(best, _score_from_vector(s.get("score", "")))
    if best == 0.0:
        qual = (raw.get("database_specific", {}) or {}).get("severity", "")
        best = _QUAL.get(str(qual).upper(), 0.0)
    return round(best, 1)


def _to_vuln(raw: dict, pkg: Package) -> Vulnerability:
    fixed = None
    for affected in raw.get("affected", []):
        for rng in affected.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed = ev["fixed"].rstrip(".")
    cvss = _cvss_from_record(raw)
    return Vulnerability(
        id=raw.get("id", "UNKNOWN"),
        summary=raw.get("summary", "") or raw.get("details", "")[:160],
        cvss=cvss, severity=severity_from_cvss(cvss),
        fixed_version=fixed,
        references=[r.get("url", "") for r in raw.get("references", [])][:5],
    )


class OSVClient:
    async def query(self, pkgs: list[Package]) -> dict[str, list[Vulnerability]]:
        raise NotImplementedError


class OfflineOSV(OSVClient):
    def __init__(self, path: Path = _FIXTURE):
        self._db = json.loads(Path(path).read_text())

    async def query(self, pkgs):
        out: dict[str, list[Vulnerability]] = {}
        for p in pkgs:
            key = f"{p.ecosystem}:{p.name}:{p.version}"
            raws = self._db.get(key, [])
            out[key] = [_to_vuln(r, p) for r in raws]
        return out


class LiveOSV(OSVClient):
    def __init__(self, timeout: float = 30.0):
        self._client = httpx.AsyncClient(timeout=timeout)

    async def query(self, pkgs):
        queries = [{"package": {"ecosystem": p.ecosystem, "name": p.name},
                    "version": p.version} for p in pkgs]
        r = await self._client.post(OSV_BATCH, json={"queries": queries})
        r.raise_for_status()
        results = r.json().get("results", [])
        out: dict[str, list[Vulnerability]] = {}
        for p, res in zip(pkgs, results):
            key = f"{p.ecosystem}:{p.name}:{p.version}"
            vulns = []
            for stub in res.get("vulns", []):
                full = await self._client.get(f"{OSV_VULN}/{stub['id']}")
                if full.status_code == 200:
                    vulns.append(_to_vuln(full.json(), p))
            out[key] = vulns
        return out

    async def aclose(self):
        await self._client.aclose()


def build_osv(mode: str | None = None) -> OSVClient:
    mode = mode or os.getenv("DASH_OSV_MODE", "offline")
    return LiveOSV() if mode == "live" else OfflineOSV()
