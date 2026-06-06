"""Threat-intelligence clients: NVD, EPSS, CISA KEV.

Two modes:
  - live    : real async HTTP calls (needs outbound network)
  - offline : reads aiva/fixtures/offline_intel.json (test tonight, no keys)

Swap by passing mode= to build_intel() or env AIVA_INTEL_MODE.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx

_FIXTURE = Path(__file__).parent / "fixtures" / "offline_intel.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


class Intel:
    """Per-CVE enrichment: cvss, epss, in_kev, description."""

    async def cvss(self, cve: str) -> float: ...
    async def epss(self, cve: str) -> float: ...
    async def kev_set(self) -> set[str]: ...
    async def description(self, cve: str) -> str: ...


class OfflineIntel(Intel):
    def __init__(self, path: Path = _FIXTURE):
        self._data = json.loads(Path(path).read_text())

    async def cvss(self, cve: str) -> float:
        return float(self._data.get("cvss", {}).get(cve.upper(), 0.0))

    async def epss(self, cve: str) -> float:
        return float(self._data.get("epss", {}).get(cve.upper(), 0.0))

    async def kev_set(self) -> set[str]:
        return {c.upper() for c in self._data.get("kev", [])}

    async def description(self, cve: str) -> str:
        return self._data.get("descriptions", {}).get(cve.upper(), "")


class LiveIntel(Intel):
    def __init__(self, api_key: str | None = None, timeout: float = 20.0,
                 kev_file: str | None = None):
        headers = {"apiKey": api_key} if api_key else {}
        self._client = httpx.AsyncClient(timeout=timeout, headers=headers)
        self._kev: set[str] | None = None
        self._kev_file = kev_file or os.getenv("AIVA_KEV_FILE")

    async def _nvd(self, cve: str) -> dict:
        try:
            r = await self._client.get(NVD_URL, params={"cveId": cve})
            r.raise_for_status()
            return r.json()
        except Exception:
            return {}

    async def cvss(self, cve: str) -> float:
        data = await self._nvd(cve)
        try:
            metrics = data["vulnerabilities"][0]["cve"]["metrics"]
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    return float(metrics[key][0]["cvssData"]["baseScore"])
        except (KeyError, IndexError):
            pass
        return 0.0

    async def description(self, cve: str) -> str:
        data = await self._nvd(cve)
        try:
            for d in data["vulnerabilities"][0]["cve"]["descriptions"]:
                if d["lang"] == "en":
                    return d["value"]
        except (KeyError, IndexError):
            pass
        return ""

    async def epss(self, cve: str) -> float:
        try:
            r = await self._client.get(EPSS_URL, params={"cve": cve})
            r.raise_for_status()
            rows = r.json().get("data", [])
            return float(rows[0]["epss"]) if rows else 0.0
        except Exception:
            return 0.0

    async def kev_set(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        try:
            # Prefer a locally downloaded CISA catalog if one is configured.
            if self._kev_file and Path(self._kev_file).exists():
                data = json.loads(Path(self._kev_file).read_text())
            else:
                r = await self._client.get(KEV_URL)
                r.raise_for_status()
                data = r.json()
            self._kev = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
        except Exception:
            self._kev = set()
        return self._kev

    async def aclose(self):
        await self._client.aclose()


def build_intel(mode: str | None = None) -> Intel:
    mode = mode or os.getenv("AIVA_INTEL_MODE", "offline")
    if mode == "live":
        return LiveIntel(api_key=os.getenv("NVD_API_KEY"),
                         kev_file=os.getenv("AIVA_KEV_FILE"))
    return OfflineIntel()
