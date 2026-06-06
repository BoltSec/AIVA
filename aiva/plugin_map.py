"""Resolve Nessus plugin IDs to CVEs.

Some Nessus exports (e.g. the Essentials API summary view) list findings by
plugin ID with no CVE attached. NVD/EPSS/KEV are all keyed by CVE, so we must
recover the CVE before enrichment can run.

Two sources, tried in order:
  1. Local map  (aiva/fixtures/plugin_cve_map.json) — instant, offline, seeded
     with common plugins. Grows as a cache.
  2. Live Tenable plugin page (only if AIVA_PLUGIN_LOOKUP=live) — authoritative,
     covers any plugin, needs internet. Results are cached back to the map.

Plenty of plugins legitimately have NO CVE (config issues, end-of-life,
insecure services). Those resolve to an empty list and are reported as such.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx

_MAP_PATH = Path(__file__).parent / "fixtures" / "plugin_cve_map.json"
_TENABLE = "https://www.tenable.com/plugins/nessus/{id}"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class PluginResolver:
    def __init__(self, live: bool | None = None, map_path: Path = _MAP_PATH):
        self._path = Path(map_path)
        self._map: dict[str, list[str]] = (
            json.loads(self._path.read_text()) if self._path.exists() else {})
        self._live = (os.getenv("AIVA_PLUGIN_LOOKUP", "offline") == "live"
                      if live is None else live)
        self._client = httpx.AsyncClient(timeout=20.0) if self._live else None
        self._dirty = False

    async def resolve(self, plugin_id: str) -> list[str]:
        pid = str(plugin_id)
        if pid in self._map:
            return self._map[pid]
        if not self._live:
            return []
        cves = await self._fetch_tenable(pid)
        self._map[pid] = cves          # cache even empties to avoid refetch
        self._dirty = True
        return cves

    async def _fetch_tenable(self, pid: str) -> list[str]:
        try:
            r = await self._client.get(_TENABLE.format(id=pid))
            if r.status_code != 200:
                return []
            return sorted(set(_CVE_RE.findall(r.text)))
        except Exception:
            return []

    def flush(self):
        if self._dirty:
            self._path.write_text(json.dumps(self._map, indent=2, sort_keys=True))
            self._dirty = False

    async def aclose(self):
        self.flush()
        if self._client:
            await self._client.aclose()


def build_resolver() -> PluginResolver:
    return PluginResolver()
