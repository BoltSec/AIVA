"""Shared data models used by both the Dashboard and AIVA.

Every external boundary (file parse, API response, report) is normalised
into these types so the two components speak one language.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Component A — dependency scanning
# ---------------------------------------------------------------------------
class Package(BaseModel):
    """A single resolved dependency from a manifest file."""
    ecosystem: str               # "PyPI" | "npm"
    name: str
    version: str


class Vulnerability(BaseModel):
    """One CVE/advisory affecting a package or host."""
    id: str                      # CVE-... or GHSA-... or OSV id
    summary: str = ""
    cvss: float = 0.0            # base score 0-10
    severity: Severity = Severity.NONE
    fixed_version: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class PackageFinding(BaseModel):
    package: Package
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    @property
    def worst_cvss(self) -> float:
        return max((v.cvss for v in self.vulnerabilities), default=0.0)


class DependencyScan(BaseModel):
    """Result of scanning one manifest file (Component A output)."""
    scan_id: str
    filename: str
    ecosystem: str
    created_at: datetime = Field(default_factory=_now)
    findings: list[PackageFinding] = Field(default_factory=list)
    grade: Grade = Grade.A
    score: float = 100.0         # 0-100, higher is safer

    @property
    def vulnerable_packages(self) -> int:
        return sum(1 for f in self.findings if f.vulnerabilities)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(f.vulnerabilities) for f in self.findings)


# ---------------------------------------------------------------------------
# Component B — AIVA reactive pipeline
# ---------------------------------------------------------------------------
class Asset(BaseModel):
    host: str
    criticality: float = 1.0     # 0.5 low .. 2.0 crown-jewel


class Finding(BaseModel):
    """A vulnerability observed on a host by a scanner (Nessus/OpenVAS)."""
    host: str
    cve: str
    name: str = ""
    service: str = ""            # human service/product label (e.g. "OpenSSL")
    plugin_id: str = ""          # Nessus plugin id (when CVE absent in export)
    cvss: float = 0.0
    severity: Severity = Severity.NONE
    # enrichment, filled by later agents:
    epss: float = 0.0            # 0-1 probability of exploitation
    in_kev: bool = False         # listed in CISA Known Exploited Vulns
    priority_score: float = 0.0
    recommendation: str = ""


class RemediationPlan(BaseModel):
    scan_source: str             # "nessus" | "openvas"
    created_at: datetime = Field(default_factory=_now)
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""            # LLM executive briefing (empty if no LLM)

    @property
    def ranked(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.priority_score, reverse=True)
