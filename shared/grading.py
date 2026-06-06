"""Deterministic scoring used by both components.

Two pure functions, no I/O — trivially unit-testable and auditable.
"""
from __future__ import annotations

from .models import DependencyScan, Finding, Grade, Severity


def severity_from_cvss(cvss: float) -> Severity:
    if cvss <= 0:
        return Severity.NONE
    if cvss < 4.0:
        return Severity.LOW
    if cvss < 7.0:
        return Severity.MEDIUM
    if cvss < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


# ---- Component A: dependency risk grade -----------------------------------
# Each vulnerable package costs points proportional to its worst CVSS.
# Start at 100, subtract, clamp, then map to a letter.
_PENALTY = {  # weight per worst-CVSS band
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 2.0,
    Severity.NONE: 0.0,
}


def grade_scan(scan: DependencyScan) -> DependencyScan:
    """Mutate and return the scan with a numeric score and letter grade."""
    score = 100.0
    for finding in scan.findings:
        if not finding.vulnerabilities:
            continue
        band = severity_from_cvss(finding.worst_cvss)
        score -= _PENALTY[band]
    score = max(0.0, min(100.0, score))
    scan.score = round(score, 1)
    scan.grade = _letter(score)
    return scan


def _letter(score: float) -> Grade:
    if score >= 90:
        return Grade.A
    if score >= 80:
        return Grade.B
    if score >= 70:
        return Grade.C
    if score >= 60:
        return Grade.D
    if score >= 50:
        return Grade.E
    return Grade.F


# ---- Component B: AIVA priority score -------------------------------------
# Combines impact (CVSS), likelihood (EPSS + KEV), and asset value.
# Output range ~0..100. Deterministic, explainable, no ML.
def priority_score(finding: Finding, asset_criticality: float = 1.0) -> float:
    base = finding.cvss * 10.0          # 0..100 from impact
    likelihood = finding.epss           # 0..1
    kev_boost = 1.5 if finding.in_kev else 1.0
    # likelihood scales impact; KEV (proven exploited) is a hard multiplier.
    raw = base * (0.5 + 0.5 * likelihood) * kev_boost
    raw *= asset_criticality
    return round(min(raw, 100.0), 2)
