"""The five AIVA agents, implemented as LangGraph node functions.

Each node receives the shared state dict and returns a partial update.
Context + Exploitability enrich concurrently across all CVEs.
"""
from __future__ import annotations

import asyncio

from shared.grading import priority_score, severity_from_cvss
from shared.models import Asset, Finding

from . import parsers


# 1. Parser ------------------------------------------------------------------
def parser_agent(state: dict) -> dict:
    source, findings = parsers.parse(state["xml"], state.get("source"))
    return {"source": source, "findings": findings}


# 1b. Resolver: plugin-id -> CVE (only for CVE-less findings) ----------------
async def resolver_agent(state: dict) -> dict:
    resolver = state.get("resolver")
    findings: list[Finding] = state["findings"]
    if resolver is None or all(f.cve for f in findings):
        return {"findings": findings, "unresolved": 0}

    resolved: list[Finding] = []
    unresolved = 0
    for f in findings:
        if f.cve:                         # already has a CVE — keep as-is
            resolved.append(f)
            continue
        cves = await resolver.resolve(f.plugin_id)
        if not cves:
            unresolved += 1
            continue
        for cve in cves:                  # one finding per CVE
            resolved.append(f.model_copy(update={"cve": cve}))
    if hasattr(resolver, "flush"):
        resolver.flush()
    return {"findings": resolved, "unresolved": unresolved}


# 2. Context: baseline CVSS from NVD/MITRE -----------------------------------
async def context_agent(state: dict) -> dict:
    intel = state["intel"]
    findings: list[Finding] = state["findings"]

    async def fill(f: Finding):
        if f.cvss <= 0:                       # only fetch when scanner lacked it
            f.cvss = await intel.cvss(f.cve)
            f.severity = severity_from_cvss(f.cvss)
        return f

    await asyncio.gather(*(fill(f) for f in findings))
    return {"findings": findings}


# 3. Exploitability: EPSS + CISA KEV -----------------------------------------
async def exploitability_agent(state: dict) -> dict:
    intel = state["intel"]
    findings: list[Finding] = state["findings"]
    kev = await intel.kev_set()

    async def fill(f: Finding):
        f.epss = await intel.epss(f.cve)
        f.in_kev = f.cve.upper() in kev
        return f

    await asyncio.gather(*(fill(f) for f in findings))
    return {"findings": findings}


# 4. Prioritization: deterministic ranking -----------------------------------
def prioritization_agent(state: dict) -> dict:
    crit = {a.host: a.criticality for a in state.get("assets", [])}
    for f in state["findings"]:
        f.priority_score = priority_score(f, crit.get(f.host, 1.0))
    return {"findings": state["findings"]}


# 5. Recommendation: LLM-tailored action per finding (deterministic fallback) ---
async def recommendation_agent(state: dict) -> dict:
    reasoner = state.get("reasoner")
    findings: list[Finding] = state["findings"]
    if reasoner is None:
        for f in findings:
            f.recommendation = _recommend(f)
        return {"findings": findings}

    async def fill(f: Finding):
        f.recommendation = await reasoner.recommend(f, _recommend(f))
        return f

    await asyncio.gather(*(fill(f) for f in findings))
    return {"findings": findings}


# 6. Summary: LLM executive briefing over the ranked set --------------------
async def summary_agent(state: dict) -> dict:
    reasoner = state.get("reasoner")
    if reasoner is None:
        return {"summary": ""}
    ranked = sorted(state["findings"], key=lambda f: f.priority_score,
                    reverse=True)
    return {"summary": await reasoner.summary(ranked)}


def _recommend(f: Finding) -> str:
    if f.in_kev:
        return ("Actively exploited (CISA KEV). Apply vendor patch now; "
                "isolate or virtually patch the host until done.")
    if f.cvss >= 9.0:
        return "Critical. Patch within 72h; restrict network exposure meanwhile."
    if f.epss >= 0.3:
        return "Elevated exploit probability. Patch within 7 days."
    if f.cvss >= 7.0:
        return "High severity. Schedule patch this cycle."
    if f.cvss > 0:
        return "Track and patch during routine maintenance."
    return "Insufficient data; verify finding manually."
