"""Interactive AIVA agent (Level 1 grounded Q&A + Level 2 tool use).

Level 1: every reply is grounded in the current scan's findings, which are
injected into the system prompt.
Level 2: the model can call tools to fetch a specific finding, filter the
list, re-rank by asset criticality, or pull fresh live CVE data — deciding
for itself when a tool is needed, then answering with the result.

Runs on the same provider config as the rest of AIVA (Groq/Gemini/etc.).
"""
from __future__ import annotations

import asyncio
import json
import re

from shared.grading import priority_score, severity_from_cvss
from shared.models import RemediationPlan

from .clients import build_intel
from .llm import _config

_MAX_STEPS = 4        # cap tool-use iterations per question
_MAX_TOKENS = 400     # keep responses short to stay under TPM limits
_GROUNDING_LIMIT = 15 # top-N findings sent in every message

_SYSTEM = """\
You are AIVA, a vulnerability-triage assistant grounded in the user's current scan results.

RULES — follow every one of these exactly:

1. NEVER GUESS CVE FACTS. If the user asks what a CVE is, what caused it, which component is affected, or any technical detail not present in the grounding data, you MUST call lookup_cve_live and base your answer on the 'description' field it returns. LLM training memory for specific CVEs is unreliable — do not use it.

2. BE SPECIFIC AND ACTIONABLE. Never say "consider implementing compensating controls" or "you may want to patch". State the exact fix: the specific config key to change, the service to disable, the version to upgrade to. If the exact version is unknown, say "check the vendor advisory" and explain what to look for.

3. NEVER OUTPUT TOOL CALL SYNTAX. Do not write <function=...>, (function=...), or any markup in your reply text. Tool calls happen silently. Your output is plain prose only.

4. SCAN-PATTERN QUESTIONS ARE IN SCOPE. Questions like "why are most CVEs SSL-related?" or "which host has the most issues?" are valid — answer them from the grounding data. If the question is not about security, vulnerability triage, or this scan, do NOT engage with it at all. Respond with exactly: "I only answer questions about this scan. Please ask about the vulnerabilities, findings, or remediation steps." Do not add anything else.

5. ADMIT UNCERTAINTY, THEN LOOK IT UP. If you are unsure of a fact, say "I don't have that detail — let me check" and call the appropriate tool. Never say "it can be inferred" or "let's assume" — these phrases indicate you are guessing.

6. NEVER ASSUME A CVE IS ABSENT. The grounding data shows only the top-ranked findings. If the user asks about a specific CVE that you do not see in the grounding data, you MUST call get_finding for that CVE first. Only say a CVE is not in this scan if get_finding returns an error saying it is not found.

7. PATCH VERSIONS. Whenever you name a specific fixed version, append: "verify this against the vendor advisory before applying."

8. KEEP ANSWERS CONCISE. 3–5 sentences maximum unless the user explicitly asks for more detail.\
"""

_TOOLS = [
    {"type": "function", "function": {
        "name": "get_finding",
        "description": (
            "Return the full scan record for one CVE: host, service, CVSS, EPSS, "
            "KEV status, priority score, and pre-generated recommendation. "
            "Call this when the user asks for remediation steps or full details "
            "of a specific CVE that is already in the scan."
        ),
        "parameters": {"type": "object", "properties": {
            "cve": {"type": "string", "description": "CVE id, e.g. CVE-2020-1938"}},
            "required": ["cve"]}}},
    {"type": "function", "function": {
        "name": "list_findings",
        "description": (
            "Return a filtered, priority-sorted list of findings. Use when the "
            "user asks for top-N findings, KEV-only findings, or findings above "
            "a certain score. Do not call this for a single named CVE — use "
            "get_finding instead."
        ),
        "parameters": {"type": "object", "properties": {
            "kev_only": {"type": "boolean",
                         "description": "If true, return only CISA KEV findings."},
            "min_score": {"type": "number",
                          "description": "Minimum priority score (0-100)."},
            "limit": {"type": "integer",
                      "description": "Maximum number of findings to return."}}}}},
    {"type": "function", "function": {
        "name": "recompute_priority",
        "description": (
            "Re-rank all findings after changing the asset criticality of one "
            "host (0.5 = low-value, 1.0 = default, 2.0 = crown-jewel). Call "
            "this when the user says a host is critical or asks what changes if "
            "a specific host is treated as high-value."
        ),
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string", "description": "IP or hostname to adjust."},
            "criticality": {"type": "number",
                            "description": "Asset weight: 0.5 low, 1.0 normal, 2.0 crown-jewel."}},
            "required": ["host", "criticality"]}}},
    {"type": "function", "function": {
        "name": "lookup_cve_live",
        "description": (
            "Fetch authoritative live data from NVD for any CVE: the official "
            "description (root cause, affected component, vulnerability class), "
            "current CVSS score, EPSS exploitation probability, and CISA KEV "
            "status. YOU MUST call this whenever the user asks what a CVE is, "
            "what caused it, which component is affected, or any technical detail "
            "not already in the grounding data. Never answer CVE-specific "
            "technical questions from memory."
        ),
        "parameters": {"type": "object", "properties": {
            "cve": {"type": "string", "description": "CVE id, e.g. CVE-2008-5161"}},
            "required": ["cve"]}}},
]


def _finding_dict(f):
    return {"cve": f.cve, "host": f.host, "service": f.service,
            "cvss": f.cvss, "severity": f.severity.value, "epss": round(f.epss, 3),
            "in_kev": f.in_kev, "priority_score": f.priority_score,
            "recommendation": f.recommendation}


def _grounding(plan: RemediationPlan) -> str:
    ranked = plan.ranked[:_GROUNDING_LIMIT]
    total = len(plan.ranked)
    rows = []
    for i, f in enumerate(ranked):
        name = f" \"{f.name}\"" if f.name else ""
        rows.append(
            f"{i+1}. {f.cve}{name} [{f.service}] on {f.host} — "
            f"CVSS {f.cvss}, EPSS {f.epss:.2f}, "
            f"KEV={'yes' if f.in_kev else 'no'}, score {f.priority_score:.0f}"
        )
    note = f" (top {_GROUNDING_LIMIT} of {total})" if total > _GROUNDING_LIMIT else ""
    return (
        f"SCAN FINDINGS{note} ranked by priority — use as source of truth:\n"
        + "\n".join(rows)
        + "\nFor CVE technical details, call lookup_cve_live."
    )


class _Tools:
    def __init__(self, plan: RemediationPlan):
        self.plan = plan

    async def call(self, name: str, args: dict) -> dict:
        fn = getattr(self, name, None)
        if fn is None:
            return {"error": f"unknown tool {name}"}
        return await fn(args)

    async def get_finding(self, a):
        cve = (a.get("cve") or "").upper()
        for f in self.plan.findings:
            if f.cve.upper() == cve:
                return _finding_dict(f)
        return {"error": "CVE not in this scan"}

    async def list_findings(self, a):
        items = self.plan.ranked
        if a.get("kev_only"):
            items = [f for f in items if f.in_kev]
        if a.get("min_score") is not None:
            items = [f for f in items if f.priority_score >= a["min_score"]]
        items = items[: int(a.get("limit", 10))]
        return {"findings": [_finding_dict(f) for f in items]}

    async def recompute_priority(self, a):
        host, crit = a.get("host"), float(a.get("criticality", 1.0))
        scored = []
        for f in self.plan.findings:
            c = crit if f.host == host else 1.0
            scored.append((priority_score(f, c), f))
        scored.sort(key=lambda x: x[0], reverse=True)
        return {"reranked_top": [
            {"cve": f.cve, "host": f.host, "new_score": round(s, 1)}
            for s, f in scored[:10]]}

    async def lookup_cve_live(self, a):
        cve = (a.get("cve") or "").upper()
        intel = build_intel()
        try:
            cvss, desc, epss, kev = await asyncio.gather(
                intel.cvss(cve),
                intel.description(cve),
                intel.epss(cve),
                intel.kev_set(),
            )
            return {"cve": cve, "cvss": cvss, "severity": severity_from_cvss(cvss).value,
                    "epss": round(epss, 3), "in_kev": cve in kev,
                    "description": desc or "No NVD description available."}
        except Exception as e:
            return {"error": f"live lookup failed: {e}"}


def _is_tool_fail(exc: Exception) -> bool:
    s = str(exc)
    return "tool_use_failed" in s or "tool_call_failed" in s or "failed_generation" in s


def _is_tpm_limit(exc: Exception) -> bool:
    s = str(exc)
    return ("429" in s or "rate_limit_exceeded" in s) and "tokens per minute" in s


def _parse_retry_wait(exc: Exception) -> float:
    """Extract the 'try again in Xs' wait from a Groq 429 message."""
    m = re.search(r"try again in (\d+\.?\d*)\s*s", str(exc), re.IGNORECASE)
    return float(m.group(1)) + 1.0 if m else 20.0


async def run_chat(plan: RemediationPlan, history: list[dict]) -> str:
    from openai import AsyncOpenAI
    _, base_url, model, api_key = _config()
    if not api_key:
        return ("The AI agent isn't configured. Set an LLM provider key "
                "(e.g. GROQ_API_KEY) to enable chat.")
    api_key = "".join(api_key.split())
    client = AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=30,
                         max_retries=0)
    tool_executor = _Tools(plan)

    base_messages = [{"role": "system", "content": _SYSTEM},
                     {"role": "system", "content": _grounding(plan)}]
    base_messages += [{"role": m["role"], "content": m["content"]} for m in history]

    async def _attempt(messages: list, with_tools: bool) -> str:
        for _ in range(_MAX_STEPS):
            kwargs: dict = dict(model=model, messages=messages, max_tokens=_MAX_TOKENS)
            if with_tools:
                kwargs["tools"] = _TOOLS
                kwargs["tool_choice"] = "auto"
            resp = await client.chat.completions.create(**kwargs)
            msg = resp.choices[0].message
            if not msg.tool_calls:
                return (msg.content or "").strip()
            messages.append({
                "role": "assistant", "content": msg.content or "",
                "tool_calls": [{"id": tc.id, "type": "function",
                                "function": {"name": tc.function.name,
                                             "arguments": tc.function.arguments}}
                               for tc in msg.tool_calls]})
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                result = await tool_executor.call(tc.function.name, args)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result)})
        return "I couldn't complete that in time — try asking more specifically."

    async def _run_with_retries(with_tools: bool) -> str:
        for attempt in range(2):   # one retry after TPM wait
            try:
                return await _attempt(list(base_messages), with_tools=with_tools)
            except Exception as e:
                if _is_tpm_limit(e) and attempt == 0:
                    wait = _parse_retry_wait(e)
                    await asyncio.sleep(wait)
                    continue
                raise
        return "Rate limit — please try again in a moment."

    try:
        return await _run_with_retries(with_tools=True)
    except Exception as e:
        if _is_tool_fail(e):
            # Model produced malformed tool-call syntax — retry without tools.
            # The grounding context already contains all findings, so the model
            # can answer most questions from that alone.
            try:
                return await _run_with_retries(with_tools=False)
            except Exception as e2:
                return f"Chat error: {e2}"
        return f"Chat error: {e}"
