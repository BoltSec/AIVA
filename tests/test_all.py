"""End-to-end offline tests — no network required."""
import asyncio
from pathlib import Path

import pytest

from shared.grading import grade_scan, priority_score, severity_from_cvss
from shared.models import (DependencyScan, Finding, PackageFinding, Package,
                           Severity)

import aiva.parsers as aparse
from aiva.clients import OfflineIntel
from aiva.pipeline import run_pipeline
from shared.models import Asset

import dashboard.parsers as dparse
from dashboard.osv import OfflineOSV

ROOT = Path(__file__).resolve().parents[1]


def test_severity_bands():
    assert severity_from_cvss(0) is Severity.NONE
    assert severity_from_cvss(3.9) is Severity.LOW
    assert severity_from_cvss(6.9) is Severity.MEDIUM
    assert severity_from_cvss(8.9) is Severity.HIGH
    assert severity_from_cvss(9.0) is Severity.CRITICAL


def test_grade_clean_scan_is_A():
    scan = DependencyScan(scan_id="x", filename="r.txt", ecosystem="PyPI",
                          findings=[PackageFinding(
                              package=Package(ecosystem="PyPI", name="a",
                                              version="1.0"))])
    grade_scan(scan)
    assert scan.grade.value == "A" and scan.score == 100.0


def test_grade_drops_with_critical():
    from shared.models import Vulnerability
    pf = PackageFinding(
        package=Package(ecosystem="PyPI", name="bad", version="1.0"),
        vulnerabilities=[Vulnerability(id="CVE-1", cvss=9.8)])
    scan = DependencyScan(scan_id="y", filename="r.txt", ecosystem="PyPI",
                          findings=[pf])
    grade_scan(scan)
    assert scan.score == 75.0 and scan.grade.value == "C"


def test_priority_kev_beats_higher_cvss():
    kev = Finding(host="h", cve="C1", cvss=8.0, epss=0.9, in_kev=True)
    plain = Finding(host="h", cve="C2", cvss=9.0, epss=0.05, in_kev=False)
    assert priority_score(kev) > priority_score(plain)


def test_openvas_parser():
    xml = (ROOT / "aiva/fixtures/sample_openvas.xml").read_bytes()
    src, findings = aparse.parse(xml)
    assert src == "openvas"
    cves = {f.cve for f in findings}
    assert "CVE-2021-44228" in cves and len(findings) == 5


def test_nessus_parser():
    xml = (ROOT / "aiva/fixtures/sample_nessus.nessus").read_bytes()
    src, findings = aparse.parse(xml)
    assert src == "nessus"
    assert any(f.cve == "CVE-2020-1472" and f.cvss == 10.0 for f in findings)


def test_full_pipeline_offline():
    xml = (ROOT / "aiva/fixtures/sample_openvas.xml").read_bytes()
    plan = asyncio.run(run_pipeline(
        xml, assets=[Asset(host="10.0.1.21", criticality=2.0)],
        intel=OfflineIntel()))
    ranked = plan.ranked
    # Log4Shell on the crown-jewel host should rank first.
    assert ranked[0].cve == "CVE-2021-44228"
    # Context agent backfilled EternalBlue's missing CVSS from intel.
    eb = next(f for f in plan.findings if f.cve == "CVE-2017-0144")
    assert eb.cvss == 8.1 and eb.in_kev
    assert all(f.recommendation for f in plan.findings)


def test_pipeline_with_mock_llm():
    # A fake reasoner stands in for Claude — proves the LLM path wires through
    # without needing an API key.
    class MockReasoner:
        async def recommend(self, f, fallback):
            return f"AI: patch {f.cve} on {f.host} now."
        async def summary(self, findings):
            return f"AI summary of {len(findings)} findings."

    xml = (ROOT / "aiva/fixtures/sample_openvas.xml").read_bytes()
    plan = asyncio.run(run_pipeline(
        xml, intel=OfflineIntel(), reasoner=MockReasoner()))
    assert plan.summary.startswith("AI summary")
    assert all(f.recommendation.startswith("AI:") for f in plan.findings)


def test_pipeline_falls_back_without_llm():
    # reasoner=None -> deterministic recommendations, empty summary.
    xml = (ROOT / "aiva/fixtures/sample_openvas.xml").read_bytes()
    plan = asyncio.run(run_pipeline(
        xml, intel=OfflineIntel(), reasoner=None))
    assert plan.summary == ""
    assert all(f.recommendation and not f.recommendation.startswith("AI:")
               for f in plan.findings)


def test_nessus_summary_parse_and_resolve():
    from aiva.plugin_map import PluginResolver
    xml = (b"<?xml version='1.0'?><NessusScan><Info>"
           b"<targets>10.0.0.9</targets></Info>"
           b"<Vulnerability><plugin_id>46882</plugin_id>"
           b"<plugin_name>UnrealIRCd Backdoor</plugin_name>"
           b"<severity>4</severity></Vulnerability>"
           b"<Vulnerability><plugin_id>99999</plugin_id>"
           b"<plugin_name>No CVE plugin</plugin_name>"
           b"<severity>2</severity></Vulnerability></NessusScan>")
    src, findings = aparse.parse(xml)
    assert src == "nessus_summary"
    assert len(findings) == 2 and all(f.cve == "" and f.plugin_id for f in findings)

    plan = asyncio.run(run_pipeline(
        xml, intel=OfflineIntel(), resolver=PluginResolver(live=False),
        reasoner=None))
    # 46882 resolves to a CVE; 99999 has no mapping and is dropped.
    assert len(plan.findings) == 1
    assert plan.findings[0].cve == "CVE-2010-2075"
    assert plan.findings[0].host == "10.0.0.9"


def test_service_classifier():
    from aiva.services import classify_service
    assert classify_service("Apache Tomcat AJP (Ghostcat)") == "Apache Tomcat"
    assert classify_service("OpenSSH CBC ciphers") == "OpenSSH"
    assert classify_service("Samba Badlock Vulnerability") == "Samba / SMB"
    assert classify_service("Totally unknown thing") == "—"


def test_chat_agent_tool_loop(monkeypatch):
    import json, types, openai
    from shared.models import RemediationPlan, Finding, Severity
    from aiva.chat import run_chat

    plan = RemediationPlan(scan_source="nessus", findings=[
        Finding(host="h", cve="CVE-2020-1938", service="Apache Tomcat",
                cvss=9.8, severity=Severity.CRITICAL, epss=0.94, in_kev=True,
                priority_score=100, recommendation="Upgrade Tomcat.")])

    def resp(content=None, tool_calls=None):
        m = types.SimpleNamespace(content=content, tool_calls=tool_calls)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=m)])
    state = {"n": 0}

    class Comp:
        async def create(self, **kw):
            state["n"] += 1
            if state["n"] == 1:
                tc = types.SimpleNamespace(id="t1", function=types.SimpleNamespace(
                    name="get_finding", arguments=json.dumps({"cve": "CVE-2020-1938"})))
                return resp(tool_calls=[tc])
            tool = [m for m in kw["messages"] if m.get("role") == "tool"][0]
            data = json.loads(tool["content"])
            return resp(content=f"Top: {data['cve']} score {data['priority_score']}")

    class Client:
        def __init__(self, **kw): self.chat = types.SimpleNamespace(completions=Comp())
    monkeypatch.setenv("AIVA_LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "dummy")
    monkeypatch.setattr(openai, "AsyncOpenAI", Client)

    ans = asyncio.run(run_chat(plan, [{"role": "user", "content": "worst finding?"}]))
    assert "CVE-2020-1938" in ans and state["n"] == 2   # tool call + final answer


def test_requirements_parser():
    eco, pkgs, skipped = dparse.parse(
        "requirements.txt", b"flask==0.12.0\n# c\nfoo>=1\n")
    assert eco == "PyPI"
    assert pkgs[0].name == "flask" and pkgs[0].version == "0.12.0"
    assert "foo>=1" in skipped


def test_package_json_parser():
    eco, pkgs, _ = dparse.parse(
        "package.json", b'{"dependencies":{"lodash":"^4.17.10"}}')
    assert eco == "npm" and pkgs[0].version == "4.17.10"


def test_offline_osv_query():
    pkgs = [Package(ecosystem="PyPI", name="jinja2", version="2.10.0")]
    res = asyncio.run(OfflineOSV(
        ROOT / "dashboard/fixtures/offline_osv.json").query(pkgs))
    vulns = res["PyPI:jinja2:2.10.0"]
    # CVSS vector string must be parsed to a real base score (the live bug).
    assert vulns and vulns[0].cvss == 9.8 and vulns[0].fixed_version == "2.10.1"


def test_osv_vector_parsing_direct():
    from dashboard.osv import _score_from_vector
    assert _score_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _score_from_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") == 7.5
    assert _score_from_vector("not a vector") == 0.0


def test_osv_qualitative_fallback():
    # lodash record has no CVSS vector, only database_specific.severity=HIGH.
    pkgs = [Package(ecosystem="npm", name="lodash", version="4.17.10")]
    res = asyncio.run(OfflineOSV(
        ROOT / "dashboard/fixtures/offline_osv.json").query(pkgs))
    v = res["npm:lodash:4.17.10"][0]
    assert v.cvss == 8.0 and v.severity.value == "HIGH"
