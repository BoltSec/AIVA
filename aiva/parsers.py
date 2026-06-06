"""Parse raw scanner exports (.nessus / OpenVAS GMP XML) into Findings.

Uses defusedxml to block XXE, billion-laughs (entity expansion), and DTD
retrieval attacks — the stdlib ElementTree is not safe against all of these
for untrusted input.
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

import defusedxml.ElementTree as DET  # noqa: N813 — safe drop-in for ET

from shared.grading import severity_from_cvss
from shared.models import Finding

from .services import classify_service

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _safe_root(xml_bytes: bytes) -> ET.Element:
    # defusedxml raises DefusedXmlException for XXE, DTD, and entity bombs
    return DET.fromstring(xml_bytes)


def detect_format(xml_bytes: bytes) -> str:
    head = xml_bytes[:2000].lower()
    if b"<nessusscan" in head or (b"<vulnerability" in head and b"vuln_index" in head):
        return "nessus_summary"
    if b"<nessusclientdata" in head or b".nessus" in head or b"reporthost" in head:
        return "nessus"
    if b"get_reports_response" in head or b"<report" in head or b"omp" in head \
            or b"gmp" in head:
        return "openvas"
    return "unknown"


def parse(xml_bytes: bytes, fmt: str | None = None) -> tuple[str, list[Finding]]:
    fmt = fmt or detect_format(xml_bytes)
    if fmt == "nessus":
        return "nessus", _parse_nessus(xml_bytes)
    if fmt == "openvas":
        return "openvas", _parse_openvas(xml_bytes)
    if fmt == "nessus_summary":
        return "nessus_summary", _parse_nessus_summary(xml_bytes)
    raise ValueError(f"Unrecognised scanner format: {fmt}")


def _parse_nessus_summary(xml_bytes: bytes) -> list[Finding]:
    """Plugin-keyed summary export (no CVEs). Resolver fills CVEs downstream."""
    root = _safe_root(xml_bytes)
    host = (root.findtext(".//targets") or "unknown").strip()
    out: list[Finding] = []
    for v in root.iter("Vulnerability"):
        sev = int(v.findtext("severity") or 0)
        if sev < 1:                      # skip informational items
            continue
        pid = (v.findtext("plugin_id") or "").strip()
        if not pid:
            continue
        nm=(v.findtext("plugin_name") or "").strip()
        out.append(Finding(
            host=host, cve="", plugin_id=pid, name=nm,
            service=classify_service(nm)))
    return out


def _parse_nessus(xml_bytes: bytes) -> list[Finding]:
    root = _safe_root(xml_bytes)
    out: list[Finding] = []
    for host in root.iter("ReportHost"):
        host_name = host.get("name", "unknown")
        for item in host.findall("ReportItem"):
            cve = (item.findtext("cve") or "").strip()
            if not cve:
                m = _CVE_RE.search(item.get("pluginName", ""))
                cve = m.group(0).upper() if m else ""
            if not cve:
                continue
            cvss = _to_float(item.findtext("cvss3_base_score")
                             or item.findtext("cvss_base_score"))
            nm = item.get("pluginName", "")
            out.append(Finding(
                host=host_name, cve=cve.upper(), name=nm,
                service=classify_service(nm),
                cvss=cvss, severity=severity_from_cvss(cvss),
            ))
    return out


def _parse_openvas(xml_bytes: bytes) -> list[Finding]:
    root = _safe_root(xml_bytes)
    out: list[Finding] = []
    for result in root.iter("result"):
        host = (result.findtext("host") or "unknown").strip()
        nvt = result.find("nvt")
        cve = ""
        if nvt is not None:
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.get("type", "").lower() == "cve":
                        cve = ref.get("id", "")
                        break
            if not cve:
                m = _CVE_RE.search(nvt.findtext("cve") or "")
                cve = m.group(0) if m else ""
        if not cve:
            m = _CVE_RE.search(ET.tostring(result, encoding="unicode"))
            cve = m.group(0) if m else ""
        if not cve:
            continue
        cvss = _to_float(result.findtext("severity")
                         or (nvt.findtext("cvss_base") if nvt is not None else None))
        name = (nvt.findtext("name") if nvt is not None else "") or \
               (result.findtext("name") or "")
        out.append(Finding(
            host=host, cve=cve.upper(), name=name,
            service=classify_service(name),
            cvss=cvss, severity=severity_from_cvss(cvss),
        ))
    return out


def _to_float(value) -> float:
    try:
        return max(0.0, min(10.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
