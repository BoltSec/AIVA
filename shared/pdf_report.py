"""PDF report generation shared by both components (reportlab)."""
from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

from .models import DependencyScan, RemediationPlan

_styles = getSampleStyleSheet()
_h1 = _styles["Title"]
_h2 = ParagraphStyle("h2", parent=_styles["Heading2"], spaceBefore=10)
_body = _styles["BodyText"]

_GRADE_COLOR = {
    "A": colors.HexColor("#1d9e75"), "B": colors.HexColor("#639922"),
    "C": colors.HexColor("#ba7517"), "D": colors.HexColor("#d85a30"),
    "E": colors.HexColor("#e24b4a"), "F": colors.HexColor("#a32d2d"),
}


def _table(rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#26215c")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f4f3ee")]),
    ]))
    return t


def dependency_report(scan: DependencyScan) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Dependency Risk Report")
    story = [Paragraph("Dependency Risk Report", _h1)]
    g = scan.grade.value
    story.append(Paragraph(
        f'File: <b>{scan.filename}</b> ({scan.ecosystem})  &nbsp; '
        f'Grade: <font color="{_GRADE_COLOR[g]}"><b>{g}</b></font> '
        f'({scan.score}/100)', _body))
    story.append(Paragraph(
        f"{scan.vulnerable_packages} vulnerable package(s), "
        f"{scan.total_vulnerabilities} known vulnerabilities.", _body))
    story.append(Spacer(1, 6 * mm))

    rows = [["Package", "Version", "CVE", "CVSS", "Fix"]]
    for f in scan.findings:
        for v in f.vulnerabilities:
            rows.append([f.package.name, f.package.version, v.id,
                         f"{v.cvss:.1f}", v.fixed_version or "—"])
    if len(rows) > 1:
        story.append(_table(rows, [38*mm, 22*mm, 38*mm, 14*mm, 28*mm]))
    else:
        story.append(Paragraph("No known vulnerabilities found.", _body))
    doc.build(story)
    return buf.getvalue()


def remediation_report(plan: RemediationPlan) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="AIVA Remediation Plan")
    story = [Paragraph("AIVA Remediation Plan", _h1)]
    story.append(Paragraph(
        f"Source: {plan.scan_source} &nbsp; "
        f"Findings: {len(plan.findings)} &nbsp; "
        f"Hosts: {len(plan.assets)}", _body))
    story.append(Paragraph("Ordered by priority — patch top items first.", _body))
    if plan.summary:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Executive summary", _h2))
        story.append(Paragraph(plan.summary, _body))
    story.append(Spacer(1, 6 * mm))

    rows = [["#", "Host", "CVE", "CVSS", "EPSS", "KEV", "Score", "Action"]]
    for i, f in enumerate(plan.ranked, 1):
        rows.append([str(i), f.host, f.cve, f"{f.cvss:.1f}",
                     f"{f.epss:.2f}", "yes" if f.in_kev else "—",
                     f"{f.priority_score:.0f}",
                     Paragraph(f.recommendation or "—",
                               ParagraphStyle("c", fontSize=7))])
    story.append(_table(rows, [8*mm, 28*mm, 32*mm, 12*mm, 13*mm,
                               10*mm, 13*mm, 44*mm]))
    doc.build(story)
    return buf.getvalue()
