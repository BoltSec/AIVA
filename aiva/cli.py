"""AIVA CLI.

Examples:
  python -m aiva.cli scan aiva/fixtures/sample_openvas.xml
  python -m aiva.cli scan report.nessus --mode live --pdf out.pdf --json out.json
  python -m aiva.cli scan report.xml --asset web01=2.0 --asset db01=1.5
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from shared.models import Asset
from shared.pdf_report import remediation_report

from .clients import build_intel
from .pipeline import run_pipeline

app = typer.Typer(add_completion=False, help="AIVA — AI Vulnerability Agent")


@app.callback()
def _root():
    """AIVA — reactive vulnerability prioritization."""


def _parse_assets(items: list[str]) -> list[Asset]:
    out = []
    for it in items:
        host, _, crit = it.partition("=")
        out.append(Asset(host=host, criticality=float(crit or 1.0)))
    return out


@app.command()
def scan(
    file: Path = typer.Argument(..., exists=True, readable=True),
    mode: str = typer.Option("offline", help="offline | live"),
    asset: list[str] = typer.Option([], help="host=criticality, repeatable"),
    json_out: Path = typer.Option(None, "--json"),
    pdf_out: Path = typer.Option(None, "--pdf"),
    top: int = typer.Option(10, help="rows to print"),
):
    """Scan a Nessus/OpenVAS export and emit a prioritized remediation plan."""
    xml = file.read_bytes()
    plan = asyncio.run(run_pipeline(
        xml, assets=_parse_assets(asset), intel=build_intel(mode)))

    ranked = plan.ranked
    typer.echo(f"\nSource: {plan.scan_source}  Findings: {len(ranked)}\n")
    if plan.summary:
        typer.echo("EXECUTIVE SUMMARY")
        typer.echo(plan.summary + "\n")
    typer.echo(f"{'#':>2} {'HOST':<14}{'CVE':<18}{'CVSS':>5}"
               f"{'EPSS':>6}{'KEV':>5}{'SCORE':>7}  ACTION")
    for i, f in enumerate(ranked[:top], 1):
        typer.echo(f"{i:>2} {f.host:<14}{f.cve:<18}{f.cvss:>5.1f}"
                   f"{f.epss:>6.2f}{('yes' if f.in_kev else '-'):>5}"
                   f"{f.priority_score:>7.0f}  {f.recommendation[:48]}")

    if json_out:
        json_out.write_text(plan.model_dump_json(indent=2, exclude={"findings"}
                                                  if False else None))
        typer.echo(f"\nJSON  -> {json_out}")
    if pdf_out:
        pdf_out.write_bytes(remediation_report(plan))
        typer.echo(f"PDF   -> {pdf_out}")


if __name__ == "__main__":
    app()
