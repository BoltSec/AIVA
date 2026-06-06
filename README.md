# AIVA — AI-powered Vulnerability Assessment Platform

## Overview

AIVA is a dual-component Python cybersecurity platform designed to solve a major limitation of traditional vulnerability scanners such as Nessus and OpenVAS.

While scanners successfully identify vulnerabilities, they do not effectively answer the most important question:

> What should be fixed first?

AIVA enriches scanner findings with real-world exploit intelligence and re-ranks vulnerabilities based on actual danger rather than theoretical severity alone.

The platform consists of two integrated components:

### Component A — Dependency Risk Dashboard

A FastAPI web application for developers that analyzes dependency files and provides security risk grading.

### Component B — AIVA (AI Vulnerability Assessment Agent)

A LangGraph-powered agentic pipeline that processes Nessus and OpenVAS reports, enriches findings with threat intelligence, prioritizes remediation efforts, and generates AI-assisted recommendations.

---

# Problem Statement

Organizations running vulnerability scans often receive hundreds or thousands of findings.

Most scanners rank findings solely using CVSS scores, which introduces several challenges:

- A CVSS 9.8 vulnerability with little or no exploitation activity may rank above a CVSS 7.5 vulnerability actively exploited by attackers.
- No visibility into whether a vulnerability appears on CISA's Known Exploited Vulnerabilities (KEV) Catalog.
- Generic remediation recommendations that ignore asset importance and context.
- Raw XML reports require expert interpretation.
- No executive-friendly summary for management or non-technical stakeholders.

As a result, security teams often struggle to determine which vulnerabilities present the greatest real-world risk.

---

# Proposed Solution

AIVA enriches vulnerability findings using multiple threat intelligence sources and prioritizes vulnerabilities using a custom scoring formula that incorporates:

- CVSS Severity
- EPSS Exploit Probability
- CISA Known Exploited Vulnerabilities (KEV)
- Asset Criticality

This enables organizations to focus remediation efforts on vulnerabilities that pose the highest practical risk.

---

# Component A — Dependency Risk Dashboard

A FastAPI-based web application designed for developers.

### Features

- Upload Python `requirements.txt`
- Upload Node.js `package.json`
- Analyze dependencies against OSV.dev
- Identify known vulnerable packages
- Generate an overall A–F security grade
- Generate downloadable PDF reports

### Workflow

```text
Dependency File
      │
      ▼
 Dependency Parser
      │
      ▼
    OSV.dev
      │
      ▼
 Risk Assessment
      │
      ▼
   Grade (A-F)
      │
      ▼
   PDF Report
```

---

# Component B — AIVA (AI Vulnerability Assessment Agent)

A LangGraph-based multi-agent vulnerability assessment pipeline.

### Supported Inputs

- Nessus XML Reports
- OpenVAS XML Reports

### Features

- Parse scanner findings
- Resolve Plugin IDs to CVEs
- Retrieve CVSS scores
- Retrieve EPSS exploit probabilities
- Check CISA KEV status
- Prioritize findings
- Generate AI-assisted remediation recommendations
- Generate executive summaries
- Export PDF remediation plans

---

# AI Agent Pipeline (LangGraph — 7 Nodes)

## 1. Parser Agent

Reads Nessus/OpenVAS XML reports and extracts all findings.

**Output:**

```python
Finding[]
```

---

## 2. Resolver Agent

Maps scanner Plugin IDs to CVE identifiers.

```text
Plugin ID → CVE
```

---

## 3. Context Agent

Retrieves vulnerability context from the NIST NVD database.

Provides:

- CVSS Score
- CVE Description

Source:

- NIST NVD API

---

## 4. Exploitability Agent

Retrieves real-world exploitation intelligence.

Provides:

- EPSS Score
- CISA KEV Status

Sources:

- FIRST EPSS
- CISA KEV

---

## 5. Prioritization Agent

Computes a custom priority score and ranks findings.

### Priority Score Formula

priority_score = (CVSS × 10) × (0.5 + 0.5 × EPSS) × KEV_boost × asset_criticality

Where:

- CVSS × 10 → Impact
- EPSS → Exploit likelihood
- KEV Boost → Active exploitation indicator
- Asset Criticality → Business importance

### KEV Boost

```python
1.5
```

Applied when:

```text
CVE exists in the CISA KEV Catalog
```

### Asset Criticality Examples

| Asset Type | Weight |
|------------|---------|
| Standard Host | 1.0 |
| Important Server | 1.5 |
| Crown Jewel Asset | 2.0 |

Final score is capped at:

```python
100
```

---

## 6. Recommendation Agent

Uses an LLM to generate:

- Host-specific remediation guidance
- Patch recommendations
- Risk explanations
- Actionable security recommendations

Important:

The LLM does not participate in prioritization.

Prioritization remains deterministic and auditable.

---

## 7. Summary Agent

Generates an executive-level security summary.

Provides:

- Overall risk posture
- Critical vulnerabilities overview
- Prioritized remediation roadmap
- Management briefing

---

# Concurrent Processing

The Context and Exploitability stages operate concurrently using:

```python
asyncio.gather()
```

This significantly improves enrichment performance across large vulnerability datasets.

---

# Interactive AI Chat

After a scan is completed, users can interact with the system using natural language.

Examples:

```text
Show top 10 findings
```

```text
Show KEV vulnerabilities only
```

```text
Explain CVE-2025-XXXX
```

```text
Re-rank findings using asset criticality 2.0
```

```text
Generate remediation plan
```

### Safety Rules

- Refuses unrelated questions
- Uses scan results as grounding context
- Fetches live vulnerability information when available
- Never relies solely on model memory

---

# Analytics Dashboard

The platform includes post-scan analytics.

### Severity Distribution

Donut chart displaying:

- Critical
- High
- Medium
- Low

### EPSS Distribution

Bar chart displaying exploit probability ranges:

- 0–25%
- 25–50%
- 50–75%
- 75–100%

### Priority Score Distribution

Bar chart displaying:

- 0–25
- 25–50
- 50–75
- 75–100

### KEV Counter

Displays the number of actively exploited vulnerabilities present in the scan.

---

# Technology Stack

| Layer | Technology |
|---------|------------|
| Web API | FastAPI |
| Server | Uvicorn |
| Agent Framework | LangGraph (StateGraph) |
| Data Validation | Pydantic v2 |
| HTTP Client | httpx |
| XML Parsing | defusedxml |
| PDF Generation | ReportLab |
| CLI | Typer |
| Testing | pytest |
| Threat Intelligence | NVD, EPSS, KEV |
| LLM Providers | Groq, Gemini, OpenRouter, Ollama, OpenAI |

---

# External Data Sources

| Source | Data | Authentication |
|----------|----------|----------|
| NIST NVD API | CVSS scores, CVE descriptions | Optional API Key |
| FIRST EPSS API | Exploit probability | None |
| CISA KEV Catalog | Known exploited vulnerabilities | None |
| OSV.dev API | Dependency vulnerabilities | None |

---

# LLM Provider Support

AIVA is provider-agnostic.

Supported providers:

- Groq
- Gemini
- OpenRouter
- Ollama
- OpenAI

Switching providers requires changing a single environment variable.

Example:

```env
AIVA_LLM_PROVIDER=groq
```

or

```env
AIVA_LLM_PROVIDER=gemini
```

### Recommended Configuration

For free usage:

- Gemini Free Tier

For production demos:

- Groq

For fully offline operation:

- Ollama

---

# Key Design Decisions

## Deterministic + AI Hybrid

The platform separates:

### Deterministic Components

- Parsing
- Scoring
- Ranking

### AI Components

- Recommendations
- Explanations
- Executive Summaries

This ensures reproducibility and auditability.

---

## Offline-First Design

The platform can operate without:

- Internet access
- API keys
- External services

using local fixtures and offline intelligence data.

---

## Provider-Agnostic LLM Layer

Supports multiple providers without code changes.

---

## Shared Architecture

Both platform components use:

```text
shared/models.py
shared/grading.py
shared/pdf_report.py
```

ensuring consistent data structures and scoring logic.

---

# Novelty Over Existing Tools

| Existing Scanners | AIVA |
|------------------|-------|
| CVSS-only ranking | CVSS + EPSS + KEV + Asset Criticality |
| Severity labels | Real exploit probability |
| No KEV awareness | CISA KEV integration |
| Generic remediation | AI-generated remediation |
| Raw XML reports | Executive summaries |
| Plugin IDs | Plugin-to-CVE resolution |
| Static reports | Interactive AI chat |

---

# Credentials and Configuration

## NVD API Key

Optional but recommended.

Benefits:

- Higher rate limits
- Faster CVE enrichment
- Better scalability

```env
NVD_API_KEY=your_api_key
```

---

## CISA KEV Catalog

Recommended for offline mode.

Place:

```text
config/known_exploited_vulnerabilities.json
```

and configure:

```env
AIVA_KEV_FILE=config/known_exploited_vulnerabilities.json
```

---

## LLM API Key

Choose one provider:

```env
AIVA_LLM_PROVIDER=gemini
GEMINI_API_KEY=...
```

or

```env
AIVA_LLM_PROVIDER=groq
GROQ_API_KEY=...
```

If no provider is configured:

- Prioritization still works
- Reports still generate
- Recommendations fall back to deterministic templates

---

# Future Enhancements

- MITRE ATT&CK Mapping
- Threat Hunting Integration
- SIEM Integration
- Continuous Monitoring
- Multi-Scanner Support
- Database-backed RBAC
- CVE Trend Forecasting

---

# License

MIT License

---

# Author

AIVA — AI-powered Vulnerability Assessment Platform

Bridging the gap between vulnerability detection and vulnerability prioritization.
