"""Build the final Markdown audit report from LLM sections and parsed data."""

from __future__ import annotations

from collections import Counter
from datetime import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _severity_stats(vulnerabilities: list[dict]) -> str:
    """Return a short Markdown block summarising severity distribution."""
    counts: Counter[str] = Counter(
        item.get("severity", "unknown") for item in vulnerabilities
    )
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    total = critical + high
    lines = [
        f"| **Total High + Critical** | **{total}** |",
        f"| Critical | {critical} |",
        f"| High | {high} |",
    ]
    return "| Metric | Count |\n|---|---:|\n" + "\n".join(lines)


def build_technical_risk_table(vulnerabilities: list[dict]) -> str:
    """Render a Markdown table of all filtered vulnerabilities."""
    header = (
        "| # | Severity | ID | Vulnerability | Asset | CVSS | CVE | Remediation |\n"
        "|---:|---|---|---|---|---:|---|---|"
    )
    rows: list[str] = []
    for idx, item in enumerate(vulnerabilities, 1):
        cvss = item.get("cvss_score")
        rows.append(
            "| {idx} | {sev} | {vid} | {title} | {asset} | {cvss} | {cve} | {rem} |".format(
                idx=idx,
                sev=item.get("severity", "").upper(),
                vid=item.get("vulnerability_id", ""),
                title=item.get("title", "").replace("|", "\\|"),
                asset=item.get("affected_asset", "").replace("|", "\\|"),
                cvss=f"{cvss:.1f}" if cvss is not None else "N/A",
                cve=item.get("cve") or "N/A",
                rem=item.get("remediation", "").replace("|", "\\|")[:120],
            )
        )
    return "\n".join([header, *rows])


def _build_risk_section(risk_scores: dict | None) -> str:
    """Build ML risk assessment section."""
    if not risk_scores:
        return ""

    score = risk_scores.get("overall_score", 0)
    level = risk_scores.get("risk_level", "unknown").upper()

    lines = [
        "## ML Risk Assessment\n",
        f"**Overall Risk Score: {score}/100 ({level})**\n",
    ]

    # Host risk profiles
    profiles = risk_scores.get("host_profiles", [])
    if profiles:
        lines.append("### Host Risk Profiles\n")
        lines.append("| Host | Risk Score | Level | Findings | Top Issue |")
        lines.append("|---|---:|---|---:|---|")
        for h in sorted(profiles, key=lambda x: -x.get("risk_score", 0)):
            lines.append(
                f"| {h.get('address', 'N/A')} | {h.get('risk_score', 0)} | "
                f"{h.get('risk_level', 'N/A').upper()} | {h.get('finding_count', 0)} | "
                f"{h.get('top_finding', 'N/A')} |"
            )
        lines.append("")

    # Attack chains
    chains = risk_scores.get("attack_chains", [])
    if chains:
        lines.append("### Attack Chains Detected\n")
        for c in chains:
            lines.append(f"**{c['name']}** ({c['severity'].upper()})")
            steps = c.get("steps", [])
            if steps:
                lines.append("  " + " → ".join(steps))
            lines.append("")

    # Compliance gaps
    gaps = risk_scores.get("compliance_gaps", [])
    if gaps:
        lines.append("### Compliance Gaps\n")
        lines.append("| Framework | Control | Gap | Severity |")
        lines.append("|---|---|---|---|")
        for g in gaps:
            lines.append(f"| {g['framework']} | {g['control']} | {g['gap']} | {g.get('severity', 'N/A').upper()} |")
        lines.append("")

    return "\n".join(lines)


def _build_recommendations_section(recommendations: list[dict] | None) -> str:
    """Build prioritized recommendations section."""
    if not recommendations:
        return ""

    lines = ["## Prioritized Remediation Recommendations\n"]

    for rec in recommendations:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(rec.get("severity", ""), "⚪")
        lines.append(f"### {emoji} P{rec.get('priority', '?')}: {rec['title']}\n")
        lines.append(f"**Severity:** {rec.get('severity', 'N/A').upper()} | "
                     f"**Effort:** {rec.get('effort', 'N/A')} | "
                     f"**Impact:** {rec.get('impact', 'N/A')} | "
                     f"**Affected:** {rec.get('affected_count', 0)} finding(s)\n")
        lines.append(f"{rec.get('description', '')}\n")

        steps = rec.get("steps", [])
        if steps:
            lines.append("**Steps:**")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------
def build_report_markdown(
    org_context: str,
    vulnerabilities: list[dict],
    executive_summary: str,
    technical_analysis: str,
    detailed_findings: str,
    risk_scores: dict | None = None,
    recommendations: list[dict] | None = None,
) -> str:
    """Assemble all sections into the final Markdown report string."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_table = build_technical_risk_table(vulnerabilities)
    stats = _severity_stats(vulnerabilities)

    risk_section = _build_risk_section(risk_scores)
    rec_section = _build_recommendations_section(recommendations)

    # Build dynamic ToC
    toc_items = [
        "1. [Summary Statistics](#summary-statistics)",
        "2. [Executive Summary](#executive-summary)",
    ]
    section_num = 3
    if risk_section:
        toc_items.append(f"{section_num}. [ML Risk Assessment](#ml-risk-assessment)")
        section_num += 1
    toc_items.append(f"{section_num}. [Technical Risk Table](#technical-risk-table)")
    section_num += 1
    toc_items.append(f"{section_num}. [Technical Risk Analysis & Recommendations](#technical-risk-analysis--recommendations)")
    section_num += 1
    if rec_section:
        toc_items.append(f"{section_num}. [Prioritized Remediation Recommendations](#prioritized-remediation-recommendations)")
        section_num += 1
    toc_items.append(f"{section_num}. [Detailed Findings with Remediation](#detailed-findings-with-remediation)")
    toc = "\n".join(toc_items)

    # Optional sections
    risk_block = f"\n---\n\n{risk_section}" if risk_section else ""
    rec_block = f"\n---\n\n{rec_section}" if rec_section else ""

    return f"""
# ReportX – AI Audit Report

> **Generated:** {timestamp}
> **Organization Context:** {org_context}
> **Mode:** Fully Offline (Ollama local inference + ML/NLP pipeline)
> **Risk Level:** {risk_scores.get('risk_level', 'N/A').upper() if risk_scores else 'N/A'} ({risk_scores.get('overall_score', 0) if risk_scores else 0}/100)

---

## Table of Contents

{toc}

---

## Summary Statistics

{stats}

---

## Executive Summary

{executive_summary}
{risk_block}
---

## Technical Risk Table

{risk_table}

---

## Technical Risk Analysis & Recommendations

{technical_analysis}
{rec_block}
---

## Detailed Findings with Remediation

{detailed_findings}

---

*Report generated by ReportX – Offline AI Audit Engine with ML Risk Scoring,
NLP Evidence Analysis, and Attack Chain Detection. All analysis is based
exclusively on parsed scan evidence; no external data sources were consulted.*
""".strip() + "\n"
