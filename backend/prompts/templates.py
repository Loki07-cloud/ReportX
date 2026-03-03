"""Prompt templates for Ollama LLM calls.

Each template injects parsed vulnerability data (as JSON) and strict
rules that prevent the model from hallucinating beyond the evidence.

Enhanced with ML risk scores, NLP analysis, and attack chain context
to provide richer, more accurate LLM outputs.
"""

from __future__ import annotations

import json


def _to_json(data: object) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _build_enrichment_section(
    risk_scores: dict | None = None,
    nlp_context: str | None = None,
) -> str:
    """Build optional enrichment sections from ML/NLP analysis."""
    sections = []

    if risk_scores:
        score = risk_scores.get("overall_score", 0)
        level = risk_scores.get("risk_level", "unknown")
        sections.append(f"=== ML RISK ASSESSMENT ===\nOverall Risk Score: {score}/100 ({level.upper()})")

        chains = risk_scores.get("attack_chains", [])
        if chains:
            chain_lines = []
            for c in chains[:5]:
                chain_lines.append(f"- {c['name']} ({c['severity']}): {' → '.join(c.get('steps', []))}")
            sections.append("Attack Chains Detected:\n" + "\n".join(chain_lines))

        gaps = risk_scores.get("compliance_gaps", [])
        if gaps:
            gap_lines = [f"- [{g['framework']}] {g['control']}: {g['gap']}" for g in gaps[:8]]
            sections.append("Compliance Gaps:\n" + "\n".join(gap_lines))

        cats = risk_scores.get("finding_categories", {})
        if cats:
            cat_lines = [f"- {k}: {v} finding(s)" for k, v in sorted(cats.items(), key=lambda x: -x[1])]
            sections.append("Finding Categories:\n" + "\n".join(cat_lines))

    if nlp_context:
        sections.append(f"=== NLP EVIDENCE ANALYSIS ===\n{nlp_context}")

    return "\n\n".join(sections) if sections else ""


# ---------------------------------------------------------------------------
# Gemma 2 2B – Executive summary (business-friendly)
# ---------------------------------------------------------------------------
def gemma_executive_prompt(
    vulnerabilities: list[dict],
    org_context: str,
    risk_scores: dict | None = None,
    nlp_context: str | None = None,
) -> str:
    enrichment = _build_enrichment_section(risk_scores, nlp_context)
    enrichment_block = f"\n\n{enrichment}\n" if enrichment else ""

    return f"""
You are an executive cyber-risk summarizer for a **{org_context}** organization.

=== STRICT RULES (MUST follow) ===
1. Use ONLY the vulnerability evidence provided in DATA below.
2. Do NOT invent, assume, or reference any systems, CVEs, scores, controls,
   or business impacts that are not explicitly present in DATA.
3. Do NOT reference external frameworks, benchmarks, or industry statistics
   unless they appear in DATA.
4. If any piece of information is unavailable, explicitly write:
   \"Unavailable in provided evidence.\"
5. Keep language concise, non-technical, and business-friendly.
6. When ML risk scores and attack chains are provided, incorporate them
   into your assessment with specific numbers and severity levels.
{enrichment_block}
=== TASK ===
Write an **Executive Summary** with 5-8 bullet points covering:
- Overall risk posture with the ML risk score (if available)
- Number of Critical vs High findings and their distribution
- Top attack chains and their business impact
- Compliance gaps requiring immediate attention
- Business urgency and potential impact
- Remediation priority recommendations with effort estimates

=== OUTPUT FORMAT ===
Return Markdown bullet points only. No preamble, no conclusion.

=== DATA ===
{_to_json(vulnerabilities)}
""".strip()


# ---------------------------------------------------------------------------
# LLaMA 3 8B – Technical analysis
# ---------------------------------------------------------------------------
def llama_technical_analysis_prompt(
    vulnerabilities: list[dict],
    org_context: str,
    risk_scores: dict | None = None,
    nlp_context: str | None = None,
) -> str:
    enrichment = _build_enrichment_section(risk_scores, nlp_context)
    enrichment_block = f"\n\n{enrichment}\n" if enrichment else ""

    return f"""
You are a technical cyber-risk analyst for a **{org_context}** organization.

=== STRICT RULES (MUST follow) ===
1. Use ONLY the vulnerability evidence provided in DATA below.
2. No assumptions beyond parsed evidence. No references to external
   datasets, threat intelligence feeds, or internet resources.
3. Do NOT fabricate CVE identifiers, CVSS scores, or asset names.
4. If details are missing, state: \"Unavailable in provided evidence.\"
5. Every claim must trace back to a specific entry in DATA.
6. When ML risk analysis data is provided (attack chains, compliance gaps,
   risk scores), incorporate it as primary evidence in your analysis.
{enrichment_block}
=== TASK ===
Produce a **Technical Risk Analysis** containing:
- Attack surface concentration themes (group by common patterns)
- Identified attack chains with step-by-step exploitation paths
- Likely exploitation paths inferred ONLY from listed findings
- Cross-finding risk amplification (how findings combine to increase risk)
- Compliance posture assessment per framework (NIST, PCI DSS, CIS, OWASP, ISO 27001)
- Prioritised remediation strategy ordered by risk score, severity, and asset exposure
- Network segmentation recommendations based on host risk profiles

=== OUTPUT FORMAT ===
Return Markdown with short headings (##) and bullet points.
No preamble, no conclusion paragraph.

=== DATA ===
{_to_json(vulnerabilities)}
""".strip()


# ---------------------------------------------------------------------------
# LLaMA 3 8B – Detailed per-finding analysis
# ---------------------------------------------------------------------------
def llama_detailed_findings_prompt(
    vulnerabilities: list[dict],
    org_context: str,
    risk_scores: dict | None = None,
    nlp_context: str | None = None,
) -> str:
    enrichment = _build_enrichment_section(risk_scores, nlp_context)
    enrichment_block = f"\n\n{enrichment}\n" if enrichment else ""

    return f"""
You are generating detailed technical findings for a **{org_context}** security audit report.

=== STRICT RULES (MUST follow) ===
1. Use ONLY the entries in DATA below.
2. Do NOT introduce new vulnerabilities, assets, CVEs, or controls.
3. If remediation is not provided in DATA, state:
   \"Remediation unavailable in provided evidence.\"
4. Do NOT speculate about root causes not supported by evidence.
5. Preserve the exact severity and IDs from DATA.
6. When risk scores and attack chain context are provided, mention
   how each finding contributes to overall risk.
{enrichment_block}
=== TASK ===
For EACH vulnerability in DATA, output a subsection containing:
- **Title** and **Severity**
- **Vulnerability ID** and **CVE** (if available)
- **Affected Asset**
- **Risk Contribution** (how this finding contributes to overall risk score and any attack chains)
- **Evidence Summary** (paraphrase, do not fabricate)
- **Remediation Recommendation** (from evidence only, with priority level)

=== OUTPUT FORMAT ===
Return Markdown with ### subsection per finding.
No preamble, no overall summary.

=== DATA ===
{_to_json(vulnerabilities)}
""".strip()
