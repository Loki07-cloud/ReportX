"""Smart alert generation engine.

Generates prioritized security alerts based on findings, risk scores,
NLP analysis, and pattern detection. Alerts include severity, context,
recommended actions, and affected assets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

log = logging.getLogger(__name__)


@dataclass
class Alert:
    """Single security alert."""
    id: str
    title: str
    severity: str  # critical | high | medium | low
    category: str
    description: str
    affected_assets: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    timestamp: str = ""
    is_actionable: bool = True
    confidence: float = 1.0  # 0-1

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "affected_assets": self.affected_assets,
            "recommended_actions": self.recommended_actions,
            "evidence_refs": self.evidence_refs,
            "timestamp": self.timestamp,
            "is_actionable": self.is_actionable,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Recommendation:
    """Prioritized remediation recommendation."""
    id: str
    title: str
    priority: int  # 1 = highest
    severity: str
    category: str
    description: str
    effort: str  # low | medium | high
    impact: str  # critical | high | medium | low
    affected_count: int = 0
    steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "priority": self.priority,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "effort": self.effort,
            "impact": self.impact,
            "affected_count": self.affected_count,
            "steps": self.steps,
        }


def generate_alerts(
    findings: list[dict],
    risk_result: dict | None = None,
    nlp_result: dict | None = None,
) -> list[Alert]:
    """Generate smart security alerts from analysis results.

    Args:
        findings: Filtered vulnerability findings.
        risk_result: Output from risk_scorer.compute_risk_scores().to_dict()
        nlp_result: Output from nlp_analyzer.run_nlp_analysis().to_dict()

    Returns:
        List of prioritized Alert objects.
    """
    alerts: list[Alert] = []
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    alert_id = 0

    # --- Finding-based alerts ---
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    high_findings = [f for f in findings if f.get("severity") == "high"]

    if critical_findings:
        alert_id += 1
        assets = list(set(f.get("affected_asset", "Unknown") for f in critical_findings))
        alerts.append(Alert(
            id=f"ALT-{alert_id:03d}",
            title=f"{len(critical_findings)} Critical Vulnerabilities Detected",
            severity="critical",
            category="Vulnerability",
            description=f"Critical severity vulnerabilities found across {len(assets)} host(s). Immediate remediation required.",
            affected_assets=assets[:10],
            recommended_actions=[
                "Prioritize patching of critical vulnerabilities immediately",
                "Isolate affected systems until remediation is complete",
                "Review access controls on affected assets",
                "Schedule emergency change window for remediation",
            ],
            evidence_refs=[f.get("source_file", "") for f in critical_findings[:5]],
            timestamp=now,
            confidence=1.0,
        ))

    # Anonymous access alert
    anon_findings = [f for f in findings if "anonymous" in f.get("title", "").lower() or "anonymous" in f.get("description", "").lower()]
    if anon_findings:
        alert_id += 1
        assets = list(set(f.get("affected_asset", "Unknown") for f in anon_findings))
        alerts.append(Alert(
            id=f"ALT-{alert_id:03d}",
            title="Anonymous/Unauthenticated Access Detected",
            severity="critical",
            category="Access Control",
            description="Services with anonymous or unauthenticated access found. This allows anyone to access potentially sensitive data.",
            affected_assets=assets,
            recommended_actions=[
                "Disable anonymous access on all FTP servers",
                "Require authentication for all services",
                "Audit file permissions on FTP directories",
                "Implement network segmentation to limit exposure",
            ],
            evidence_refs=[f.get("source_file", "") for f in anon_findings],
            timestamp=now,
            confidence=0.95,
        ))

    # Weak crypto alert
    crypto_findings = [f for f in findings if any(kw in (f.get("title", "") + f.get("description", "")).lower() for kw in ["ssl", "tls", "cipher", "3des", "rc4", "poodle", "sweet32"])]
    if crypto_findings:
        alert_id += 1
        assets = list(set(f.get("affected_asset", "Unknown") for f in crypto_findings))
        alerts.append(Alert(
            id=f"ALT-{alert_id:03d}",
            title=f"Weak Cryptography Detected on {len(assets)} Host(s)",
            severity="high",
            category="Cryptography",
            description="Deprecated SSL/TLS protocols or weak cipher suites detected, enabling potential decryption or man-in-the-middle attacks.",
            affected_assets=assets,
            recommended_actions=[
                "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1",
                "Remove RC4, 3DES, NULL, and EXPORT ciphers",
                "Configure minimum TLS 1.2 with strong cipher suites",
                "Use 2048-bit+ DH parameters, prefer ECDHE",
                "Renew any expired certificates",
            ],
            evidence_refs=[f.get("source_file", "") for f in crypto_findings[:5]],
            timestamp=now,
            confidence=0.95,
        ))

    # Default credentials alert
    default_creds = [f for f in findings if any(kw in (f.get("title", "") + f.get("description", "")).lower() for kw in ["default", "nopass", "brute force success", "credential"])]
    if default_creds:
        alert_id += 1
        assets = list(set(f.get("affected_asset", "Unknown") for f in default_creds))
        alerts.append(Alert(
            id=f"ALT-{alert_id:03d}",
            title="Weak or Default Credentials Found",
            severity="critical",
            category="Authentication",
            description="Systems with default, weak, or missing credentials detected. This provides trivial unauthorized access.",
            affected_assets=assets,
            recommended_actions=[
                "Immediately change default credentials on all systems",
                "Enforce strong password policy (12+ chars, complexity)",
                "Implement multi-factor authentication (MFA)",
                "Deploy account lockout after failed attempts",
                "Audit all service accounts for default passwords",
            ],
            evidence_refs=[f.get("source_file", "") for f in default_creds],
            timestamp=now,
            confidence=0.90,
        ))

    # --- Risk-based alerts ---
    if risk_result:
        # Attack chain alerts
        chains = risk_result.get("attack_chains", [])
        for chain in chains:
            if chain.get("severity") == "critical":
                alert_id += 1
                alerts.append(Alert(
                    id=f"ALT-{alert_id:03d}",
                    title=f"Attack Chain: {chain['name']}",
                    severity="critical",
                    category="Attack Path",
                    description=f"Multi-step attack path identified: {' → '.join(chain.get('steps', []))}",
                    affected_assets=[],
                    recommended_actions=[
                        "Break the attack chain by remediating the first step",
                        "Apply defense-in-depth controls at each step",
                        "Monitor for exploitation attempts",
                    ],
                    evidence_refs=[],
                    timestamp=now,
                    confidence=0.85,
                ))

        # High-risk host alerts
        high_risk_hosts = [h for h in risk_result.get("host_profiles", []) if h.get("risk_level") in ("critical", "high")]
        if high_risk_hosts:
            alert_id += 1
            alerts.append(Alert(
                id=f"ALT-{alert_id:03d}",
                title=f"{len(high_risk_hosts)} High-Risk Hosts Require Immediate Attention",
                severity="high",
                category="Risk Assessment",
                description=f"ML risk scoring identified {len(high_risk_hosts)} hosts with elevated risk scores requiring priority remediation.",
                affected_assets=[h.get("address", "Unknown") for h in high_risk_hosts[:10]],
                recommended_actions=[
                    "Start remediation with highest-risk hosts",
                    "Consider network isolation for critical-risk hosts",
                    "Schedule vulnerability rescanning after remediation",
                ],
                evidence_refs=[],
                timestamp=now,
                confidence=0.90,
            ))

        # Compliance gap alerts
        gaps = risk_result.get("compliance_gaps", [])
        critical_gaps = [g for g in gaps if g.get("severity") in ("critical", "high")]
        if critical_gaps:
            alert_id += 1
            frameworks = list(set(g.get("framework", "") for g in critical_gaps))
            alerts.append(Alert(
                id=f"ALT-{alert_id:03d}",
                title=f"Compliance Gaps Detected ({len(critical_gaps)} controls)",
                severity="high",
                category="Compliance",
                description=f"Security control gaps identified against: {', '.join(frameworks)}",
                affected_assets=[],
                recommended_actions=[
                    f"Address {g['control']}: {g['gap']}" for g in critical_gaps[:5]
                ],
                evidence_refs=[],
                timestamp=now,
                confidence=0.85,
            ))

    # --- NLP-based alerts ---
    if nlp_result:
        threat_indicators = nlp_result.get("threat_indicators", [])
        critical_threats = [t for t in threat_indicators if t.get("severity") == "critical"]
        if critical_threats:
            alert_id += 1
            alerts.append(Alert(
                id=f"ALT-{alert_id:03d}",
                title=f"NLP Analysis: {len(critical_threats)} Critical Threat Pattern(s) Detected",
                severity="critical",
                category="Threat Intelligence",
                description="Natural language analysis of evidence files identified critical threat patterns: " + "; ".join(t["name"] for t in critical_threats),
                affected_assets=[],
                recommended_actions=[t.get("description", "") for t in critical_threats],
                evidence_refs=[],
                timestamp=now,
                confidence=0.80,
            ))

        # CVE alerts
        cves = nlp_result.get("cves_found", [])
        high_cves = [c for c in cves if c.get("severity") in ("critical", "high")]
        if high_cves:
            alert_id += 1
            alerts.append(Alert(
                id=f"ALT-{alert_id:03d}",
                title=f"{len(high_cves)} Known CVEs Detected in Evidence",
                severity="high",
                category="CVE Intelligence",
                description="Known CVEs identified: " + ", ".join(f"{c['cve_id']} ({c.get('name', 'Unknown')})" for c in high_cves),
                affected_assets=[],
                recommended_actions=[
                    f"Patch {c['cve_id']} - {c.get('description', 'Apply vendor patch')}" for c in high_cves[:5]
                ],
                evidence_refs=[],
                timestamp=now,
                confidence=0.95,
            ))

    # EOL software alert
    eol_findings = [f for f in findings if any(kw in (f.get("title", "") + f.get("description", "")).lower() for kw in ["end of life", "eol", "unsupported", "2008", "2003"])]
    if eol_findings:
        alert_id += 1
        assets = list(set(f.get("affected_asset", "Unknown") for f in eol_findings))
        alerts.append(Alert(
            id=f"ALT-{alert_id:03d}",
            title="End-of-Life Software Detected",
            severity="high",
            category="Patch Management",
            description="Systems running end-of-life software without vendor security support detected.",
            affected_assets=assets,
            recommended_actions=[
                "Plan migration to supported versions",
                "Apply virtual patching via WAF/IPS if immediate upgrade not possible",
                "Isolate EOL systems from production networks",
                "Increase monitoring on EOL systems",
            ],
            evidence_refs=[f.get("source_file", "") for f in eol_findings],
            timestamp=now,
            confidence=0.90,
        ))

    # Sort by severity then confidence
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (severity_order.get(a.severity, 9), -a.confidence))

    log.info("Generated %d alerts (%d critical, %d high)",
             len(alerts),
             sum(1 for a in alerts if a.severity == "critical"),
             sum(1 for a in alerts if a.severity == "high"))
    return alerts


def generate_recommendations(
    findings: list[dict],
    risk_result: dict | None = None,
    nlp_result: dict | None = None,
) -> list[Recommendation]:
    """Generate prioritized remediation recommendations.

    Args:
        findings: Filtered vulnerability findings.
        risk_result: Risk scoring output dict.
        nlp_result: NLP analysis output dict.

    Returns:
        List of Recommendation objects sorted by priority.
    """
    recs: list[Recommendation] = []
    rec_id = 0

    # Analyze finding patterns to generate targeted recommendations
    finding_categories: dict[str, list[dict]] = {}
    for f in findings:
        title = (f.get("title", "") + " " + f.get("description", "")).lower()
        if any(kw in title for kw in ["ssl", "tls", "cipher", "crypto"]):
            finding_categories.setdefault("crypto", []).append(f)
        elif any(kw in title for kw in ["ftp", "anonymous", "credential", "password", "auth"]):
            finding_categories.setdefault("auth", []).append(f)
        elif any(kw in title for kw in ["http", "web", "header", "csrf", "xss"]):
            finding_categories.setdefault("web", []).append(f)
        elif any(kw in title for kw in ["port", "service", "smb", "rdp"]):
            finding_categories.setdefault("network", []).append(f)
        elif any(kw in title for kw in ["snmp", "dns", "ntp"]):
            finding_categories.setdefault("infra", []).append(f)
        else:
            finding_categories.setdefault("other", []).append(f)

    # Authentication & Access recommendations
    if "auth" in finding_categories:
        rec_id += 1
        auth_findings = finding_categories["auth"]
        crit = sum(1 for f in auth_findings if f.get("severity") == "critical")
        recs.append(Recommendation(
            id=f"REC-{rec_id:03d}",
            title="Strengthen Authentication Controls",
            priority=1 if crit > 0 else 2,
            severity="critical" if crit > 0 else "high",
            category="Authentication & Access",
            description=f"{len(auth_findings)} authentication-related findings across {len(set(f.get('affected_asset') for f in auth_findings))} host(s).",
            effort="medium",
            impact="critical",
            affected_count=len(auth_findings),
            steps=[
                "Disable anonymous/guest access on all services (FTP, SMB, etc.)",
                "Change all default and weak passwords immediately",
                "Implement centralized identity management (Active Directory/LDAP)",
                "Deploy multi-factor authentication (MFA) for all administrative access",
                "Configure account lockout policies (5 failed attempts, 30min lockout)",
                "Audit and remove unnecessary service accounts",
            ],
        ))

    # Cryptography recommendations
    if "crypto" in finding_categories:
        rec_id += 1
        crypto_findings = finding_categories["crypto"]
        recs.append(Recommendation(
            id=f"REC-{rec_id:03d}",
            title="Harden SSL/TLS Configuration",
            priority=2,
            severity="high",
            category="Cryptography",
            description=f"{len(crypto_findings)} cryptographic weaknesses found. Modern cipher configuration required.",
            effort="medium",
            impact="high",
            affected_count=len(crypto_findings),
            steps=[
                "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on all services",
                "Remove weak ciphers: RC4, 3DES, NULL, EXPORT, DES",
                "Configure TLS 1.2 minimum with AEAD ciphers (AES-GCM, ChaCha20)",
                "Generate 2048-bit+ RSA keys and DH parameters",
                "Enable HSTS with 1-year max-age and includeSubDomains",
                "Implement automated certificate renewal (Let's Encrypt/ACME)",
                "Renew all expired certificates immediately",
            ],
        ))

    # Web security recommendations
    if "web" in finding_categories:
        rec_id += 1
        web_findings = finding_categories["web"]
        recs.append(Recommendation(
            id=f"REC-{rec_id:03d}",
            title="Improve Web Application Security",
            priority=3,
            severity="high",
            category="Web Application",
            description=f"{len(web_findings)} web application security issues identified.",
            effort="medium",
            impact="high",
            affected_count=len(web_findings),
            steps=[
                "Deploy security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options",
                "Disable HTTP TRACE method on all web servers",
                "Implement anti-CSRF tokens on all forms",
                "Configure proper CORS policies",
                "Remove server version disclosure from response headers",
                "Implement Web Application Firewall (WAF) rules",
            ],
        ))

    # Network hardening
    if "network" in finding_categories:
        rec_id += 1
        net_findings = finding_categories["network"]
        recs.append(Recommendation(
            id=f"REC-{rec_id:03d}",
            title="Network Service Hardening",
            priority=2,
            severity="high",
            category="Network Security",
            description=f"{len(net_findings)} network service issues requiring hardening.",
            effort="high",
            impact="high",
            affected_count=len(net_findings),
            steps=[
                "Audit all open services and disable unnecessary ones",
                "Segment networks to isolate sensitive services",
                "Implement host-based firewalls on all systems",
                "Disable SMBv1 and enforce SMB signing",
                "Restrict management interfaces to dedicated VLANs",
                "Deploy network intrusion detection/prevention (IDS/IPS)",
            ],
        ))

    # Infrastructure protocol hardening
    if "infra" in finding_categories:
        rec_id += 1
        infra_findings = finding_categories["infra"]
        recs.append(Recommendation(
            id=f"REC-{rec_id:03d}",
            title="Infrastructure Protocol Security",
            priority=3,
            severity="medium",
            category="Infrastructure",
            description=f"{len(infra_findings)} infrastructure protocol issues found.",
            effort="medium",
            impact="medium",
            affected_count=len(infra_findings),
            steps=[
                "Upgrade SNMP to v3 with authentication and encryption",
                "Change default SNMP community strings",
                "Restrict SNMP access to management networks only",
                "Configure DNS with DNSSEC where possible",
                "Disable unnecessary protocol services",
            ],
        ))

    # Patch management (based on risk context)
    if risk_result:
        eol_hosts = [h for h in risk_result.get("host_profiles", []) if h.get("is_eol")]
        if eol_hosts:
            rec_id += 1
            recs.append(Recommendation(
                id=f"REC-{rec_id:03d}",
                title="End-of-Life System Migration",
                priority=1,
                severity="critical",
                category="Patch Management",
                description=f"{len(eol_hosts)} host(s) running end-of-life operating systems.",
                effort="high",
                impact="critical",
                affected_count=len(eol_hosts),
                steps=[
                    "Inventory all EOL systems and assess business dependencies",
                    "Create migration plan to supported OS versions",
                    "Apply virtual patching via IPS/WAF as interim measure",
                    "Isolate EOL systems in separate network segments",
                    "Increase logging and monitoring on EOL systems",
                    "Set firm decommission dates with management approval",
                ],
            ))

    # Monitoring recommendation (always)
    rec_id += 1
    recs.append(Recommendation(
        id=f"REC-{rec_id:03d}",
        title="Enhance Security Monitoring",
        priority=4,
        severity="medium",
        category="Detection & Monitoring",
        description="Improve detection capabilities to identify exploitation attempts.",
        effort="high",
        impact="high",
        affected_count=len(findings),
        steps=[
            "Deploy centralized SIEM with log aggregation from all hosts",
            "Configure alerts for authentication failures and anomalous access",
            "Implement file integrity monitoring on critical systems",
            "Establish regular vulnerability scanning schedule (weekly/monthly)",
            "Create incident response playbooks for detected vulnerability classes",
            "Conduct regular penetration testing to validate remediation",
        ],
    ))

    # Sort by priority
    recs.sort(key=lambda r: r.priority)

    log.info("Generated %d recommendations", len(recs))
    return recs
