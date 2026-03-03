"""ML-powered risk scoring engine.

Computes multi-factor risk scores for hosts, findings, and the overall
environment using weighted algorithms, CVSS normalization, exposure
analysis, and attack chain detection.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known CVE severity database (offline lookup for common CVEs)
# ---------------------------------------------------------------------------
_CVE_SEVERITY_DB: dict[str, float] = {
    "CVE-2014-3566": 3.4,   # POODLE
    "CVE-2016-2183": 5.3,   # SWEET32 / 3DES
    "CVE-2010-0738": 7.5,   # JBoss JMX Console
    "CVE-2015-4000": 3.7,   # Logjam
    "CVE-2014-0160": 7.5,   # Heartbleed
    "CVE-2017-5638": 10.0,  # Apache Struts
    "CVE-2021-44228": 10.0, # Log4Shell
    "CVE-2019-0708": 9.8,   # BlueKeep
    "CVE-2017-0144": 8.1,   # EternalBlue
    "CVE-2020-1472": 10.0,  # Zerologon
    "CVE-2021-34527": 8.8,  # PrintNightmare
}

# Weight factors for risk scoring
_WEIGHTS = {
    "severity_critical": 10.0,
    "severity_high": 7.0,
    "severity_medium": 4.0,
    "severity_low": 1.5,
    "cvss_multiplier": 1.5,
    "exposure_internet": 3.0,
    "exposure_internal": 1.5,
    "eol_os": 5.0,
    "weak_crypto": 4.0,
    "default_creds": 8.0,
    "anonymous_access": 7.0,
    "chain_amplifier": 2.0,
    "service_diversity": 0.5,
}

# End-of-life OS patterns
_EOL_PATTERNS = [
    r"windows\s*(2003|2008|xp|vista|7\b|server\s*2008)",
    r"ubuntu\s*(12|14|16)\.",
    r"centos\s*(5|6)\.",
    r"debian\s*(7|8)\.",
    r"ios\s*12\.",
]

# Weak cryptography patterns
_WEAK_CRYPTO_PATTERNS = [
    r"sslv[23]",
    r"rc4",
    r"3des|triple.?des|des-cbc",
    r"md5",
    r"sha1(?![\d])",
    r"1024.?bit\s*(dh|rsa|dsa)",
    r"export.?cipher",
    r"null.?cipher",
]


@dataclass
class HostRiskProfile:
    """Risk profile for a single host."""
    address: str
    risk_score: float = 0.0
    risk_level: str = "low"  # critical | high | medium | low | info
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    open_services: int = 0
    os_info: str = ""
    is_eol: bool = False
    has_weak_crypto: bool = False
    has_default_creds: bool = False
    has_anonymous_access: bool = False
    attack_chains: list[dict] = field(default_factory=list)
    top_vulnerabilities: list[str] = field(default_factory=list)
    exposure_type: str = "internal"  # internet | internal | unknown
    environment: str = "unknown"  # azure | on-prem | unknown

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "open_services": self.open_services,
            "os_info": self.os_info,
            "is_eol": self.is_eol,
            "has_weak_crypto": self.has_weak_crypto,
            "has_default_creds": self.has_default_creds,
            "has_anonymous_access": self.has_anonymous_access,
            "attack_chains": self.attack_chains,
            "top_vulnerabilities": self.top_vulnerabilities[:5],
            "exposure_type": self.exposure_type,
            "environment": self.environment,
        }


@dataclass
class RiskScoreResult:
    """Complete risk scoring output."""
    overall_score: float = 0.0
    overall_level: str = "low"
    host_profiles: list[HostRiskProfile] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    category_scores: dict = field(default_factory=dict)
    risk_distribution: dict = field(default_factory=dict)
    risk_trend: str = "stable"  # improving | stable | degrading
    top_risks: list[dict] = field(default_factory=list)
    compliance_gaps: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 1),
            "overall_level": self.overall_level,
            "risk_level": self.overall_level,  # alias for frontend compatibility
            "host_profiles": [h.to_dict() for h in self.host_profiles],
            "attack_chains": self.attack_chains,
            "category_scores": self.category_scores,
            "risk_distribution": self.risk_distribution,
            "risk_trend": self.risk_trend,
            "top_risks": self.top_risks,
            "compliance_gaps": self.compliance_gaps,
        }


def _classify_risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _is_eol_os(os_info: str) -> bool:
    """Check if the OS is end-of-life."""
    for pattern in _EOL_PATTERNS:
        if re.search(pattern, os_info, re.IGNORECASE):
            return True
    return False


def _has_weak_crypto_in_text(text: str) -> bool:
    for pattern in _WEAK_CRYPTO_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _detect_attack_chains(host_findings: list[dict]) -> list[dict]:
    """Detect potential multi-step attack chains from co-located findings."""
    chains: list[dict] = []
    titles_lower = [f.get("title", "").lower() for f in host_findings]
    evidence_text = " ".join(f.get("evidence", "") + " " + f.get("description", "") for f in host_findings).lower()

    # Chain: Anonymous FTP + Weak Creds → Data Exfiltration
    has_anon_ftp = any("anonymous" in t and "ftp" in t for t in titles_lower) or "anonymous" in evidence_text and "ftp" in evidence_text
    has_weak_creds = any("default" in t or "weak" in t or "nopass" in t for t in titles_lower)
    if has_anon_ftp:
        chain = {
            "name": "Anonymous FTP Access → Data Exfiltration",
            "severity": "critical",
            "steps": ["Anonymous FTP access confirmed", "File listing/download possible", "Potential data exfiltration"],
            "impact": "Unauthorized access to files, potential data breach",
            "likelihood": "high",
        }
        if has_weak_creds:
            chain["steps"].insert(1, "Weak/default credentials also present")
            chain["name"] = "Weak Credentials + Anonymous FTP → Full Compromise"
        chains.append(chain)

    # Chain: SSL/TLS Weakness + HTTP Service → MitM
    has_ssl_weak = any("ssl" in t or "tls" in t or "poodle" in t or "sweet32" in t for t in titles_lower)
    has_http = any("http" in t or "web" in t for t in titles_lower)
    if has_ssl_weak and has_http:
        chains.append({
            "name": "Weak SSL/TLS + Web Service → Man-in-the-Middle",
            "severity": "high",
            "steps": ["Weak SSL/TLS configuration detected", "Web services exposed", "Potential traffic interception"],
            "impact": "Session hijacking, credential theft, data interception",
            "likelihood": "medium",
        })

    # Chain: EOL OS + Open Services → Remote Exploitation
    has_eol = any("end.of.life" in t or "unsupported" in t or "2008" in t or "2003" in t for t in titles_lower)
    has_open_services = len(host_findings) > 2
    if has_eol and has_open_services:
        chains.append({
            "name": "End-of-Life OS + Exposed Services → Remote Code Execution",
            "severity": "critical",
            "steps": ["Unpatched OS with known vulnerabilities", "Multiple services exposed", "Public exploits likely available"],
            "impact": "Full system compromise, lateral movement",
            "likelihood": "high",
        })

    # Chain: SNMP + Network Device → Network Takeover
    has_snmp = any("snmp" in t for t in titles_lower) or "snmp" in evidence_text
    has_network_device = "cisco" in evidence_text or "fortinet" in evidence_text or "router" in evidence_text
    if has_snmp and has_network_device:
        chains.append({
            "name": "SNMP Exposure + Network Device → Network Reconnaissance/Takeover",
            "severity": "high",
            "steps": ["SNMP service accessible", "Network device identified", "Configuration/topology disclosure possible"],
            "impact": "Network mapping, potential configuration changes",
            "likelihood": "medium",
        })

    # Chain: JMX Console + Open Management → Application Takeover
    has_jmx = any("jmx" in t or "jboss" in t for t in titles_lower)
    if has_jmx:
        chains.append({
            "name": "Unauthenticated JMX Console → Application Server Compromise",
            "severity": "critical",
            "steps": ["JMX Console accessible without authentication", "Arbitrary code deployment possible", "Full application server control"],
            "impact": "Remote code execution, data theft, service disruption",
            "likelihood": "high",
        })

    # Chain: Internal IP Leak + CSRF → Internal Pivot
    has_ip_leak = "internal" in evidence_text and ("ip" in evidence_text or "leak" in evidence_text or "x-forwarded" in evidence_text)
    has_csrf = any("csrf" in t for t in titles_lower)
    if has_ip_leak and has_csrf:
        chains.append({
            "name": "Internal IP Disclosure + CSRF → Internal Network Pivot",
            "severity": "high",
            "steps": ["Internal IP addresses disclosed", "CSRF vulnerabilities enable forged requests", "Attacker can target internal systems"],
            "impact": "Lateral movement into internal network",
            "likelihood": "medium",
        })

    return chains


def _detect_compliance_gaps(findings: list[dict], host_profiles: list[HostRiskProfile]) -> list[dict]:
    """Detect compliance violations against common frameworks."""
    gaps: list[dict] = []
    all_text = " ".join(
        f.get("title", "") + " " + f.get("description", "") + " " + f.get("evidence", "")
        for f in findings
    ).lower()

    eol_hosts = [h for h in host_profiles if h.is_eol]
    if eol_hosts:
        gaps.append({
            "framework": "NIST SP 800-53",
            "control": "SI-2 (Flaw Remediation)",
            "gap": f"{len(eol_hosts)} host(s) running end-of-life operating systems without vendor support",
            "severity": "critical",
            "hosts": [h.address for h in eol_hosts],
        })

    weak_crypto_hosts = [h for h in host_profiles if h.has_weak_crypto]
    if weak_crypto_hosts:
        gaps.append({
            "framework": "PCI DSS v4.0",
            "control": "Requirement 4.2.1",
            "gap": f"{len(weak_crypto_hosts)} host(s) using weak cryptographic algorithms (SSLv3, RC4, 3DES, weak DH)",
            "severity": "high",
            "hosts": [h.address for h in weak_crypto_hosts],
        })

    anon_hosts = [h for h in host_profiles if h.has_anonymous_access]
    if anon_hosts:
        gaps.append({
            "framework": "CIS Controls v8",
            "control": "Control 6 - Access Control Management",
            "gap": f"{len(anon_hosts)} host(s) allowing anonymous/unauthenticated service access",
            "severity": "critical",
            "hosts": [h.address for h in anon_hosts],
        })

    if "trace" in all_text and "method" in all_text:
        gaps.append({
            "framework": "OWASP Top 10",
            "control": "A05:2021 Security Misconfiguration",
            "gap": "HTTP TRACE method enabled on web servers, enabling Cross-Site Tracing (XST)",
            "severity": "medium",
            "hosts": [],
        })

    if "expired" in all_text and ("cert" in all_text or "ssl" in all_text):
        gaps.append({
            "framework": "ISO 27001:2022",
            "control": "A.8.24 - Use of Cryptography",
            "gap": "Expired SSL/TLS certificates detected, indicating poor certificate lifecycle management",
            "severity": "high",
            "hosts": [],
        })

    default_creds_hosts = [h for h in host_profiles if h.has_default_creds]
    if default_creds_hosts:
        gaps.append({
            "framework": "NIST CSF",
            "control": "PR.AC-1 (Identity & Credential Management)",
            "gap": f"{len(default_creds_hosts)} host(s) with default/weak credentials",
            "severity": "critical",
            "hosts": [h.address for h in default_creds_hosts],
        })

    if "sql" in all_text and "inject" in all_text:
        gaps.append({
            "framework": "OWASP Top 10",
            "control": "A03:2021 Injection",
            "gap": "Potential SQL injection vectors detected in web applications",
            "severity": "critical",
            "hosts": [],
        })

    if "elasticsearch" in all_text and ("9200" in all_text or "rest" in all_text):
        gaps.append({
            "framework": "CIS Controls v8",
            "control": "Control 3 - Data Protection",
            "gap": "Elasticsearch REST API exposed without authentication",
            "severity": "high",
            "hosts": [],
        })

    return gaps


def compute_risk_scores(findings: list[dict], hosts_info: list[dict] | None = None) -> RiskScoreResult:
    """Compute comprehensive risk scores from parsed/filtered findings.

    Args:
        findings: List of vulnerability findings (may be filtered or raw).
        hosts_info: Optional list of host metadata dicts with address, os_name, etc.

    Returns:
        RiskScoreResult with per-host profiles, attack chains, and overall score.
    """
    result = RiskScoreResult()

    # Group findings by host
    host_findings: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        asset = f.get("affected_asset", "UNKNOWN")
        host_findings[asset].append(f)

    # Build host metadata lookup
    host_meta: dict[str, dict] = {}
    if hosts_info:
        for h in hosts_info:
            addr = h.get("address", "")
            if addr:
                host_meta[addr] = h

    # Score each host
    all_chains: list[dict] = []
    category_scores: dict[str, float] = defaultdict(float)

    for host_addr, h_findings in host_findings.items():
        profile = HostRiskProfile(address=host_addr)

        # Get host metadata
        meta = host_meta.get(host_addr, {})
        profile.os_info = meta.get("os_name", "") + " " + meta.get("os_flavor", "")
        profile.environment = meta.get("environment", "unknown")
        profile.is_eol = _is_eol_os(profile.os_info)

        # Count severities
        for f in h_findings:
            sev = f.get("severity", "").lower()
            if sev == "critical":
                profile.critical_count += 1
            elif sev == "high":
                profile.high_count += 1
            elif sev == "medium":
                profile.medium_count += 1
            else:
                profile.low_count += 1
            profile.top_vulnerabilities.append(f.get("title", "Unknown"))

        # Compute base score from severity counts
        base_score = (
            profile.critical_count * _WEIGHTS["severity_critical"]
            + profile.high_count * _WEIGHTS["severity_high"]
            + profile.medium_count * _WEIGHTS["severity_medium"]
            + profile.low_count * _WEIGHTS["severity_low"]
        )

        # CVSS amplification
        cvss_scores = [f.get("cvss_score", 0) for f in h_findings if f.get("cvss_score")]
        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            base_score += avg_cvss * _WEIGHTS["cvss_multiplier"]

        # Check for weak crypto
        all_text = " ".join(f.get("title", "") + " " + f.get("description", "") + " " + f.get("evidence", "") for f in h_findings)
        profile.has_weak_crypto = _has_weak_crypto_in_text(all_text)
        if profile.has_weak_crypto:
            base_score += _WEIGHTS["weak_crypto"]

        # Check for default/weak credentials
        if re.search(r"default|nopass|admin.admin|test.test|password123", all_text, re.IGNORECASE):
            profile.has_default_creds = True
            base_score += _WEIGHTS["default_creds"]

        # Check for anonymous access
        if re.search(r"anonymous.*access|anonymous.*login|anon.*ftp", all_text, re.IGNORECASE):
            profile.has_anonymous_access = True
            base_score += _WEIGHTS["anonymous_access"]

        # EOL amplification
        if profile.is_eol:
            base_score += _WEIGHTS["eol_os"]

        # Detect attack chains
        chains = _detect_attack_chains(h_findings)
        profile.attack_chains = chains
        if chains:
            chain_boost = len(chains) * _WEIGHTS["chain_amplifier"]
            crit_chains = sum(1 for c in chains if c["severity"] == "critical")
            chain_boost += crit_chains * 3.0
            base_score += chain_boost
        all_chains.extend(chains)

        # Open service count from findings diversity
        source_files = set(f.get("source_file", "") for f in h_findings)
        profile.open_services = len(source_files)
        base_score += profile.open_services * _WEIGHTS["service_diversity"]

        # Normalize to 0-100 using sigmoid-like function
        profile.risk_score = min(100, 100 * (1 - math.exp(-base_score / 30)))
        profile.risk_level = _classify_risk_level(profile.risk_score)

        result.host_profiles.append(profile)

    # Sort by risk score descending
    result.host_profiles.sort(key=lambda h: h.risk_score, reverse=True)

    # Overall score: weighted average of top hosts + chain amplification
    if result.host_profiles:
        # Use RMS (root-mean-square) to emphasize high-risk hosts
        scores = [h.risk_score for h in result.host_profiles]
        rms = math.sqrt(sum(s ** 2 for s in scores) / len(scores))
        result.overall_score = min(100, rms + len(all_chains) * 1.5)
    result.overall_level = _classify_risk_level(result.overall_score)

    # Category scores
    finding_categories = _categorize_findings(findings)
    for cat, cat_findings in finding_categories.items():
        cat_crits = sum(1 for f in cat_findings if f.get("severity") == "critical")
        cat_highs = sum(1 for f in cat_findings if f.get("severity") == "high")
        cat_score = cat_crits * 10 + cat_highs * 7 + len(cat_findings) * 0.5
        category_scores[cat] = min(100, cat_score)
    result.category_scores = dict(category_scores)

    # Risk distribution
    dist = Counter(h.risk_level for h in result.host_profiles)
    result.risk_distribution = {
        "critical": dist.get("critical", 0),
        "high": dist.get("high", 0),
        "medium": dist.get("medium", 0),
        "low": dist.get("low", 0),
        "info": dist.get("info", 0),
    }

    # Attack chains (deduplicated by name)
    seen_chains: set[str] = set()
    unique_chains: list[dict] = []
    for c in all_chains:
        if c["name"] not in seen_chains:
            seen_chains.add(c["name"])
            unique_chains.append(c)
    result.attack_chains = unique_chains

    # Top risks summary
    for hp in result.host_profiles[:5]:
        if hp.risk_score > 20:
            result.top_risks.append({
                "host": hp.address,
                "score": round(hp.risk_score, 1),
                "level": hp.risk_level,
                "reason": _build_risk_reason(hp),
            })

    # Compliance gaps
    result.compliance_gaps = _detect_compliance_gaps(findings, result.host_profiles)

    # Trend assessment
    crit_ratio = dist.get("critical", 0) / max(1, len(result.host_profiles))
    if crit_ratio > 0.3:
        result.risk_trend = "degrading"
    elif crit_ratio > 0.1:
        result.risk_trend = "stable"
    else:
        result.risk_trend = "improving"

    log.info(
        "Risk scoring complete – overall=%.1f (%s), %d hosts, %d chains, %d compliance gaps",
        result.overall_score, result.overall_level,
        len(result.host_profiles), len(result.attack_chains),
        len(result.compliance_gaps),
    )
    return result


def _build_risk_reason(profile: HostRiskProfile) -> str:
    reasons = []
    if profile.critical_count:
        reasons.append(f"{profile.critical_count} critical findings")
    if profile.high_count:
        reasons.append(f"{profile.high_count} high findings")
    if profile.is_eol:
        reasons.append("end-of-life OS")
    if profile.has_default_creds:
        reasons.append("default credentials")
    if profile.has_anonymous_access:
        reasons.append("anonymous access")
    if profile.has_weak_crypto:
        reasons.append("weak cryptography")
    if profile.attack_chains:
        reasons.append(f"{len(profile.attack_chains)} attack chain(s)")
    return "; ".join(reasons) if reasons else "elevated exposure"


def _categorize_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Categorize findings by vulnerability type."""
    categories: dict[str, list[dict]] = defaultdict(list)

    for f in findings:
        title = (f.get("title", "") + " " + f.get("description", "")).lower()
        evidence = f.get("evidence", "").lower()
        combined = title + " " + evidence

        if any(kw in combined for kw in ["ssl", "tls", "certificate", "cipher", "crypto", "poodle", "sweet32", "dh group"]):
            categories["Cryptography & TLS"].append(f)
        elif any(kw in combined for kw in ["ftp", "anonymous", "authentication", "credential", "password", "login", "brute"]):
            categories["Authentication & Access"].append(f)
        elif any(kw in combined for kw in ["http", "web", "header", "cookie", "csrf", "xss", "injection", "trace"]):
            categories["Web Application"].append(f)
        elif any(kw in combined for kw in ["port", "service", "open", "smb", "rdp", "ssh", "telnet"]):
            categories["Network Services"].append(f)
        elif any(kw in combined for kw in ["os", "kernel", "patch", "update", "end.of.life", "eol"]):
            categories["OS & Patch Management"].append(f)
        elif any(kw in combined for kw in ["snmp", "dns", "dhcp", "ntp"]):
            categories["Infrastructure Protocols"].append(f)
        elif any(kw in combined for kw in ["database", "sql", "db2", "elasticsearch", "redis", "mongo"]):
            categories["Database Security"].append(f)
        else:
            categories["Other"].append(f)

    return dict(categories)
