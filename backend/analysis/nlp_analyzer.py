"""NLP-powered evidence analyzer.

Uses regex-based NLP, TF-IDF-inspired keyword extraction, and pattern
matching to extract structured intelligence from raw evidence text.
Works fully offline with no external dependencies.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Known CVE info (offline enrichment)
_CVE_INFO: dict[str, dict] = {
    "CVE-2014-3566": {"name": "POODLE", "cvss": 3.4, "severity": "medium", "description": "SSLv3 padding oracle attack allows MitM decryption"},
    "CVE-2016-2183": {"name": "SWEET32", "cvss": 5.3, "severity": "medium", "description": "64-bit block cipher birthday attack on 3DES/Blowfish"},
    "CVE-2010-0738": {"name": "JBoss JMX Unauthenticated", "cvss": 7.5, "severity": "high", "description": "JBoss JMX Console allows unauthenticated remote code execution"},
    "CVE-2015-4000": {"name": "Logjam", "cvss": 3.7, "severity": "medium", "description": "TLS vulnerability from weak DH key exchange"},
    "CVE-2014-0160": {"name": "Heartbleed", "cvss": 7.5, "severity": "high", "description": "OpenSSL buffer over-read leaks sensitive memory"},
    "CVE-2021-44228": {"name": "Log4Shell", "cvss": 10.0, "severity": "critical", "description": "Apache Log4j remote code execution via JNDI lookup"},
    "CVE-2019-0708": {"name": "BlueKeep", "cvss": 9.8, "severity": "critical", "description": "Windows RDP pre-auth remote code execution"},
    "CVE-2017-0144": {"name": "EternalBlue", "cvss": 8.1, "severity": "high", "description": "SMBv1 remote code execution vulnerability"},
    "CVE-2020-1472": {"name": "Zerologon", "cvss": 10.0, "severity": "critical", "description": "Netlogon elevation of privilege"},
}


def extract_cves(text: str) -> list[dict]:
    """Extract CVE references from text and enrich with known info."""
    found = set(_CVE_PATTERN.findall(text.upper()))
    results = []
    for cve_id in sorted(found):
        info = _CVE_INFO.get(cve_id, {})
        results.append({
            "cve_id": cve_id,
            "name": info.get("name", "Unknown"),
            "cvss": info.get("cvss"),
            "severity": info.get("severity", "unknown"),
            "description": info.get("description", "No description available offline"),
        })
    return results


# ---------------------------------------------------------------------------
# Service / Port extraction
# ---------------------------------------------------------------------------
_PORT_PATTERN = re.compile(
    r"(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)",
    re.IGNORECASE,
)

_SERVICE_BANNER_PATTERN = re.compile(
    r"(?:Server|X-Powered-By|Via):\s*(.+)",
    re.IGNORECASE,
)


def extract_services(text: str) -> list[dict]:
    """Extract open services from nmap-style output."""
    services = []
    seen = set()
    for match in _PORT_PATTERN.finditer(text):
        port, proto, state, service = match.groups()
        key = (port, proto)
        if key not in seen and state.lower() == "open":
            seen.add(key)
            services.append({
                "port": int(port),
                "protocol": proto.lower(),
                "state": state.lower(),
                "service": service,
            })
    return services


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(text: str) -> list[str]:
    """Extract unique IP addresses from text."""
    ips = set(_IP_PATTERN.findall(text))
    # Filter out common non-host IPs
    return sorted(ip for ip in ips if not ip.startswith("0.") and ip != "255.255.255.255")


# ---------------------------------------------------------------------------
# Keyword extraction (TF-IDF inspired)
# ---------------------------------------------------------------------------
# Security-relevant keywords with importance weights
_SECURITY_KEYWORDS: dict[str, float] = {
    "critical": 5.0, "vulnerability": 4.0, "exploit": 5.0, "remote": 3.5,
    "unauthenticated": 5.0, "authentication": 3.0, "bypass": 4.5,
    "injection": 5.0, "overflow": 4.5, "disclosure": 3.5,
    "arbitrary": 4.0, "code execution": 5.0, "denial of service": 3.5,
    "privileges": 3.5, "escalation": 4.5, "root": 4.0,
    "password": 3.5, "credential": 4.0, "plaintext": 4.5,
    "anonymous": 4.5, "default": 3.5, "backdoor": 5.0,
    "ssl": 3.0, "tls": 3.0, "certificate": 2.5, "expired": 3.5,
    "cipher": 3.0, "weak": 3.5, "deprecated": 3.5,
    "poodle": 4.0, "sweet32": 3.5, "heartbleed": 5.0,
    "smb": 3.5, "ftp": 3.0, "snmp": 3.5, "rdp": 3.5, "ssh": 2.5,
    "telnet": 4.0, "http": 2.0, "https": 2.0,
    "csrf": 4.0, "xss": 4.5, "sqli": 5.0,
    "information leak": 3.5, "internal ip": 3.5,
    "end of life": 4.5, "unsupported": 4.0, "unpatched": 4.5,
    "misconfigured": 3.5, "open port": 3.0,
    "brute force": 3.5, "hydra": 3.0,
}


def extract_keywords(text: str, top_n: int = 15) -> list[dict]:
    """Extract security-relevant keywords with importance scores."""
    text_lower = text.lower()
    scored: list[tuple[str, float, int]] = []

    for keyword, weight in _SECURITY_KEYWORDS.items():
        count = text_lower.count(keyword)
        if count > 0:
            # Score = weight * log(1 + count) to dampen high-frequency terms
            import math
            score = weight * math.log1p(count)
            scored.append((keyword, round(score, 2), count))

    scored.sort(key=lambda x: x[1], reverse=True)
    return [
        {"keyword": kw, "score": sc, "count": ct}
        for kw, sc, ct in scored[:top_n]
    ]


# ---------------------------------------------------------------------------
# Vulnerability classification
# ---------------------------------------------------------------------------
_VULN_CATEGORIES = {
    "Cryptography & TLS": [
        r"ssl", r"tls", r"cipher", r"certificate", r"poodle", r"sweet32",
        r"heartbleed", r"dh.?group", r"rc4", r"3des", r"des-cbc", r"sha1",
        r"md5.*hash", r"export.*cipher", r"logjam",
    ],
    "Authentication & Access": [
        r"anonymous", r"credential", r"password", r"login", r"brute",
        r"authentication", r"default.*pass", r"nopass", r"unauthorized",
        r"admin.*access", r"privilege", r"escalat",
    ],
    "Web Application": [
        r"http.*header", r"cookie", r"csrf", r"xss", r"inject(?!ion\b)",
        r"sql.*inject", r"trace.*method", r"clickjack", r"cors",
        r"content.?security", r"x-frame", r"hsts",
    ],
    "Network Services": [
        r"open.*port", r"smb", r"rdp", r"ssh.*weak", r"telnet",
        r"ftp", r"nfs", r"ldap", r"samba",
    ],
    "Information Disclosure": [
        r"information.*leak", r"internal.*ip", r"server.*version",
        r"stack.*trace", r"debug", r"verbose.*error", r"directory.*list",
        r"source.*disclos", r"banner",
    ],
    "Infrastructure": [
        r"snmp", r"dns.*zone", r"ntp.*amplif", r"dhcp",
        r"elasticsearch", r"database", r"db2", r"redis", r"mongo",
    ],
}


def classify_finding(finding: dict) -> str:
    """Classify a finding into a vulnerability category."""
    text = (
        finding.get("title", "") + " "
        + finding.get("description", "") + " "
        + finding.get("evidence", "")
    ).lower()

    best_cat = "Other"
    best_score = 0

    for category, patterns in _VULN_CATEGORIES.items():
        score = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
        if score > best_score:
            best_score = score
            best_cat = category

    return best_cat


def classify_all_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Classify all findings into categories."""
    categorized: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        cat = classify_finding(f)
        categorized[cat].append(f)
    return dict(categorized)


# ---------------------------------------------------------------------------
# Severity prediction from text (when severity is missing/generic)
# ---------------------------------------------------------------------------
_SEVERITY_INDICATORS = {
    "critical": [
        r"remote\s+code\s+execution", r"unauthenticated.*access",
        r"arbitrary\s+code", r"backdoor", r"zero.?day",
        r"cvss.*[89]\.\d|cvss.*10\.0", r"root.*access",
        r"pre-?auth", r"default.*password.*admin",
    ],
    "high": [
        r"privilege.*escalat", r"sql.*inject", r"bypass.*auth",
        r"information.*disclosure.*sensitive", r"man.in.the.middle",
        r"cvss.*[67]\.\d", r"buffer.*overflow", r"xss.*stored",
        r"weak.*encryption", r"anonymous.*access",
    ],
    "medium": [
        r"cross.site.*scripting", r"csrf", r"clickjack",
        r"ssl.*weak", r"deprecated.*protocol", r"information.*leak",
        r"cvss.*[45]\.\d", r"session.*fixation", r"trace.*method",
        r"3des|sweet32|poodle",
    ],
    "low": [
        r"informational", r"best.*practice", r"header.*missing",
        r"cookie.*flag", r"verbose.*error", r"banner.*disclosure",
        r"cvss.*[0-3]\.\d",
    ],
}


def predict_severity(text: str) -> str:
    """Predict severity from description/evidence text."""
    text_lower = text.lower()
    scores = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for severity, patterns in _SEVERITY_INDICATORS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                scores[severity] += 1

    # Return highest scoring severity
    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best
    return "medium"  # default


# ---------------------------------------------------------------------------
# Full NLP analysis pipeline
# ---------------------------------------------------------------------------
@dataclass
class NLPAnalysisResult:
    """Complete NLP analysis output."""
    cves_found: list[dict] = field(default_factory=list)
    keywords: list[dict] = field(default_factory=list)
    finding_categories: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    services_detected: list[dict] = field(default_factory=list)
    ips_found: list[str] = field(default_factory=list)
    threat_indicators: list[dict] = field(default_factory=list)
    context_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "cves_found": self.cves_found,
            "keywords": self.keywords,
            "finding_categories": self.finding_categories,
            "severity_distribution": self.severity_distribution,
            "services_detected": self.services_detected,
            "ips_found": self.ips_found[:30],
            "threat_indicators": self.threat_indicators,
            "context_summary": self.context_summary,
        }


def _detect_threat_indicators(text: str) -> list[dict]:
    """Detect specific threat indicators from evidence text."""
    indicators: list[dict] = []
    text_lower = text.lower()

    threat_checks = [
        ("Expired SSL Certificate", r"expired.*cert|cert.*expired", "high",
         "Expired certificates indicate poor PKI management and enable MitM attacks"),
        ("Anonymous FTP Access", r"anonymous.*ftp|ftp.*anonymous.*login", "critical",
         "Anonymous FTP allows unauthenticated file access and potential data exfiltration"),
        ("Default Credentials", r"default.*password|admin.*nopass|password.*password", "critical",
         "Default credentials provide immediate unauthorized access"),
        ("SNMP Public Community", r"snmp.*public|community.*public", "high",
         "Default SNMP community strings expose network configuration data"),
        ("SSL POODLE Vulnerability", r"poodle|sslv3.*cbc", "medium",
         "SSLv3 POODLE allows MitM decryption of encrypted traffic"),
        ("SWEET32 / 3DES Weakness", r"sweet32|3des.*cbc|des-cbc3", "medium",
         "64-bit block ciphers vulnerable to birthday attacks"),
        ("HTTP TRACE Enabled", r"trace.*method.*enabled|trace.*is.*enabled", "medium",
         "TRACE method enables Cross-Site Tracing attacks"),
        ("Internal IP Disclosure", r"internal.*ip.*disclos|private.*ip.*leak|x-forwarded.*10\.", "medium",
         "Internal IP disclosure aids attacker reconnaissance"),
        ("SQL Injection Vector", r"sql.*inject|sqli|webresource\.axd", "critical",
         "SQL injection enables database compromise and data theft"),
        ("CSRF Vulnerability", r"csrf|cross.site.*request.*forgery", "high",
         "CSRF enables attackers to perform actions on behalf of authenticated users"),
        ("JMX Console Exposed", r"jmx.*console|jboss.*jmx", "critical",
         "Exposed JMX console allows remote code execution"),
        ("Elasticsearch Exposed", r"elasticsearch.*api|elasticsearch.*9200", "high",
         "Exposed Elasticsearch enables unauthorized data access"),
        ("Weak DH Parameters", r"weak.*dh|1024.*bit.*dh|dh.*1024", "medium",
         "Weak DH parameters enable Logjam-style attacks"),
        ("End-of-Life Software", r"windows\s*2008|windows\s*2003|eol|end.of.life|unsupported", "high",
         "EOL software has no security patches, increasing exploitation risk"),
        ("FileZilla FTP Detected", r"filezilla.*0\.9|filezilla.*server.*0", "high",
         "Outdated FileZilla Server with known vulnerabilities"),
    ]

    seen = set()
    for name, pattern, severity, description in threat_checks:
        if re.search(pattern, text_lower) and name not in seen:
            seen.add(name)
            indicators.append({
                "name": name,
                "severity": severity,
                "description": description,
            })

    return indicators


def run_nlp_analysis(findings: list[dict], raw_evidence_text: str = "") -> NLPAnalysisResult:
    """Run comprehensive NLP analysis on findings and raw evidence.

    Args:
        findings: List of parsed vulnerability findings.
        raw_evidence_text: Combined raw text from all evidence files.

    Returns:
        NLPAnalysisResult with extracted intelligence.
    """
    result = NLPAnalysisResult()

    # Combine all text
    all_text = raw_evidence_text + "\n"
    for f in findings:
        all_text += " ".join([
            f.get("title", ""),
            f.get("description", ""),
            f.get("evidence", ""),
            f.get("remediation", ""),
        ]) + "\n"

    # Extract CVEs
    result.cves_found = extract_cves(all_text)

    # Extract keywords
    result.keywords = extract_keywords(all_text, top_n=20)

    # Classify findings
    categories = classify_all_findings(findings)
    result.finding_categories = {cat: len(items) for cat, items in categories.items()}

    # Severity distribution
    sev_dist = Counter(f.get("severity", "unknown") for f in findings)
    result.severity_distribution = dict(sev_dist)

    # Extract services
    result.services_detected = extract_services(all_text)

    # Extract IPs
    result.ips_found = extract_ips(all_text)

    # Detect threat indicators
    result.threat_indicators = _detect_threat_indicators(all_text)

    # Build context summary for LLM
    result.context_summary = _build_context_summary(result, len(findings))

    log.info(
        "NLP analysis complete – %d CVEs, %d keywords, %d categories, %d threats",
        len(result.cves_found), len(result.keywords),
        len(result.finding_categories), len(result.threat_indicators),
    )
    return result


def _build_context_summary(result: NLPAnalysisResult, finding_count: int) -> str:
    """Build a structured context summary for LLM consumption."""
    parts = [f"Analysis of {finding_count} security findings:"]

    if result.cves_found:
        cve_list = ", ".join(c["cve_id"] for c in result.cves_found[:10])
        parts.append(f"CVEs identified: {cve_list}")

    if result.threat_indicators:
        critical_threats = [t["name"] for t in result.threat_indicators if t["severity"] == "critical"]
        if critical_threats:
            parts.append(f"CRITICAL threats: {', '.join(critical_threats)}")

    if result.finding_categories:
        top_cats = sorted(result.finding_categories.items(), key=lambda x: x[1], reverse=True)[:5]
        cat_str = "; ".join(f"{cat}: {count}" for cat, count in top_cats)
        parts.append(f"Finding categories: {cat_str}")

    if result.severity_distribution:
        sev_str = ", ".join(f"{sev}: {count}" for sev, count in sorted(result.severity_distribution.items()))
        parts.append(f"Severity distribution: {sev_str}")

    return " | ".join(parts)
