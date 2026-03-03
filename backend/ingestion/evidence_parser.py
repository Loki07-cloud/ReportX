"""Evidence text file parsers for security scan outputs.

Handles Nmap, banners, Hydra brute force, FTP, SNMP, SSL/TLS,
HTTP headers, vulnerability assessment, and reconnaissance output.
Converts raw .txt evidence files into structured vulnerability findings.
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Content pre-processing helpers
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[0m|\[1m|\[34m|\[\d+m")
_MSF_PREFIX_RE = re.compile(r"^\[\*\]\s*Nmap:\s*", re.MULTILINE)
_CURL_PROGRESS_RE = re.compile(
    r"^\s*(%\s+Total|Dload|Upload|--:--:--|^\s*\d+\s+\d+).*$",
    re.MULTILINE,
)


def _clean_content(content: str) -> str:
    """Strip ANSI escape codes, Metasploit prefixes, and curl progress lines."""
    # Remove ANSI color escape sequences
    content = _ANSI_RE.sub("", content)
    # Remove MSF workspace lines (e.g. "[*] Workspace: ...")
    content = re.sub(r"^\[\*\]\s*Workspace:.*$", "", content, flags=re.MULTILINE)
    # Remove the "[*] Nmap: " prefix from nmap output run inside MSF
    content = _MSF_PREFIX_RE.sub("", content)
    # Remove curl progress/stat lines
    content = _CURL_PROGRESS_RE.sub("", content)
    # Collapse multiple blank lines
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


# ---------------------------------------------------------------------------
# Nmap scan output parser
# ---------------------------------------------------------------------------
_NMAP_HOST_RE = re.compile(r"Nmap scan report for\s+(\S+)")
_NMAP_PORT_RE = re.compile(
    r"(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)",
    re.IGNORECASE,
)
_NMAP_OS_RE = re.compile(r"OS details?:\s*(.+)", re.IGNORECASE)
_NMAP_VULN_RE = re.compile(
    r"\|\s*([\w-]+):\s*\n((?:\|\s+.*\n)*)",
    re.MULTILINE,
)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def parse_nmap_scan(content: str, source_file: str) -> list[dict]:
    """Parse nmap port scan / service detection output."""
    findings: list[dict] = []
    current_host = "UNKNOWN"

    for line in content.split("\n"):
        host_match = _NMAP_HOST_RE.search(line)
        if host_match:
            current_host = host_match.group(1)
            continue

        port_match = _NMAP_PORT_RE.match(line.strip())
        if port_match:
            port, proto, state, service, info = port_match.groups()
            if state.lower() == "open":
                severity = _assess_service_risk(int(port), service, info)
                findings.append({
                    "source_file": source_file,
                    "vulnerability_id": f"OPEN-{port}-{proto.upper()}",
                    "title": f"Open {service.upper()} Service on Port {port}/{proto}",
                    "severity": severity,
                    "cve": None,
                    "cvss_score": _service_cvss(int(port), service),
                    "affected_asset": current_host,
                    "description": f"Open {service} service detected on port {port}/{proto}. {info.strip()}",
                    "evidence": line.strip(),
                    "remediation": _service_remediation(service, int(port)),
                })

    log.info("Parsed %d findings from nmap scan %s", len(findings), source_file)
    return findings


def _assess_service_risk(port: int, service: str, info: str) -> str:
    """Assess risk level of an open service."""
    svc_lower = service.lower()
    info_lower = info.lower()

    # Critical risk services
    if svc_lower in ("telnet", "rlogin", "rsh", "rexec"):
        return "critical"
    if svc_lower == "ftp" and ("anonymous" in info_lower or "0.9.60" in info_lower):
        return "critical"
    if svc_lower == "ms-sql" or port == 1433:
        return "high"
    if svc_lower == "smb" or port in (445, 139):
        return "high"
    if port == 9200:  # Elasticsearch
        return "high"
    if "jmx" in info_lower or "jboss" in info_lower:
        return "critical"

    # High risk
    if svc_lower == "ftp":
        return "high"
    if svc_lower == "snmp":
        return "high"
    if svc_lower == "rdp" or port == 3389:
        return "high"
    if port in (8080, 8443, 9090):  # management ports
        return "high"

    # Medium risk
    if svc_lower in ("http", "https", "ssh"):
        return "medium"

    return "medium"


def _service_cvss(port: int, service: str) -> float:
    """Estimate CVSS score for an open service."""
    svc = service.lower()
    if svc in ("telnet", "rlogin"):
        return 9.0
    if svc == "ftp":
        return 7.5
    if svc == "snmp":
        return 7.0
    if svc in ("smb", "ms-sql"):
        return 7.5
    if svc == "rdp":
        return 7.0
    if svc in ("http", "https"):
        return 5.0
    if svc == "ssh":
        return 4.0
    return 5.0


def _service_remediation(service: str, port: int) -> str:
    """Provide remediation guidance for a detected service."""
    recs = {
        "ftp": "Disable FTP and use SFTP/SCP. If FTP is required, disable anonymous access and enforce TLS.",
        "telnet": "Disable Telnet immediately and use SSH for remote management.",
        "snmp": "Restrict SNMP to management VLANs, use SNMPv3 with authentication, change default community strings.",
        "smb": "Restrict SMB access via firewall rules, disable SMBv1, enforce SMB signing.",
        "rdp": "Enable NLA, restrict RDP access via firewall, use VPN for remote access.",
        "ssh": "Disable root login, use key-based authentication, restrict to management networks.",
        "http": "Enable HTTPS, implement security headers (HSTS, CSP, X-Frame-Options).",
        "https": "Ensure strong TLS configuration (TLS 1.2+), disable weak ciphers.",
    }
    return recs.get(service.lower(), f"Review necessity of service on port {port} and restrict access if not required.")


# ---------------------------------------------------------------------------
# Vulnerability assessment parser (nmap vuln scripts)
# ---------------------------------------------------------------------------
def parse_vuln_assessment(content: str, source_file: str) -> list[dict]:
    """Parse nmap vulnerability script output (--script vuln)."""
    findings: list[dict] = []

    # Extract host from filename (e.g., 10.102.237.149_http_80_nmap_vuln.txt)
    host = _extract_host_from_filename(source_file)

    # Parse each vulnerability block
    lines = content.split("\n")
    current_vuln = None
    current_text = []

    for line in lines:
        # Detect script names like |_http-trace: TRACE is enabled
        vuln_start = re.match(r"\|[_\s]*([\w-]+):\s*(.*)", line)
        if vuln_start and not line.strip().startswith("|  "):
            if current_vuln:
                findings.extend(_process_vuln_block(current_vuln, "\n".join(current_text), host, source_file))
            current_vuln = vuln_start.group(1)
            current_text = [vuln_start.group(2)]
        elif line.strip().startswith("|"):
            text = re.sub(r"^\|\s*", "", line.strip())
            current_text.append(text)

    if current_vuln:
        findings.extend(_process_vuln_block(current_vuln, "\n".join(current_text), host, source_file))

    log.info("Parsed %d findings from vuln assessment %s", len(findings), source_file)
    return findings


def _process_vuln_block(vuln_name: str, text: str, host: str, source_file: str) -> list[dict]:
    """Convert a vulnerability block into structured findings."""
    findings = []
    text_lower = text.lower()

    # Skip informational/not vulnerable results
    if "not vulnerable" in text_lower or "error" in text_lower and len(text) < 50:
        return []

    # Extract CVEs
    cves = _CVE_RE.findall(text)

    severity = _assess_vuln_severity(vuln_name, text)
    if severity == "info":
        return []

    title = _vuln_title(vuln_name, text)
    description = text[:500].strip()

    finding = {
        "source_file": source_file,
        "vulnerability_id": cves[0] if cves else vuln_name.upper(),
        "title": title,
        "severity": severity,
        "cve": cves[0] if cves else None,
        "cvss_score": _vuln_cvss(vuln_name, cves[0] if cves else None),
        "affected_asset": host,
        "description": description,
        "evidence": text[:1000].strip(),
        "remediation": _vuln_remediation(vuln_name, text),
    }
    findings.append(finding)

    return findings


def _assess_vuln_severity(vuln_name: str, text: str) -> str:
    """Assess severity of a vulnerability assessment finding."""
    name_lower = vuln_name.lower()
    text_lower = text.lower()

    if any(kw in name_lower for kw in ["rce", "code-execution", "jmx"]):
        return "critical"
    if any(kw in text_lower for kw in ["remote code execution", "arbitrary code", "jmx console"]):
        return "critical"
    if "poodle" in text_lower or "CVE-2014-3566" in text:
        return "high"
    if "sweet32" in text_lower or "3des" in text_lower:
        return "high"
    if "trace" in name_lower and "enabled" in text_lower:
        return "medium"
    if "csrf" in text_lower:
        return "high"
    if "sql" in text_lower and "inject" in text_lower:
        return "critical"
    if "internal" in text_lower and "ip" in text_lower:
        return "medium"
    if "ssl" in name_lower or "tls" in name_lower:
        return "high"
    if "vuln" in name_lower:
        return "high"
    if any(kw in name_lower for kw in ["header", "enum"]):
        return "medium"
    return "medium"


def _vuln_title(vuln_name: str, text: str) -> str:
    """Generate a human-readable title from vuln script name."""
    title_map = {
        "http-trace": "HTTP TRACE Method Enabled",
        "ssl-poodle": "SSL POODLE Vulnerability (CVE-2014-3566)",
        "ssl-dh-params": "Weak Diffie-Hellman Key Exchange",
        "ssl-ccs-injection": "SSL CCS Injection Vulnerability",
        "ssl-heartbleed": "OpenSSL Heartbleed Vulnerability",
        "http-csrf": "Cross-Site Request Forgery (CSRF)",
        "http-sql-injection": "SQL Injection Vulnerability",
        "http-enum": "Web Application Directory Enumeration",
        "http-headers": "HTTP Security Header Analysis",
        "smb-vuln-ms17-010": "EternalBlue SMB Vulnerability (MS17-010)",
    }
    return title_map.get(vuln_name.lower(), vuln_name.replace("-", " ").replace("_", " ").title())


def _vuln_cvss(vuln_name: str, cve: str | None) -> float | None:
    """Estimate CVSS for known vulnerability scripts."""
    cvss_map = {
        "CVE-2014-3566": 3.4,
        "CVE-2016-2183": 5.3,
        "CVE-2010-0738": 7.5,
        "CVE-2014-0160": 7.5,
        "CVE-2017-0144": 8.1,
    }
    if cve and cve.upper() in cvss_map:
        return cvss_map[cve.upper()]
    name_lower = vuln_name.lower()
    if "poodle" in name_lower:
        return 3.4
    if "heartbleed" in name_lower:
        return 7.5
    if "trace" in name_lower:
        return 5.3
    if "csrf" in name_lower:
        return 6.5
    return None


def _vuln_remediation(vuln_name: str, text: str) -> str:
    """Provide remediation for known vulnerability types."""
    name_lower = vuln_name.lower()
    if "trace" in name_lower:
        return "Disable HTTP TRACE method in web server configuration (TraceEnable Off in Apache, remove TRACE from allowed methods in IIS)."
    if "poodle" in name_lower or "sslv3" in name_lower:
        return "Disable SSLv3 protocol. Configure minimum TLS 1.2. Update cipher suite configuration."
    if "sweet32" in name_lower or "3des" in name_lower:
        return "Disable 3DES and other 64-bit block ciphers. Use AES-GCM or ChaCha20."
    if "dh" in name_lower:
        return "Use 2048-bit or larger DH parameters. Prefer ECDHE key exchange."
    if "csrf" in name_lower:
        return "Implement anti-CSRF tokens. Use SameSite cookie attribute. Validate Referer/Origin headers."
    if "heartbleed" in name_lower:
        return "Update OpenSSL to patched version. Regenerate SSL certificates and keys."
    if "header" in name_lower:
        return "Implement security headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, X-XSS-Protection."
    return "Review and remediate according to vendor security guidance."


# ---------------------------------------------------------------------------
# Banner / FTP / credential test parser
# ---------------------------------------------------------------------------
def parse_banner_or_test(content: str, source_file: str) -> list[dict]:
    """Parse banner grabs and credential test results."""
    findings = []
    host = _extract_host_from_filename(source_file)
    filename_lower = source_file.lower()

    # FTP anonymous access test
    if "anonymous" in filename_lower and "ftp" in content.lower():
        if "230" in content:  # 230 = login successful
            findings.append({
                "source_file": source_file,
                "vulnerability_id": "FTP-ANON-ACCESS",
                "title": "Anonymous FTP Login Successful",
                "severity": "critical",
                "cve": None,
                "cvss_score": 8.5,
                "affected_asset": host,
                "description": "Anonymous FTP access is enabled allowing unauthenticated users to access the FTP server.",
                "evidence": content.strip()[:1000],
                "remediation": "Disable anonymous FTP access. Require authenticated users with strong passwords.",
            })
        elif "331" in content:  # 331 = password required
            findings.append({
                "source_file": source_file,
                "vulnerability_id": "FTP-ANON-PARTIAL",
                "title": "FTP Anonymous User Accepted (Password Required)",
                "severity": "medium",
                "cve": None,
                "cvss_score": 4.0,
                "affected_asset": host,
                "description": "FTP server accepts 'anonymous' as a username but requires a password.",
                "evidence": content.strip()[:1000],
                "remediation": "Disable anonymous FTP user if not required.",
            })

    # Admin no-password test
    if "admin" in filename_lower and "nopass" in filename_lower:
        if "230" in content:
            findings.append({
                "source_file": source_file,
                "vulnerability_id": "FTP-ADMIN-NOPASS",
                "title": "FTP Admin Access Without Password",
                "severity": "critical",
                "cve": None,
                "cvss_score": 9.8,
                "affected_asset": host,
                "description": "Admin FTP access is possible without a password, providing full unauthorized access.",
                "evidence": content.strip()[:1000],
                "remediation": "Immediately set a strong password for the admin account or disable the account.",
            })

    # Banner grab
    if "banner" in filename_lower:
        service_info = _extract_service_from_banner(content)
        if service_info:
            sev = "medium"
            if "0.9.60" in content:  # Old FileZilla
                sev = "high"
            findings.append({
                "source_file": source_file,
                "vulnerability_id": "BANNER-INFO",
                "title": f"Service Banner Disclosure: {service_info}",
                "severity": sev,
                "cve": None,
                "cvss_score": 5.0 if sev == "high" else 3.0,
                "affected_asset": host,
                "description": f"Service banner reveals software version: {service_info}. This aids attacker reconnaissance.",
                "evidence": content.strip()[:1000],
                "remediation": "Configure the service to suppress or obfuscate version information in banners.",
            })

    return findings


def _extract_service_from_banner(content: str) -> str | None:
    """Extract service name/version from a banner."""
    patterns = [
        r"(FileZilla\s+Server\s+[\d.]+\s*\w*)",
        r"(Apache[\s/][\d.]+)",
        r"(nginx[\s/][\d.]+)",
        r"(Microsoft-IIS[\s/][\d.]+)",
        r"(OpenSSH[\s_][\d.]+\w*)",
        r"(ProFTPD\s+[\d.]+)",
        r"(vsftpd\s+[\d.]+)",
    ]
    for pattern in patterns:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    # Generic first line
    first_line = content.strip().split("\n")[0][:100]
    if len(first_line) > 5:
        return first_line
    return None


# ---------------------------------------------------------------------------
# Hydra brute force result parser
# ---------------------------------------------------------------------------
def parse_hydra_result(content: str, source_file: str) -> list[dict]:
    """Parse Hydra brute force test output."""
    findings = []
    host = _extract_host_from_filename(source_file)

    # Look for successful logins
    success_pattern = re.compile(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)", re.IGNORECASE)
    for match in success_pattern.finditer(content):
        port, service, target, login, password = match.groups()
        findings.append({
            "source_file": source_file,
            "vulnerability_id": f"BRUTE-{service.upper()}-{port}",
            "title": f"Brute Force Success: {service.upper()} Credential '{login}' Found",
            "severity": "critical",
            "cve": None,
            "cvss_score": 9.0,
            "affected_asset": target or host,
            "description": f"Hydra brute force attack succeeded on {service} port {port}. User '{login}' with weak/default password.",
            "evidence": f"Login: {login}, Port: {port}/{service}",
            "remediation": "Change credentials immediately. Implement account lockout. Use strong password policy. Consider MFA.",
        })

    # If content has attempts but no success
    if not findings and ("login:" not in content.lower() and "valid" not in content.lower()):
        if "0 valid" in content.lower() or "0 of" in content.lower():
            pass  # Not a finding—no creds found
        elif content.strip():
            findings.append({
                "source_file": source_file,
                "vulnerability_id": f"BRUTE-ATTEMPT",
                "title": f"Brute Force Test Conducted",
                "severity": "low",
                "cve": None,
                "cvss_score": None,
                "affected_asset": host,
                "description": "Brute force testing was conducted but no valid credentials found.",
                "evidence": content.strip()[:500],
                "remediation": "Implement brute force protection (account lockout, rate limiting, fail2ban).",
            })

    return findings


# ---------------------------------------------------------------------------
# SSL/TLS analysis parser
# ---------------------------------------------------------------------------
def parse_ssl_analysis(content: str, source_file: str) -> list[dict]:
    """Parse SSL cipher and certificate analysis output."""
    findings = []
    host = _extract_host_from_filename(source_file)

    content_lower = content.lower()

    # SSLv3 / SSLv2
    if re.search(r"sslv[23]", content_lower):
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "SSL-DEPRECATED-PROTOCOL",
            "title": "Deprecated SSL Protocol Enabled (SSLv2/SSLv3)",
            "severity": "high",
            "cve": "CVE-2014-3566",
            "cvss_score": 3.4,
            "affected_asset": host,
            "description": "Deprecated SSL protocol versions are enabled, vulnerable to POODLE and other attacks.",
            "evidence": _extract_context(content, r"sslv[23]", 200),
            "remediation": "Disable SSLv2 and SSLv3. Configure minimum TLS version to 1.2.",
        })

    # Weak ciphers (RC4, 3DES, NULL, EXPORT)
    weak_ciphers = re.findall(r"(?:TLS|SSL)_\w*(?:RC4|3DES|DES_CBC|NULL|EXPORT)\w*", content, re.IGNORECASE)
    if weak_ciphers:
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "SSL-WEAK-CIPHER",
            "title": f"Weak SSL/TLS Ciphers Detected ({len(weak_ciphers)} ciphers)",
            "severity": "high",
            "cve": "CVE-2016-2183" if any("3DES" in c for c in weak_ciphers) else None,
            "cvss_score": 5.3,
            "affected_asset": host,
            "description": f"Weak cipher suites detected: {', '.join(weak_ciphers[:5])}",
            "evidence": "\n".join(weak_ciphers[:10]),
            "remediation": "Remove RC4, 3DES, NULL, and EXPORT ciphers. Use AES-GCM and ChaCha20-Poly1305.",
        })

    # Weak DH
    if re.search(r"1024.?bit\s*dh|weak.*dh|dh.*1024", content_lower):
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "SSL-WEAK-DH",
            "title": "Weak Diffie-Hellman Key Exchange Parameters",
            "severity": "high",
            "cve": "CVE-2015-4000",
            "cvss_score": 3.7,
            "affected_asset": host,
            "description": "Server uses 1024-bit or smaller DH parameters, vulnerable to Logjam attack.",
            "evidence": _extract_context(content, r"dh|diffie", 200),
            "remediation": "Use 2048-bit or larger DH parameters. Prefer ECDHE key exchange.",
        })

    # Expired certificate
    if "expired" in content_lower and ("cert" in content_lower or "ssl" in content_lower):
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "SSL-EXPIRED-CERT",
            "title": "Expired SSL/TLS Certificate",
            "severity": "high",
            "cve": None,
            "cvss_score": 5.0,
            "affected_asset": host,
            "description": "SSL/TLS certificate has expired, causing trust warnings and potential MitM exposure.",
            "evidence": _extract_context(content, r"expir", 300),
            "remediation": "Renew the SSL/TLS certificate immediately. Implement automated certificate renewal.",
        })

    return findings


# ---------------------------------------------------------------------------
# HTTP header analysis parser
# ---------------------------------------------------------------------------
def parse_http_headers(content: str, source_file: str) -> list[dict]:
    """Parse HTTP header security analysis output."""
    findings = []
    host = _extract_host_from_filename(source_file)
    content_lower = content.lower()

    # Missing security headers
    missing_headers = []
    for header, severity, desc in [
        ("Strict-Transport-Security", "high", "HSTS not configured, enabling protocol downgrade attacks"),
        ("X-Frame-Options", "medium", "X-Frame-Options not set, enabling clickjacking attacks"),
        ("X-Content-Type-Options", "medium", "X-Content-Type-Options not set, enabling MIME sniffing"),
        ("Content-Security-Policy", "medium", "Content-Security-Policy not configured"),
        ("X-XSS-Protection", "low", "X-XSS-Protection not set"),
    ]:
        header_lower = header.lower()
        # Check if header is mentioned as missing or not present
        if (header_lower not in content_lower) or ("missing" in content_lower and header_lower in content_lower):
            if "header" in content_lower:  # Only if this is actually a header analysis
                missing_headers.append((header, severity, desc))

    if missing_headers:
        sev = missing_headers[0][1] if missing_headers else "medium"
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "HTTP-MISSING-HEADERS",
            "title": f"Missing HTTP Security Headers ({len(missing_headers)} headers)",
            "severity": sev,
            "cve": None,
            "cvss_score": 4.0,
            "affected_asset": host,
            "description": "; ".join(d for _, _, d in missing_headers),
            "evidence": content.strip()[:800],
            "remediation": "Configure all recommended security headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP.",
        })

    # Server version disclosure
    server_match = re.search(r"Server:\s*(.+)", content, re.IGNORECASE)
    if server_match:
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "HTTP-SERVER-DISCLOSURE",
            "title": f"HTTP Server Version Disclosed: {server_match.group(1).strip()[:60]}",
            "severity": "low",
            "cve": None,
            "cvss_score": 2.0,
            "affected_asset": host,
            "description": f"Server header reveals: {server_match.group(1).strip()}",
            "evidence": server_match.group(0),
            "remediation": "Remove or obfuscate the Server header to prevent information disclosure.",
        })

    # Internal IP disclosure
    internal_ips = re.findall(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", content)
    if internal_ips and host not in internal_ips:
        unique_ips = list(set(ip for ip in internal_ips if ip != host))
        if unique_ips:
            findings.append({
                "source_file": source_file,
                "vulnerability_id": "HTTP-INTERNAL-IP-LEAK",
                "title": f"Internal IP Address Disclosure ({len(unique_ips)} addresses)",
                "severity": "medium",
                "cve": None,
                "cvss_score": 5.0,
                "affected_asset": host,
                "description": f"Internal IP addresses leaked in HTTP response: {', '.join(unique_ips[:5])}",
                "evidence": f"Leaked IPs: {', '.join(unique_ips[:5])}",
                "remediation": "Configure reverse proxy to strip internal IP addresses from responses.",
            })

    return findings


# ---------------------------------------------------------------------------
# SNMP parser
# ---------------------------------------------------------------------------
def parse_snmp_result(content: str, source_file: str) -> list[dict]:
    """Parse SNMP enumeration results."""
    findings = []
    host = _extract_host_from_filename(source_file)

    if content.strip():
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "SNMP-INFO-DISCLOSURE",
            "title": "SNMP Information Disclosure",
            "severity": "high",
            "cve": None,
            "cvss_score": 7.0,
            "affected_asset": host,
            "description": "SNMP service responded to queries, revealing system information and network configuration.",
            "evidence": content.strip()[:1000],
            "remediation": "Restrict SNMP access. Use SNMPv3 with authentication. Change default community strings. Firewall SNMP port.",
        })

    return findings


# ---------------------------------------------------------------------------
# Reconnaissance parsers (DNS, WHOIS, Shodan)
# ---------------------------------------------------------------------------
def parse_recon_file(content: str, source_file: str) -> list[dict]:
    """Parse reconnaissance output for informational findings."""
    findings = []
    filename_lower = source_file.lower()
    host = _extract_host_from_filename(source_file)

    if "shodan" in filename_lower and content.strip():
        # Extract interesting Shodan data
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "RECON-SHODAN-EXPOSURE",
            "title": "Internet-Facing Assets Identified via Shodan",
            "severity": "medium",
            "cve": None,
            "cvss_score": 4.0,
            "affected_asset": host or "Multiple",
            "description": "Shodan search results reveal internet-facing services and potential exposure.",
            "evidence": content.strip()[:1500],
            "remediation": "Review internet-facing services. Remove unnecessary public exposure. Implement WAF where applicable.",
        })

    if "whois" in filename_lower and content.strip():
        findings.append({
            "source_file": source_file,
            "vulnerability_id": "RECON-WHOIS-INFO",
            "title": "Domain/IP Registration Information Gathered",
            "severity": "low",
            "cve": None,
            "cvss_score": None,
            "affected_asset": host or "Multiple",
            "description": "WHOIS information reveals domain/IP registration details useful for reconnaissance.",
            "evidence": content.strip()[:1000],
            "remediation": "Consider WHOIS privacy protection where applicable.",
        })

    return findings


# ---------------------------------------------------------------------------
# Generic text evidence parser (catch-all)
# ---------------------------------------------------------------------------
def parse_generic_evidence(content: str, source_file: str) -> list[dict]:
    """Generic parser for unclassified evidence text files."""
    findings = []
    host = _extract_host_from_filename(source_file)

    if not content.strip() or len(content.strip()) < 10:
        return []

    # Look for any CVEs mentioned
    cves = _CVE_RE.findall(content)

    # Look for common vulnerability indicators
    content_lower = content.lower()
    indicators = []

    vuln_checks = [
        ("anonymous.*access", "critical", "Anonymous Access Detected"),
        ("authentication.*bypass", "critical", "Authentication Bypass"),
        ("sql.*inject", "critical", "SQL Injection Indicator"),
        ("default.*password|admin.*admin", "critical", "Default Credentials"),
        ("expired.*cert", "high", "Expired Certificate"),
        ("weak.*cipher|rc4|3des", "high", "Weak Cryptography"),
        ("trace.*enabled", "medium", "HTTP TRACE Enabled"),
        ("csrf", "high", "CSRF Vulnerability"),
        ("information.*disclos", "medium", "Information Disclosure"),
    ]

    for pattern, severity, title in vuln_checks:
        if re.search(pattern, content_lower):
            indicators.append((severity, title))

    if indicators:
        sev = indicators[0][0]  # Use most severe
        titles = [t for _, t in indicators]
        findings.append({
            "source_file": source_file,
            "vulnerability_id": cves[0] if cves else "EVIDENCE-" + re.sub(r"[^\w]", "", source_file[-30:]).upper(),
            "title": titles[0] if len(titles) == 1 else f"Multiple Issues: {', '.join(titles[:3])}",
            "severity": sev,
            "cve": cves[0] if cves else None,
            "cvss_score": None,
            "affected_asset": host,
            "description": f"Evidence file analysis detected: {', '.join(titles)}",
            "evidence": content.strip()[:1000],
            "remediation": "Review evidence and apply appropriate remediation.",
        })

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_host_from_filename(filename: str) -> str:
    """Try to extract an IP/hostname from a filename."""
    # Handle paths
    basename = filename.replace("\\", "/").split("/")[-1]

    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", basename)
    if ip_match:
        return ip_match.group(1)
    return "UNKNOWN"


def _extract_context(content: str, pattern: str, context_chars: int = 200) -> str:
    """Extract text around a pattern match."""
    m = re.search(pattern, content, re.IGNORECASE)
    if m:
        start = max(0, m.start() - context_chars // 2)
        end = min(len(content), m.end() + context_chars // 2)
        return content[start:end].strip()
    return content[:context_chars].strip()


# ---------------------------------------------------------------------------
# Master dispatcher
# ---------------------------------------------------------------------------
def parse_evidence_text(content: str, source_file: str) -> list[dict]:
    """Route a text file to the appropriate parser based on filename/content."""
    # Pre-process: strip ANSI codes, MSF prefixes, curl stats
    content = _clean_content(content)

    # Use only the basename for dispatch (avoid matching folder names like 'vulnerability_assessment')
    basename_lower = os.path.basename(source_file).lower()

    # Vulnerability assessment (nmap vuln scripts)
    if "nmap_vuln" in basename_lower or ("vuln" in basename_lower and "assessment" in basename_lower):
        return parse_vuln_assessment(content, source_file)

    # SSL/TLS analysis
    if "ssl" in basename_lower or "cipher" in basename_lower or "tls" in basename_lower:
        return parse_ssl_analysis(content, source_file)

    # HTTP headers
    if "header" in basename_lower:
        return parse_http_headers(content, source_file)

    # Port scans (nmap-style)
    if any(kw in basename_lower for kw in ["port_scan", "tcp_", "udp_", "scan", "discovery", "common_port"]):
        return parse_nmap_scan(content, source_file)

    # SMB/SSH/HTTP enumeration
    if any(kw in basename_lower for kw in ["smb_enum", "ssh_enum", "http_enum"]):
        return parse_nmap_scan(content, source_file)

    # Hydra brute force
    if "hydra" in basename_lower:
        return parse_hydra_result(content, source_file)

    # SNMP
    if "snmp" in basename_lower:
        return parse_snmp_result(content, source_file)

    # Banner / FTP / credential tests
    if any(kw in basename_lower for kw in ["banner", "anonymous", "admin", "nopass", "ftp"]):
        return parse_banner_or_test(content, source_file)

    # Recon files
    if any(kw in basename_lower for kw in ["shodan", "whois", "dns_", "theharvester", "wayback"]):
        return parse_recon_file(content, source_file)

    # Content-based fallback dispatch: if looks like nmap output, parse as nmap
    if "Nmap scan report for" in content or re.search(r"\d+/tcp\s+open", content):
        return parse_nmap_scan(content, source_file)

    # Generic fallback
    return parse_generic_evidence(content, source_file)
