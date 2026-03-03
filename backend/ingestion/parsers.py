"""Scan-file parsers for JSON, XML, and CSV formats.

Each parser returns a flat list of dicts matching the Vulnerability schema.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET
from collections.abc import Iterable

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_text(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _to_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return None


def _iter_dict_candidates(data: object) -> Iterable[dict]:
    """Recursively yield every dict found in *data*."""
    if isinstance(data, dict):
        yield data
        for value in data.values():
            yield from _iter_dict_candidates(value)
    elif isinstance(data, list):
        for item in data:
            yield from _iter_dict_candidates(item)


def _normalize_candidate(candidate: dict, source_file: str) -> dict | None:
    """Try to map an arbitrary dict into a normalised finding."""
    severity = _safe_text(
        candidate.get("severity")
        or candidate.get("risk")
        or candidate.get("priority")
        or candidate.get("level")
        or candidate.get("risk_level")
    ).lower()
    if not severity:
        return None

    vulnerability_id = _safe_text(
        candidate.get("id")
        or candidate.get("plugin_id")
        or candidate.get("qid")
        or candidate.get("vuln_id")
        or candidate.get("finding_id"),
        default="UNKNOWN",
    )
    title = _safe_text(
        candidate.get("title")
        or candidate.get("name")
        or candidate.get("plugin_name")
        or candidate.get("vulnerability")
        or candidate.get("synopsis"),
        default="Untitled Vulnerability",
    )
    asset = _safe_text(
        candidate.get("host")
        or candidate.get("asset")
        or candidate.get("ip")
        or candidate.get("hostname")
        or candidate.get("target"),
        default="UNKNOWN_ASSET",
    )

    return {
        "source_file": source_file,
        "vulnerability_id": vulnerability_id,
        "title": title,
        "severity": severity,
        "cve": _safe_text(candidate.get("cve"), default="") or None,
        "cvss_score": _to_float(
            candidate.get("cvss")
            or candidate.get("cvss_score")
            or candidate.get("cvss3_score")
        ),
        "affected_asset": asset,
        "description": _safe_text(
            candidate.get("description") or candidate.get("synopsis"),
            default="No description provided",
        ),
        "evidence": _safe_text(
            candidate.get("evidence")
            or candidate.get("proof")
            or candidate.get("output"),
            default="No evidence provided",
        ),
        "remediation": _safe_text(
            candidate.get("solution")
            or candidate.get("remediation")
            or candidate.get("fix"),
            default="No remediation provided",
        ),
    }


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------
def parse_json_bytes(content: bytes, source_file: str) -> list[dict]:
    """Parse a JSON scan file and return a list of normalised findings."""
    try:
        payload = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        log.warning("Invalid JSON in %s – skipped", source_file)
        return []

    findings: list[dict] = []
    for candidate in _iter_dict_candidates(payload):
        normalized = _normalize_candidate(candidate, source_file)
        if normalized:
            findings.append(normalized)

    log.info("Parsed %d findings from JSON file %s", len(findings), source_file)
    return findings


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------
def _xml_element_to_dict(node: ET.Element) -> dict:
    """Flatten an XML element into a dict of tag → text (one level)."""
    out: dict = {k.lower(): v for k, v in node.attrib.items()}
    for child in list(node):
        key = child.tag.split("}")[-1].lower()
        text = (child.text or "").strip()
        if list(child):
            out[key] = _xml_element_to_dict(child)
        else:
            out[key] = text
    return out


def parse_xml_bytes(content: bytes, source_file: str) -> list[dict]:
    """Parse an XML scan file and return a list of normalised findings."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        log.warning("Invalid XML in %s – skipped", source_file)
        return []

    findings: list[dict] = []
    for node in root.iter():
        candidate = _xml_element_to_dict(node)
        normalized = _normalize_candidate(candidate, source_file)
        if normalized:
            findings.append(normalized)

    log.info("Parsed %d findings from XML file %s", len(findings), source_file)
    return findings


# ---------------------------------------------------------------------------
# CSV parser (new)
# ---------------------------------------------------------------------------
def parse_csv_bytes(content: bytes, source_file: str) -> list[dict]:
    """Parse a CSV scan export and return a list of normalised findings."""
    try:
        text = content.decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(text))
    except Exception:
        log.warning("Failed to read CSV %s – skipped", source_file)
        return []

    findings: list[dict] = []
    for row in reader:
        # Lowercase all keys for uniform lookup
        lowered = {k.lower().strip(): v for k, v in row.items() if k}
        normalized = _normalize_candidate(lowered, source_file)
        if normalized:
            findings.append(normalized)

    log.info("Parsed %d findings from CSV file %s", len(findings), source_file)
    return findings
