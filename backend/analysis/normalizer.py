"""Normalize, filter, and deduplicate vulnerability findings.

Only High and Critical severities are kept.  Duplicate findings
(same vulnerability_id + affected_asset) are collapsed, and the
result is sorted by severity then title.
"""

from __future__ import annotations

import logging

from config import ALLOWED_SEVERITIES, SEVERITY_ALIASES

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1}


def _resolve_severity(raw: str) -> str | None:
    """Map a raw severity string to 'high' or 'critical', or return None."""
    lowered = raw.strip().lower()
    # Direct match
    if lowered in ALLOWED_SEVERITIES:
        return lowered
    # Alias lookup (e.g. "4" -> "high", "severe" -> "critical")
    return SEVERITY_ALIASES.get(lowered)


def normalize_and_filter(findings: list[dict]) -> list[dict]:
    """Return a deduplicated, severity-filtered, sorted list of findings."""
    seen: set[tuple[str, str]] = set()
    kept: list[dict] = []

    for finding in findings:
        severity = _resolve_severity(str(finding.get("severity", "")))
        if severity is None:
            continue

        # Deduplication key: (vulnerability_id, affected_asset)
        dedup_key = (
            str(finding.get("vulnerability_id", "UNKNOWN")),
            str(finding.get("affected_asset", "UNKNOWN_ASSET")),
        )
        if dedup_key in seen:
            log.debug("Duplicate finding skipped: %s on %s", *dedup_key)
            continue
        seen.add(dedup_key)

        finding["severity"] = severity
        kept.append(finding)

    kept.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(item.get("severity", "high"), 9),
            str(item.get("title", "")),
            str(item.get("vulnerability_id", "")),
            str(item.get("affected_asset", "")),
        )
    )

    log.info(
        "Normalization complete – %d finding(s) kept out of %d (deduplicated %d)",
        len(kept),
        len(findings),
        len(findings) - len(kept),
    )
    return kept
