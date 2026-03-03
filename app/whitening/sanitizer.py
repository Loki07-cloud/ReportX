"""Data-whitening / sanitization module.

Removes or masks sensitive fields (IPs, hostnames, URLs, emails, MACs,
UUIDs, client identifiers) from parsed scan data so that reports never
leak private infrastructure details.
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for sensitive values embedded in free text
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # IPv4
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    # IPv6 (simplified)
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), "[REDACTED_IP]"),
    # URLs
    (re.compile(r"https?://[^\s\]\)'\"]+", re.IGNORECASE), "[REDACTED_URL]"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # MAC addresses
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "[REDACTED_MAC]"),
    # UUIDs
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "[REDACTED_UUID]"),
    # Client / tenant / account identifiers
    (re.compile(
        r"\b(?:client|customer|tenant|account)[-_]?(?:id|number)?[:=]?\s*[a-zA-Z0-9_-]{4,}\b",
        re.IGNORECASE,
    ), "[REDACTED_CLIENT_ID]"),
    # Hostnames (FQDN-like strings) – keep last to avoid masking partial matches
    (re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"), "[REDACTED_HOST]"),
]

# Keys whose *values* should be replaced entirely
_SENSITIVE_KEYS: set[str] = {
    "ip",
    "ip_address",
    "hostname",
    "host",
    "url",
    "uri",
    "fqdn",
    "target",
    "client",
    "client_id",
    "tenant_id",
    "customer_id",
    "account_id",
    "email",
    "mac",
    "mac_address",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def whiten_text(value: str) -> str:
    """Apply all regex patterns to a single string, masking sensitive tokens."""
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def whiten_data(payload: object) -> object:
    """Recursively traverse *payload* and sanitise sensitive keys / values."""
    if isinstance(payload, dict):
        out: dict = {}
        for key, value in payload.items():
            key_lower = str(key).lower().strip()
            if key_lower in _SENSITIVE_KEYS:
                out[key] = "[REDACTED]"
            else:
                out[key] = whiten_data(value)
        return out

    if isinstance(payload, list):
        return [whiten_data(item) for item in payload]

    if isinstance(payload, str):
        return whiten_text(value=payload)

    return payload
