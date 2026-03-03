"""In-memory pipeline state management.

Tracks the progress of each pipeline step, stores intermediate results,
and provides query methods for the API endpoints.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline step tracking
# ---------------------------------------------------------------------------

@dataclass
class PipelineStep:
    """Represents a single step in the processing pipeline."""
    name: str
    status: str = "pending"          # pending | processing | completed | failed
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    detail: str = ""
    _start_time: float = field(default=0.0, repr=False)

    def start(self, detail: str = "") -> None:
        self.status = "processing"
        self.started_at = datetime.utcnow().strftime("%H:%M:%S")
        self._start_time = time.perf_counter()
        if detail:
            self.detail = detail

    def complete(self, detail: str = "") -> None:
        self.status = "completed"
        self.completed_at = datetime.utcnow().strftime("%H:%M:%S")
        if self._start_time:
            self.duration_seconds = round(time.perf_counter() - self._start_time, 1)
        if detail:
            self.detail = detail

    def fail(self, detail: str = "") -> None:
        self.status = "failed"
        self.completed_at = datetime.utcnow().strftime("%H:%M:%S")
        if self._start_time:
            self.duration_seconds = round(time.perf_counter() - self._start_time, 1)
        if detail:
            self.detail = detail

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Analysis timeline event
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    time: str
    event: str
    detail: str
    status: str  # done | active | pending

    def to_dict(self) -> dict:
        return {"time": self.time, "event": self.event, "detail": self.detail, "status": self.status}


# ---------------------------------------------------------------------------
# Model usage tracking
# ---------------------------------------------------------------------------

@dataclass
class ModelUsage:
    model: str
    task: str
    input_tokens: int = 0
    output_tokens: int = 0
    duration_seconds: float = 0.0
    status: str = "pending"  # pending | processing | completed | failed

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "task": self.task,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Whitening tracking
# ---------------------------------------------------------------------------

# Known sensitive patterns with category labels
WHITENING_RULES = [
    {
        "id": "ip",
        "label": "IP Address Masking",
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "replacement": "[REDACTED_IP]",
        "category": "Network",
    },
    {
        "id": "domain",
        "label": "Domain / Hostname Masking",
        "pattern": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "replacement": "[REDACTED_HOST]",
        "category": "Identity",
    },
    {
        "id": "email",
        "label": "Email Address Removal",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "replacement": "[REDACTED_EMAIL]",
        "category": "PII",
    },
    {
        "id": "url",
        "label": "URL Sanitization",
        "pattern": r"https?://[^\s\]\)'\"]+",
        "replacement": "[REDACTED_URL]",
        "category": "Network",
    },
    {
        "id": "mac",
        "label": "MAC Address Masking",
        "pattern": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        "replacement": "[REDACTED_MAC]",
        "category": "Network",
    },
    {
        "id": "cert",
        "label": "Certificate & Device Identity",
        "pattern": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "replacement": "[REDACTED_UUID]",
        "category": "Identity",
    },
]


def _count_pattern_matches(text: str, pattern: str) -> int:
    """Count matches of a regex pattern in text."""
    try:
        return len(re.findall(pattern, text, re.IGNORECASE))
    except re.error:
        return 0


# ---------------------------------------------------------------------------
# Full pipeline state
# ---------------------------------------------------------------------------

@dataclass
class PipelineState:
    """Holds all state for the current pipeline run."""

    steps: list[PipelineStep] = field(default_factory=lambda: [
        PipelineStep("Ingestion"),
        PipelineStep("Parsing & ETL"),
        PipelineStep("Data Whitening"),
        PipelineStep("AI Analysis"),
        PipelineStep("Validation"),
        PipelineStep("Report"),
    ])

    # Ingestion results
    raw_findings: list[dict] = field(default_factory=list)
    file_count: int = 0
    zip_size_bytes: int = 0

    # Whitening results
    whitened_findings: list[dict] = field(default_factory=list)
    whitening_examples: list[dict] = field(default_factory=list)
    sanitization_stats: list[dict] = field(default_factory=list)

    # Filtered/normalized findings
    filtered_findings: list[dict] = field(default_factory=list)

    # AI Analysis results
    executive_summary: str = ""
    technical_analysis: str = ""
    detailed_findings_text: str = ""
    analysis_timeline: list[TimelineEvent] = field(default_factory=list)
    model_usage: list[ModelUsage] = field(default_factory=list)

    # Validation
    validation_checklist: list[dict] = field(default_factory=list)

    # Report
    report_markdown: str = ""
    report_path: str = ""

    # Metadata
    organization_context: str = "general"
    started_at: str = ""

    def overall_progress(self) -> int:
        completed = sum(1 for s in self.steps if s.status == "completed")
        processing = sum(1 for s in self.steps if s.status == "processing")
        total = len(self.steps)
        if total == 0:
            return 0
        return int((completed * 100 + processing * 50) / total)

    def current_step_name(self) -> str:
        for s in self.steps:
            if s.status == "processing":
                return s.name
        for s in self.steps:
            if s.status == "pending":
                return s.name
        return "Complete"

    def compute_sanitization_stats(self, raw_text: str) -> None:
        """Count how many times each whitening rule matched in the raw data."""
        self.sanitization_stats = []
        for rule in WHITENING_RULES:
            count = _count_pattern_matches(raw_text, rule["pattern"])
            self.sanitization_stats.append({
                "id": rule["id"],
                "label": rule["label"],
                "pattern": rule["pattern"],
                "replacement": rule["replacement"],
                "category": rule["category"],
                "count": count,
            })

    def compute_whitening_examples(self, raw_findings: list[dict]) -> None:
        """Extract real before/after whitening examples from findings."""
        examples: list[dict] = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        host_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

        seen_types: set[str] = set()
        for finding in raw_findings[:20]:  # limit scan
            text = str(finding)
            if "IP Address" not in seen_types:
                ips = ip_pattern.findall(text)
                if ips:
                    examples.append({"field": "IP Address", "original": ips[0], "whitened": "[REDACTED_IP]"})
                    seen_types.add("IP Address")
            if "Hostname" not in seen_types:
                hosts = host_pattern.findall(text)
                for h in hosts:
                    if not ip_pattern.match(h) and len(h) > 5:
                        examples.append({"field": "Hostname / FQDN", "original": h, "whitened": "[REDACTED_HOST]"})
                        seen_types.add("Hostname")
                        break
            if len(seen_types) >= 4:
                break

        self.whitening_examples = examples

    def compute_validation(self) -> None:
        """Run validation checks on filtered findings."""
        findings = self.filtered_findings
        checklist: list[dict] = []

        # Check 1: All findings have evidence
        all_have_evidence = all(
            bool(f.get("evidence") and f["evidence"] != "No evidence provided")
            for f in findings
        ) if findings else False
        checklist.append({
            "label": "All vulnerability findings traced to evidence files",
            "passed": all_have_evidence,
        })

        # Check 2: CVE references present
        cve_count = sum(1 for f in findings if f.get("cve"))
        checklist.append({
            "label": f"CVE references present ({cve_count}/{len(findings)} findings)",
            "passed": cve_count > 0,
        })

        # Check 3: Severity ratings valid
        valid_severities = {"critical", "high"}
        all_valid = all(
            f.get("severity", "").lower() in valid_severities
            for f in findings
        ) if findings else False
        checklist.append({
            "label": "Severity ratings aligned with High/Critical filtering",
            "passed": all_valid,
        })

        # Check 4: No external data references in AI output
        ai_output = self.executive_summary + self.technical_analysis + self.detailed_findings_text
        no_external = not bool(re.search(r"according to|external report|industry benchmark", ai_output, re.IGNORECASE))
        checklist.append({
            "label": "No external data references in AI output",
            "passed": no_external if ai_output else False,
        })

        # Check 5: Asset fields populated
        all_assets = all(
            f.get("affected_asset") and f["affected_asset"] != "UNKNOWN_ASSET"
            for f in findings
        ) if findings else False
        checklist.append({
            "label": "All findings have identified affected assets",
            "passed": all_assets,
        })

        # Check 6: Remediation provided
        all_remediation = all(
            f.get("remediation") and f["remediation"] != "No remediation provided"
            for f in findings
        ) if findings else False
        checklist.append({
            "label": "Remediation steps provided for all findings",
            "passed": all_remediation,
        })

        # Check 7: Executive summary generated
        checklist.append({
            "label": "Executive summary generated by AI",
            "passed": bool(self.executive_summary.strip()),
        })

        # Check 8: Technical analysis generated
        checklist.append({
            "label": "Technical analysis generated by AI",
            "passed": bool(self.technical_analysis.strip()),
        })

        self.validation_checklist = checklist

    def to_status_dict(self) -> dict:
        """Return full pipeline status as a serializable dict."""
        return {
            "steps": [s.to_dict() for s in self.steps],
            "overall_progress": self.overall_progress(),
            "current_step": self.current_step_name(),
            "organization_context": self.organization_context,
            "started_at": self.started_at,
            "finding_count": len(self.filtered_findings),
            "raw_finding_count": len(self.raw_findings),
            "file_count": self.file_count,
        }

    def to_ingestion_dict(self) -> dict:
        return {
            "file_count": self.file_count,
            "zip_size_bytes": self.zip_size_bytes,
            "raw_finding_count": len(self.raw_findings),
            "filtered_finding_count": len(self.filtered_findings),
            "findings": self.filtered_findings,
        }

    def to_whitening_dict(self) -> dict:
        return {
            "examples": self.whitening_examples,
            "sanitization_rules": self.sanitization_stats,
            "whitened_count": len(self.whitened_findings),
        }

    def to_analysis_dict(self) -> dict:
        return {
            "executive_summary": self.executive_summary,
            "technical_analysis": self.technical_analysis,
            "detailed_findings": self.detailed_findings_text,
            "timeline": [e.to_dict() for e in self.analysis_timeline],
            "model_usage": [m.to_dict() for m in self.model_usage],
        }

    def to_validation_dict(self) -> dict:
        return {
            "checklist": self.validation_checklist,
            "finding_count": len(self.filtered_findings),
        }


# ---------------------------------------------------------------------------
# Singleton state + generated reports store
# ---------------------------------------------------------------------------

_current_pipeline: PipelineState | None = None
_generated_reports: list[dict] = []


def get_pipeline() -> PipelineState | None:
    """Get the current pipeline state, if any."""
    return _current_pipeline


def create_pipeline(org_context: str = "general") -> PipelineState:
    """Create a fresh pipeline state."""
    global _current_pipeline
    _current_pipeline = PipelineState(
        organization_context=org_context,
        started_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    return _current_pipeline


def add_report(report: dict) -> None:
    """Store a completed report."""
    _generated_reports.append(report)


def get_reports() -> list[dict]:
    """Return all generated reports, newest first."""
    return list(reversed(_generated_reports))
