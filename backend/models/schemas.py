"""Pydantic models shared across the ReportX backend."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Core vulnerability model
# ---------------------------------------------------------------------------
class Vulnerability(BaseModel):
    """Single parsed and whitened vulnerability record."""

    source_file: str = Field(..., description="Scan file the finding was extracted from")
    vulnerability_id: str = Field("UNKNOWN", description="Plugin / QID / scan-specific ID")
    title: str = Field("Untitled Vulnerability", description="Human-readable title")
    severity: str = Field(..., description="Normalized severity: high or critical")
    cve: str | None = Field(None, description="CVE identifier if available")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS v2/v3 score")
    affected_asset: str = Field("UNKNOWN_ASSET", description="Affected host / asset (may be redacted)")
    description: str = Field("No description provided", description="Finding description")
    evidence: str = Field("No evidence provided", description="Raw evidence or proof")
    remediation: str = Field("No remediation provided", description="Vendor / scanner remediation advice")


# ---------------------------------------------------------------------------
# Deterministic normalized payload persisted as JSON
# ---------------------------------------------------------------------------
class NormalizedPayload(BaseModel):
    """Wrapper written to the normalized JSON output file."""

    organization_context: str = Field(default="general", description="Sector context")
    total_findings: int = Field(0, description="Count of High+Critical findings")
    vulnerabilities: list[Vulnerability]


# ---------------------------------------------------------------------------
# LLM section outputs
# ---------------------------------------------------------------------------
class LLMSections(BaseModel):
    """Container for all LLM-generated Markdown sections."""

    executive_summary: str = Field(..., description="Business-friendly summary")
    technical_analysis: str = Field(..., description="Technical risk analysis")
    detailed_findings: str = Field(..., description="Per-finding details and remediation")


# ---------------------------------------------------------------------------
# API response models
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    """Returned by GET /health."""

    status: str = Field("ok", description="Service status")
    offline: bool = Field(True, description="Always True - no cloud calls")
    ollama_reachable: bool = Field(False, description="Whether Ollama responded to a ping")


class ReportResponse(BaseModel):
    """Returned by POST /reports/generate."""

    output_markdown_path: str = Field(..., description="Path where the .md file was saved")
    markdown: str = Field(..., description="Full Markdown report content")
    vulnerability_count: int = Field(..., ge=0, description="Number of High+Critical findings")


class ErrorDetail(BaseModel):
    """Standardized error body."""

    detail: str = Field(..., description="Human-readable error message")
