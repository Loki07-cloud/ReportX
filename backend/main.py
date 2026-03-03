"""ReportX Backend – FastAPI application entry point."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import (
    MODEL_GEMMA_EXEC,
    MODEL_LLAMA_TECH,
    OLLAMA_BASE_URL,
    setup_logging,
)
from llm.ollama_client import ping_ollama
from models.schemas import ErrorDetail, HealthResponse, ReportResponse
from pipeline.state import get_pipeline, get_reports
from service.report_service import generate_report_from_zip, generate_report_from_folder

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
setup_logging()
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ReportX Backend",
    version="1.0.0",
    description=(
        "Fully offline AI-powered audit report generator. "
        "Ingests scan ZIP files, filters High/Critical vulnerabilities, "
        "whitens sensitive data, runs local LLM analysis via Ollama, "
        "and exports Markdown reports."
    ),
    contact={"name": "ReportX Team"},
    license_info={"name": "MIT"},
    openapi_tags=[
        {
            "name": "Health",
            "description": "Service health checks",
        },
        {
            "name": "Reports",
            "description": "Generate audit reports from scan ZIP files",
        },
        {
            "name": "Pipeline",
            "description": "Pipeline state and intermediate results",
        },
        {
            "name": "Intelligence",
            "description": "ML risk scores, alerts, and recommendations",
        },
        {
            "name": "Models",
            "description": "LLM model information",
        },
    ],
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Allow local frontends (e.g. React dev server) to reach the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Startup event
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def _startup() -> None:
    log.info("ReportX Backend starting…")
    if ping_ollama():
        log.info("Ollama is reachable at http://localhost:11434")
    else:
        log.warning(
            "Ollama is NOT reachable – report generation will fail until it is started"
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
    description="Returns service health status, offline confirmation, and Ollama reachability.",
)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        offline=True,
        ollama_reachable=ping_ollama(),
    )


@app.post(
    "/reports/generate",
    response_model=ReportResponse,
    tags=["Reports"],
    summary="Generate audit report",
    description=(
        "Upload a ZIP file containing XML/JSON/CSV scan outputs and an optional "
        "organization context (e.g. 'banking', 'healthcare'). The service "
        "filters High/Critical vulnerabilities, whitens sensitive data, "
        "runs local LLM analysis, and returns a Markdown report."
    ),
    responses={
        200: {"description": "Report generated successfully"},
        400: {"description": "Invalid input (non-ZIP file)", "model": ErrorDetail},
        500: {"description": "Internal error during report generation", "model": ErrorDetail},
    },
)
async def generate_report(
    scan_zip: UploadFile = File(..., description="ZIP containing XML/JSON/CSV scan files"),
    organization_context: str = Form("general", description="Organization context, e.g. 'banking', 'healthcare'"),
) -> ReportResponse:
    if not scan_zip.filename or not scan_zip.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP uploads are supported")

    try:
        zip_bytes = await scan_zip.read()
        output_path, markdown, count = generate_report_from_zip(
            zip_bytes, organization_context
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("Report generation failed")
        raise HTTPException(
            status_code=500, detail=f"Failed to generate report: {exc}"
        ) from exc

    return ReportResponse(
        output_markdown_path=output_path,
        markdown=markdown,
        vulnerability_count=count,
    )


# ---------------------------------------------------------------------------
# Pipeline state endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/pipeline/status",
    tags=["Pipeline"],
    summary="Get pipeline status",
    description="Returns the current pipeline progress including step statuses, timings, and counts.",
)
def pipeline_status() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {
            "steps": [
                {"name": "Ingestion", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
                {"name": "Parsing & ETL", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
                {"name": "Data Whitening", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
                {"name": "AI Analysis", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
                {"name": "Validation", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
                {"name": "Report", "status": "pending", "started_at": None, "completed_at": None, "duration_seconds": None, "detail": ""},
            ],
            "overall_progress": 0,
            "current_step": "Ingestion",
            "organization_context": "",
            "started_at": "",
            "finding_count": 0,
            "raw_finding_count": 0,
            "file_count": 0,
        }
    return pipeline.to_status_dict()


@app.get(
    "/pipeline/ingestion",
    tags=["Pipeline"],
    summary="Get ingestion results",
    description="Returns parsed findings from the most recent pipeline run.",
)
def pipeline_ingestion() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {"file_count": 0, "zip_size_bytes": 0, "raw_finding_count": 0, "filtered_finding_count": 0, "findings": []}
    return pipeline.to_ingestion_dict()


@app.get(
    "/pipeline/whitening",
    tags=["Pipeline"],
    summary="Get whitening results",
    description="Returns data whitening examples and sanitization statistics.",
)
def pipeline_whitening() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {"examples": [], "sanitization_rules": [], "whitened_count": 0}
    return pipeline.to_whitening_dict()


@app.get(
    "/pipeline/analysis",
    tags=["Pipeline"],
    summary="Get AI analysis results",
    description="Returns LLM-generated analysis sections, timeline, and model usage.",
)
def pipeline_analysis() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {
            "executive_summary": "",
            "technical_analysis": "",
            "detailed_findings": "",
            "timeline": [],
            "model_usage": [],
        }
    return pipeline.to_analysis_dict()


@app.get(
    "/pipeline/validation",
    tags=["Pipeline"],
    summary="Get validation results",
    description="Returns the validation checklist and finding count.",
)
def pipeline_validation() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {"checklist": [], "finding_count": 0}
    return pipeline.to_validation_dict()


# ---------------------------------------------------------------------------
# Intelligence endpoints (ML/NLP)
# ---------------------------------------------------------------------------

@app.get(
    "/pipeline/alerts",
    tags=["Intelligence"],
    summary="Get security alerts",
    description="Returns ML-generated security alerts sorted by severity.",
)
def pipeline_alerts() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {"alerts": [], "total": 0, "critical": 0, "high": 0, "medium": 0}
    return pipeline.to_alerts_dict()


@app.get(
    "/pipeline/risk-scores",
    tags=["Intelligence"],
    summary="Get risk scores",
    description="Returns ML risk scores, host profiles, attack chains, and compliance gaps.",
)
def pipeline_risk_scores() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {
            "overall_score": 0,
            "risk_level": "unknown",
            "host_profiles": [],
            "attack_chains": [],
            "compliance_gaps": [],
            "finding_categories": {},
        }
    return pipeline.to_risk_dict()


@app.get(
    "/pipeline/recommendations",
    tags=["Intelligence"],
    summary="Get remediation recommendations",
    description="Returns prioritized remediation recommendations.",
)
def pipeline_recommendations() -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        return {"recommendations": [], "total": 0}
    return pipeline.to_recommendations_dict()


class FolderRequest(BaseModel):
    folder_path: str
    organization_context: str = "general"


@app.post(
    "/reports/generate-from-folder",
    response_model=ReportResponse,
    tags=["Reports"],
    summary="Generate report from evidence folder",
    description="Process evidence files directly from a folder path on disk.",
)
def generate_from_folder(req: FolderRequest) -> ReportResponse:
    folder = Path(req.folder_path)
    if not folder.exists():
        raise HTTPException(status_code=400, detail=f"Folder not found: {req.folder_path}")
    try:
        output_path, markdown, count = generate_report_from_folder(
            req.folder_path, req.organization_context
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("Report generation from folder failed")
        raise HTTPException(status_code=500, detail=f"Failed: {exc}") from exc
    return ReportResponse(
        output_markdown_path=output_path,
        markdown=markdown,
        vulnerability_count=count,
    )


# ---------------------------------------------------------------------------
# Reports listing
# ---------------------------------------------------------------------------


@app.get(
    "/reports",
    tags=["Reports"],
    summary="List generated reports",
    description="Returns all previously generated reports (newest first).",
)
def list_reports() -> list[dict[str, Any]]:
    return get_reports()


# ---------------------------------------------------------------------------
# Model information
# ---------------------------------------------------------------------------


@app.get(
    "/models",
    tags=["Models"],
    summary="Get LLM model information",
    description="Returns info about the configured LLM models and their availability.",
)
def model_info() -> dict[str, Any]:
    ollama_up = ping_ollama()
    return {
        "ollama_reachable": ollama_up,
        "ollama_url": OLLAMA_BASE_URL,
        "models": [
            {
                "name": "LLaMA 3",
                "model_tag": MODEL_LLAMA_TECH,
                "purpose": "Technical Risk Analysis & Detailed Findings",
                "parameters": "8B",
                "context_window": "128K",
                "quantization": "Q4_K_M",
            },
            {
                "name": "Gemma 2",
                "model_tag": MODEL_GEMMA_EXEC,
                "purpose": "Executive Summary & Remediation",
                "parameters": "2B",
                "context_window": "8K",
                "quantization": "Q4_K_M",
            },
        ],
    }
