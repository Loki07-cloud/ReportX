"""Orchestrates the full report-generation pipeline with state tracking.

1. Extract findings from ZIP
2. Whiten sensitive data
3. Normalize & filter (High + Critical only, deduplicated)
4. Call Ollama for each LLM section
5. Build Markdown report
6. Persist outputs to disk

Each step updates the pipeline state so the frontend can poll progress.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from app.analysis.normalizer import normalize_and_filter
from app.config import OUTPUT_DIR
from app.ingestion.zip_handler import extract_findings_from_zip
from app.llm.ollama_client import call_ollama
from app.llm.router import (
    TASK_DETAILED_FINDINGS,
    TASK_EXECUTIVE_SUMMARY,
    TASK_TECHNICAL_ANALYSIS,
    select_model,
)
from app.pipeline.state import (
    ModelUsage,
    TimelineEvent,
    add_report,
    create_pipeline,
)
from app.prompts.templates import (
    gemma_executive_prompt,
    llama_detailed_findings_prompt,
    llama_technical_analysis_prompt,
)
from app.report.markdown_builder import build_report_markdown
from app.whitening.sanitizer import whiten_data

log = logging.getLogger(__name__)


def generate_report_from_zip(
    zip_bytes: bytes,
    organization_context: str,
) -> tuple[str, str, int]:
    """Run the full pipeline and return ``(md_path, markdown, vuln_count)``.

    Also updates the shared pipeline state at each step.
    """
    t_start = time.perf_counter()

    # Create tracked pipeline state
    pipeline = create_pipeline(organization_context)
    pipeline.zip_size_bytes = len(zip_bytes)

    # --- 1. Ingestion ---------------------------------------------------------
    step = pipeline.steps[0]  # Ingestion
    step.start(f"Extracting findings from ZIP ({len(zip_bytes)} bytes)")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Data ingestion started",
            detail=f"Processing ZIP file ({len(zip_bytes):,} bytes)",
            status="active",
        )
    )

    log.info("[1/6] Extracting findings from ZIP (%d bytes)", len(zip_bytes))
    raw_findings = extract_findings_from_zip(zip_bytes)
    pipeline.raw_findings = raw_findings
    pipeline.file_count = len(set(f.get("source_file", "") for f in raw_findings))
    step.complete(f"Extracted {len(raw_findings)} raw findings from {pipeline.file_count} files")

    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = (
        f"Extracted {len(raw_findings)} raw findings from {pipeline.file_count} files"
    )

    # --- 2. Parsing & ETL -----------------------------------------------------
    step = pipeline.steps[1]  # Parsing & ETL
    step.start(f"Parsing {len(raw_findings)} raw findings")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Evidence parsing started",
            detail=f"Processing {len(raw_findings)} raw findings",
            status="active",
        )
    )
    step.complete(f"Parsed {len(raw_findings)} findings from {pipeline.file_count} scan files")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 3. Whitening ---------------------------------------------------------
    step = pipeline.steps[2]  # Data Whitening
    step.start(f"Whitening {len(raw_findings)} raw findings")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Data whitening",
            detail=f"Sanitizing {len(raw_findings)} findings",
            status="active",
        )
    )

    log.info("[2/6] Whitening %d raw finding(s)", len(raw_findings))
    whitened = whiten_data(raw_findings)
    pipeline.whitened_findings = whitened if isinstance(whitened, list) else []

    # Compute whitening stats from raw text
    raw_text = json.dumps(raw_findings)
    pipeline.compute_sanitization_stats(raw_text)
    pipeline.compute_whitening_examples(raw_findings)

    step.complete(f"Whitened {len(pipeline.whitened_findings)} findings")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 3b. Normalize & filter -----------------------------------------------
    log.info("[3/6] Normalising & filtering (High + Critical only)")
    filtered = normalize_and_filter(pipeline.whitened_findings)
    pipeline.filtered_findings = filtered
    log.info("Retained %d finding(s) after filtering", len(filtered))

    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Vulnerability correlation",
            detail=f"Filtered to {len(filtered)} High/Critical findings (from {len(raw_findings)} raw)",
            status="done",
        )
    )

    if not filtered:
        log.warning("No High/Critical findings found – generating empty report")

    # --- 4. LLM calls --------------------------------------------------------
    step = pipeline.steps[3]  # AI Analysis
    step.start(f"Running LLM analysis on {len(filtered)} findings")

    log.info("[4/6] Running LLM analysis via Ollama")

    executive_model = select_model(TASK_EXECUTIVE_SUMMARY)
    technical_model = select_model(TASK_TECHNICAL_ANALYSIS)
    details_model = select_model(TASK_DETAILED_FINDINGS)

    # Track model usage
    exec_usage = ModelUsage(model=executive_model, task="Executive Summary", status="processing")
    tech_usage = ModelUsage(model=technical_model, task="Technical Analysis", status="pending")
    detail_usage = ModelUsage(model=details_model, task="Detailed Findings", status="pending")
    pipeline.model_usage = [exec_usage, tech_usage, detail_usage]

    # Executive summary
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{executive_model} — Executive Summary",
            detail=f"Generating executive summary from {len(filtered)} findings",
            status="active",
        )
    )
    t0 = time.perf_counter()
    exec_prompt = gemma_executive_prompt(filtered, organization_context)
    executive_summary = call_ollama(executive_model, exec_prompt)
    exec_duration = time.perf_counter() - t0
    exec_usage.status = "completed"
    exec_usage.duration_seconds = round(exec_duration, 1)
    exec_usage.input_tokens = len(exec_prompt.split())
    exec_usage.output_tokens = len(executive_summary.split())
    pipeline.executive_summary = executive_summary
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {exec_duration:.1f}s"

    # Technical analysis
    tech_usage.status = "processing"
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{technical_model} — Technical Analysis",
            detail="Analyzing attack surface and risk patterns",
            status="active",
        )
    )
    t0 = time.perf_counter()
    tech_prompt = llama_technical_analysis_prompt(filtered, organization_context)
    technical_analysis = call_ollama(technical_model, tech_prompt)
    tech_duration = time.perf_counter() - t0
    tech_usage.status = "completed"
    tech_usage.duration_seconds = round(tech_duration, 1)
    tech_usage.input_tokens = len(tech_prompt.split())
    tech_usage.output_tokens = len(technical_analysis.split())
    pipeline.technical_analysis = technical_analysis
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {tech_duration:.1f}s"

    # Detailed findings
    detail_usage.status = "processing"
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{details_model} — Detailed Findings",
            detail=f"Generating per-finding analysis for {len(filtered)} vulnerabilities",
            status="active",
        )
    )
    t0 = time.perf_counter()
    detail_prompt = llama_detailed_findings_prompt(filtered, organization_context)
    detailed_findings = call_ollama(details_model, detail_prompt)
    detail_duration = time.perf_counter() - t0
    detail_usage.status = "completed"
    detail_usage.duration_seconds = round(detail_duration, 1)
    detail_usage.input_tokens = len(detail_prompt.split())
    detail_usage.output_tokens = len(detailed_findings.split())
    pipeline.detailed_findings_text = detailed_findings
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {detail_duration:.1f}s"

    step.complete("All 3 LLM tasks completed")

    # --- 5. Validation --------------------------------------------------------
    step = pipeline.steps[4]  # Validation
    step.start("Running validation checks")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Cross-validation pass",
            detail="Validating findings against evidence and AI outputs",
            status="active",
        )
    )

    pipeline.compute_validation()

    passed = sum(1 for c in pipeline.validation_checklist if c["passed"])
    total = len(pipeline.validation_checklist)
    step.complete(f"Validation complete — {passed}/{total} checks passed")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 6. Build & persist report --------------------------------------------
    step = pipeline.steps[5]  # Report
    step.start("Building Markdown report")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Report generation",
            detail="Assembling final Markdown report",
            status="active",
        )
    )

    log.info("[5/6] Building Markdown report")
    markdown = build_report_markdown(
        org_context=organization_context,
        vulnerabilities=filtered,
        executive_summary=executive_summary,
        technical_analysis=technical_analysis,
        detailed_findings=detailed_findings,
    )

    log.info("[6/6] Saving output files")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    md_path = OUTPUT_DIR / f"reportx_{timestamp}.md"
    json_path = OUTPUT_DIR / f"reportx_{timestamp}_normalized.json"

    md_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "organization_context": organization_context,
                "total_findings": len(filtered),
                "vulnerabilities": filtered,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    pipeline.report_markdown = markdown
    pipeline.report_path = str(md_path)

    step.complete(f"Report saved to {md_path.name}")
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Report saved: {md_path.name}"

    # Store as generated report
    elapsed = time.perf_counter() - t_start
    add_report({
        "name": f"ReportX — {organization_context.title()} Assessment",
        "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "status": "Completed",
        "vulnerability_count": len(filtered),
        "output_path": str(md_path),
        "duration_seconds": round(elapsed, 1),
    })

    log.info(
        "Pipeline complete in %.1fs – %d finding(s), output: %s",
        elapsed,
        len(filtered),
        md_path,
    )
    return str(md_path), markdown, len(filtered)
