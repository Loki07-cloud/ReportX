"""Orchestrates the full report-generation pipeline with state tracking.

1. Extract findings from ZIP (or folder)
2. Whiten sensitive data
3. Normalize & filter (High + Critical only, deduplicated)
4. Run ML/NLP analysis (risk scoring, NLP evidence analysis, alerts)
5. Call Ollama for each LLM section (with enriched context)
6. Build Markdown report
7. Persist outputs to disk

Each step updates the pipeline state so the frontend can poll progress.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from analysis.normalizer import normalize_and_filter
from analysis.risk_scorer import compute_risk_scores
from analysis.nlp_analyzer import run_nlp_analysis, _build_context_summary
from analysis.alert_engine import generate_alerts, generate_recommendations
from config import OUTPUT_DIR
from ingestion.zip_handler import extract_findings_from_zip, extract_findings_from_folder
from llm.ollama_client import call_ollama
from llm.router import (
    TASK_DETAILED_FINDINGS,
    TASK_EXECUTIVE_SUMMARY,
    TASK_TECHNICAL_ANALYSIS,
    select_model,
)
from pipeline.state import (
    ModelUsage,
    TimelineEvent,
    add_report,
    create_pipeline,
)
from prompts.templates import (
    gemma_executive_prompt,
    llama_detailed_findings_prompt,
    llama_technical_analysis_prompt,
)
from report.markdown_builder import build_report_markdown
from whitening.sanitizer import whiten_data

log = logging.getLogger(__name__)


def _run_ml_pipeline(pipeline, filtered: list[dict], raw_evidence_text: str = "") -> tuple[dict, dict]:
    """Run ML/NLP analysis and update pipeline state. Returns (risk_dict, nlp_dict)."""
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="ML Risk Scoring",
            detail="Computing multi-factor risk scores and attack chains",
            status="active",
        )
    )

    # Risk scoring
    t0 = time.perf_counter()
    risk_result = compute_risk_scores(filtered)
    risk_dict = risk_result.to_dict()
    pipeline.risk_scores = risk_dict
    risk_duration = time.perf_counter() - t0

    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = (
        f"Risk score: {risk_dict['overall_score']}/100 ({risk_dict['risk_level']}) "
        f"| {len(risk_dict.get('attack_chains', []))} attack chains | "
        f"{len(risk_dict.get('compliance_gaps', []))} compliance gaps "
        f"[{risk_duration:.1f}s]"
    )

    # NLP analysis
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="NLP Evidence Analysis",
            detail="Extracting CVEs, keywords, threat indicators from evidence text",
            status="active",
        )
    )

    t0 = time.perf_counter()
    nlp_result = run_nlp_analysis(filtered, raw_evidence_text)
    nlp_dict = nlp_result.to_dict()
    pipeline.nlp_analysis = nlp_dict
    nlp_duration = time.perf_counter() - t0

    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = (
        f"{len(nlp_dict.get('cves_found', []))} CVEs | "
        f"{len(nlp_dict.get('top_keywords', []))} keywords | "
        f"{len(nlp_dict.get('threat_indicators', []))} threat indicators "
        f"[{nlp_duration:.1f}s]"
    )

    # Alerts
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Alert Generation",
            detail="Generating smart security alerts",
            status="active",
        )
    )

    alerts = generate_alerts(filtered, risk_dict, nlp_dict)
    pipeline.alerts = [a.to_dict() for a in alerts]

    recommendations = generate_recommendations(filtered, risk_dict, nlp_dict)
    pipeline.recommendations = [r.to_dict() for r in recommendations]

    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = (
        f"{len(alerts)} alerts ({sum(1 for a in alerts if a.severity == 'critical')} critical) | "
        f"{len(recommendations)} recommendations"
    )

    log.info(
        "ML pipeline complete: risk=%d/100, %d alerts, %d recommendations",
        risk_dict["overall_score"],
        len(alerts),
        len(recommendations),
    )
    return risk_dict, nlp_dict


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

    log.info("[1/7] Extracting findings from ZIP (%d bytes)", len(zip_bytes))
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

    log.info("[2/7] Whitening %d raw finding(s)", len(raw_findings))
    whitened = whiten_data(raw_findings)
    pipeline.whitened_findings = whitened if isinstance(whitened, list) else []

    # Compute whitening stats from raw text
    raw_text = json.dumps(raw_findings)
    pipeline.compute_sanitization_stats(raw_text)
    pipeline.compute_whitening_examples(raw_findings)

    step.complete(f"Whitened {len(pipeline.whitened_findings)} findings")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 3b. Normalize & filter -----------------------------------------------
    log.info("[3/7] Normalising & filtering (High + Critical only)")
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

    # --- 4. ML/NLP Analysis ---------------------------------------------------
    log.info("[4/7] Running ML/NLP analysis pipeline")
    risk_dict, nlp_dict = _run_ml_pipeline(pipeline, filtered, pipeline.raw_evidence_text)
    nlp_context = _build_context_summary(
        run_nlp_analysis(filtered, pipeline.raw_evidence_text), len(filtered)
    )

    # --- 5. LLM calls (with enriched context) --------------------------------
    step = pipeline.steps[3]  # AI Analysis
    step.start(f"Running LLM analysis on {len(filtered)} findings")

    log.info("[5/7] Running LLM analysis via Ollama (with ML-enriched context)")

    executive_model = select_model(TASK_EXECUTIVE_SUMMARY)
    technical_model = select_model(TASK_TECHNICAL_ANALYSIS)
    details_model = select_model(TASK_DETAILED_FINDINGS)

    # Track model usage
    exec_usage = ModelUsage(model=executive_model, task="Executive Summary", status="processing")
    tech_usage = ModelUsage(model=technical_model, task="Technical Analysis", status="pending")
    detail_usage = ModelUsage(model=details_model, task="Detailed Findings", status="pending")
    pipeline.model_usage = [exec_usage, tech_usage, detail_usage]

    # Executive summary (with ML context)
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{executive_model} — Executive Summary",
            detail=f"Generating executive summary from {len(filtered)} findings + ML context",
            status="active",
        )
    )
    t0 = time.perf_counter()
    exec_prompt = gemma_executive_prompt(filtered, organization_context, risk_dict, nlp_context)
    executive_summary = call_ollama(executive_model, exec_prompt)
    exec_duration = time.perf_counter() - t0
    exec_usage.status = "completed"
    exec_usage.duration_seconds = round(exec_duration, 1)
    exec_usage.input_tokens = len(exec_prompt.split())
    exec_usage.output_tokens = len(executive_summary.split())
    pipeline.executive_summary = executive_summary
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {exec_duration:.1f}s"

    # Technical analysis (with ML context)
    tech_usage.status = "processing"
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{technical_model} — Technical Analysis",
            detail="Analyzing attack surface and risk patterns with ML enrichment",
            status="active",
        )
    )
    t0 = time.perf_counter()
    tech_prompt = llama_technical_analysis_prompt(filtered, organization_context, risk_dict, nlp_context)
    technical_analysis = call_ollama(technical_model, tech_prompt)
    tech_duration = time.perf_counter() - t0
    tech_usage.status = "completed"
    tech_usage.duration_seconds = round(tech_duration, 1)
    tech_usage.input_tokens = len(tech_prompt.split())
    tech_usage.output_tokens = len(technical_analysis.split())
    pipeline.technical_analysis = technical_analysis
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {tech_duration:.1f}s"

    # Detailed findings (with ML context)
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
    detail_prompt = llama_detailed_findings_prompt(filtered, organization_context, risk_dict, nlp_context)
    detailed_findings = call_ollama(details_model, detail_prompt)
    detail_duration = time.perf_counter() - t0
    detail_usage.status = "completed"
    detail_usage.duration_seconds = round(detail_duration, 1)
    detail_usage.input_tokens = len(detail_prompt.split())
    detail_usage.output_tokens = len(detailed_findings.split())
    pipeline.detailed_findings_text = detailed_findings
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {detail_duration:.1f}s"

    step.complete("All 3 LLM tasks completed (with ML-enriched context)")

    # --- 6. Validation --------------------------------------------------------
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

    # --- 7. Build & persist report --------------------------------------------
    step = pipeline.steps[5]  # Report
    step.start("Building Markdown report")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Report generation",
            detail="Assembling final Markdown report with ML insights",
            status="active",
        )
    )

    log.info("[6/7] Building Markdown report with ML-enriched sections")
    markdown = build_report_markdown(
        org_context=organization_context,
        vulnerabilities=filtered,
        executive_summary=executive_summary,
        technical_analysis=technical_analysis,
        detailed_findings=detailed_findings,
        risk_scores=risk_dict,
        recommendations=pipeline.recommendations,
    )

    log.info("[7/7] Saving output files")
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
                "risk_scores": risk_dict,
                "alerts": pipeline.alerts,
                "recommendations": pipeline.recommendations,
                "nlp_analysis": nlp_dict,
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
        "risk_score": risk_dict.get("overall_score", 0),
        "risk_level": risk_dict.get("risk_level", "unknown"),
        "alert_count": len(pipeline.alerts),
    })

    log.info(
        "Pipeline complete in %.1fs – %d finding(s), risk=%d/100, %d alerts, output: %s",
        elapsed,
        len(filtered),
        risk_dict.get("overall_score", 0),
        len(pipeline.alerts),
        md_path,
    )
    return str(md_path), markdown, len(filtered)


def generate_report_from_folder(
    folder_path: str,
    organization_context: str,
) -> tuple[str, str, int]:
    """Run the full pipeline from a folder of evidence files.

    Same as generate_report_from_zip but reads directly from disk.
    """
    t_start = time.perf_counter()
    pipeline = create_pipeline(organization_context)

    # --- 1. Ingestion from folder ---
    step = pipeline.steps[0]
    step.start(f"Extracting findings from folder: {folder_path}")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Folder ingestion started",
            detail=f"Processing evidence folder: {folder_path}",
            status="active",
        )
    )

    log.info("[1/7] Extracting findings from folder: %s", folder_path)
    raw_findings, raw_evidence_text = extract_findings_from_folder(folder_path)
    pipeline.raw_findings = raw_findings
    pipeline.raw_evidence_text = raw_evidence_text
    pipeline.file_count = len(set(f.get("source_file", "") for f in raw_findings))
    step.complete(f"Extracted {len(raw_findings)} raw findings from {pipeline.file_count} files")
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = (
        f"Extracted {len(raw_findings)} findings from {pipeline.file_count} files"
    )

    # --- 2. Parsing & ETL ---
    step = pipeline.steps[1]
    step.start(f"Parsing {len(raw_findings)} raw findings")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Evidence parsing",
            detail=f"Processing {len(raw_findings)} findings",
            status="active",
        )
    )
    step.complete(f"Parsed {len(raw_findings)} findings")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 3. Whitening ---
    step = pipeline.steps[2]
    step.start(f"Whitening {len(raw_findings)} raw findings")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Data whitening",
            detail=f"Sanitizing {len(raw_findings)} findings",
            status="active",
        )
    )

    log.info("[2/7] Whitening %d raw finding(s)", len(raw_findings))
    whitened = whiten_data(raw_findings)
    pipeline.whitened_findings = whitened if isinstance(whitened, list) else []
    raw_text = json.dumps(raw_findings)
    pipeline.compute_sanitization_stats(raw_text)
    pipeline.compute_whitening_examples(raw_findings)
    step.complete(f"Whitened {len(pipeline.whitened_findings)} findings")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 3b. Filter ---
    log.info("[3/7] Normalising & filtering (High + Critical only)")
    filtered = normalize_and_filter(pipeline.whitened_findings)
    pipeline.filtered_findings = filtered
    log.info("Retained %d finding(s) after filtering", len(filtered))
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Vulnerability correlation",
            detail=f"Filtered to {len(filtered)} High/Critical findings",
            status="done",
        )
    )

    if not filtered:
        log.warning("No High/Critical findings found – generating empty report")

    # --- 4. ML/NLP ---
    log.info("[4/7] Running ML/NLP analysis")
    risk_dict, nlp_dict = _run_ml_pipeline(pipeline, filtered, raw_evidence_text)
    nlp_context = _build_context_summary(
        run_nlp_analysis(filtered, raw_evidence_text), len(filtered)
    )

    # --- 5. LLM ---
    step = pipeline.steps[3]
    step.start(f"Running LLM analysis on {len(filtered)} findings")
    log.info("[5/7] Running LLM analysis via Ollama")

    executive_model = select_model(TASK_EXECUTIVE_SUMMARY)
    technical_model = select_model(TASK_TECHNICAL_ANALYSIS)
    details_model = select_model(TASK_DETAILED_FINDINGS)

    exec_usage = ModelUsage(model=executive_model, task="Executive Summary", status="processing")
    tech_usage = ModelUsage(model=technical_model, task="Technical Analysis", status="pending")
    detail_usage = ModelUsage(model=details_model, task="Detailed Findings", status="pending")
    pipeline.model_usage = [exec_usage, tech_usage, detail_usage]

    # Executive summary
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event=f"{executive_model} — Executive Summary",
            detail="Generating with ML context",
            status="active",
        )
    )
    t0 = time.perf_counter()
    exec_prompt = gemma_executive_prompt(filtered, organization_context, risk_dict, nlp_context)
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
            detail="Analyzing with ML enrichment",
            status="active",
        )
    )
    t0 = time.perf_counter()
    tech_prompt = llama_technical_analysis_prompt(filtered, organization_context, risk_dict, nlp_context)
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
            detail=f"Analyzing {len(filtered)} findings",
            status="active",
        )
    )
    t0 = time.perf_counter()
    detail_prompt = llama_detailed_findings_prompt(filtered, organization_context, risk_dict, nlp_context)
    detailed_findings = call_ollama(details_model, detail_prompt)
    detail_duration = time.perf_counter() - t0
    detail_usage.status = "completed"
    detail_usage.duration_seconds = round(detail_duration, 1)
    detail_usage.input_tokens = len(detail_prompt.split())
    detail_usage.output_tokens = len(detailed_findings.split())
    pipeline.detailed_findings_text = detailed_findings
    pipeline.analysis_timeline[-1].status = "done"
    pipeline.analysis_timeline[-1].detail = f"Completed in {detail_duration:.1f}s"

    step.complete("All LLM tasks completed")

    # --- 6. Validation ---
    step = pipeline.steps[4]
    step.start("Running validation checks")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Cross-validation",
            detail="Validating findings",
            status="active",
        )
    )
    pipeline.compute_validation()
    passed = sum(1 for c in pipeline.validation_checklist if c["passed"])
    total = len(pipeline.validation_checklist)
    step.complete(f"Validation — {passed}/{total} checks passed")
    pipeline.analysis_timeline[-1].status = "done"

    # --- 7. Report ---
    step = pipeline.steps[5]
    step.start("Building report")
    pipeline.analysis_timeline.append(
        TimelineEvent(
            time=datetime.utcnow().strftime("%H:%M:%S"),
            event="Report generation",
            detail="Assembling Markdown report",
            status="active",
        )
    )

    log.info("[6/7] Building report")
    markdown = build_report_markdown(
        org_context=organization_context,
        vulnerabilities=filtered,
        executive_summary=executive_summary,
        technical_analysis=technical_analysis,
        detailed_findings=detailed_findings,
        risk_scores=risk_dict,
        recommendations=pipeline.recommendations,
    )

    log.info("[7/7] Saving output files")
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
                "risk_scores": risk_dict,
                "alerts": pipeline.alerts,
                "recommendations": pipeline.recommendations,
                "nlp_analysis": nlp_dict,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    pipeline.report_markdown = markdown
    pipeline.report_path = str(md_path)
    step.complete(f"Report saved: {md_path.name}")
    pipeline.analysis_timeline[-1].status = "done"

    elapsed = time.perf_counter() - t_start
    add_report({
        "name": f"ReportX — {organization_context.title()} Assessment",
        "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "status": "Completed",
        "vulnerability_count": len(filtered),
        "output_path": str(md_path),
        "duration_seconds": round(elapsed, 1),
        "risk_score": risk_dict.get("overall_score", 0),
        "risk_level": risk_dict.get("risk_level", "unknown"),
        "alert_count": len(pipeline.alerts),
    })

    log.info("Pipeline complete in %.1fs – %d findings, risk=%d/100", elapsed, len(filtered), risk_dict.get("overall_score", 0))
    return str(md_path), markdown, len(filtered)
