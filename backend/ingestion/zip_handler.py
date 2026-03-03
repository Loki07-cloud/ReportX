"""Extract findings from an uploaded ZIP of scan files."""

from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from config import MAX_ZIP_SIZE_MB
from ingestion.parsers import parse_csv_bytes, parse_json_bytes, parse_xml_bytes
from ingestion.evidence_parser import parse_evidence_text

log = logging.getLogger(__name__)

_MAX_BYTES = MAX_ZIP_SIZE_MB * 1024 * 1024


def extract_findings_from_zip(zip_bytes: bytes) -> list[dict]:
    """Open *zip_bytes*, iterate over supported scan files and return parsed findings."""
    if len(zip_bytes) > _MAX_BYTES:
        raise ValueError(
            f"ZIP file exceeds maximum allowed size of {MAX_ZIP_SIZE_MB} MB"
        )

    try:
        zf = ZipFile(BytesIO(zip_bytes))
    except BadZipFile as exc:
        raise ValueError("Uploaded file is not a valid ZIP archive") from exc

    findings: list[dict] = []
    processed_files = 0

    with zf:
        for name in zf.namelist():
            lowered = name.lower()
            # Skip directories and hidden / macOS resource-fork files
            if name.endswith("/") or name.startswith("__MACOSX"):
                continue

            with zf.open(name) as file_obj:
                content = file_obj.read()

            if lowered.endswith(".json"):
                findings.extend(parse_json_bytes(content, name))
                processed_files += 1
            elif lowered.endswith(".xml"):
                findings.extend(parse_xml_bytes(content, name))
                processed_files += 1
            elif lowered.endswith(".csv"):
                findings.extend(parse_csv_bytes(content, name))
                processed_files += 1
            elif lowered.endswith(".txt") or lowered.endswith(".log") or lowered.endswith(".nmap"):
                # Parse text evidence files (nmap, banners, vulnerability assessments, etc.)
                try:
                    text_content = content.decode("utf-8", errors="replace")
                    text_findings = parse_evidence_text(text_content, name)
                    findings.extend(text_findings)
                    processed_files += 1
                    log.info("Parsed %d findings from evidence file: %s", len(text_findings), name)
                except Exception as exc:
                    log.warning("Failed to parse evidence file %s: %s", name, exc)
            else:
                log.debug("Skipping unsupported file: %s", name)

    log.info(
        "ZIP extraction complete – %d scan file(s) processed, %d raw finding(s)",
        processed_files,
        len(findings),
    )
    return findings


def extract_findings_from_folder(folder_path: str) -> tuple[list[dict], str]:
    """Extract findings from a folder of evidence/scan files on disk.

    Returns (findings, raw_evidence_text) where raw_evidence_text is
    the concatenated text of all evidence files for NLP analysis.
    """
    folder = Path(folder_path)
    if not folder.exists():
        raise ValueError(f"Folder not found: {folder_path}")

    findings: list[dict] = []
    raw_texts: list[str] = []
    processed = 0

    for fpath in sorted(folder.rglob("*")):
        if not fpath.is_file():
            continue
        name = str(fpath.relative_to(folder))
        lowered = name.lower()

        try:
            content = fpath.read_bytes()
        except Exception as exc:
            log.warning("Cannot read %s: %s", name, exc)
            continue

        if lowered.endswith(".json"):
            findings.extend(parse_json_bytes(content, name))
            processed += 1
        elif lowered.endswith(".xml"):
            findings.extend(parse_xml_bytes(content, name))
            processed += 1
        elif lowered.endswith(".csv"):
            findings.extend(parse_csv_bytes(content, name))
            processed += 1
        elif lowered.endswith((".txt", ".log", ".nmap")):
            try:
                text = content.decode("utf-8", errors="replace")
                raw_texts.append(f"--- {name} ---\n{text}")
                text_findings = parse_evidence_text(text, name)
                findings.extend(text_findings)
                processed += 1
            except Exception as exc:
                log.warning("Failed to parse evidence file %s: %s", name, exc)

    raw_evidence = "\n\n".join(raw_texts)
    log.info(
        "Folder extraction complete – %d file(s) processed, %d raw finding(s)",
        processed,
        len(findings),
    )
    return findings, raw_evidence
