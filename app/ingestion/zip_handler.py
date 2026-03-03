"""Extract findings from an uploaded ZIP of scan files."""

from __future__ import annotations

import logging
from io import BytesIO
from zipfile import BadZipFile, ZipFile

from app.config import MAX_ZIP_SIZE_MB
from app.ingestion.parsers import parse_csv_bytes, parse_json_bytes, parse_xml_bytes

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
            else:
                log.debug("Skipping unsupported file: %s", name)

    log.info(
        "ZIP extraction complete – %d scan file(s) processed, %d raw finding(s)",
        processed_files,
        len(findings),
    )
    return findings
