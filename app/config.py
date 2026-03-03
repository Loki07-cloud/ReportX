"""Central configuration for the ReportX backend."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging() -> None:
    """Configure root logger once at startup."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format=LOG_FORMAT,
        stream=sys.stdout,
    )


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = "http://localhost:11434"
OLLAMA_TIMEOUT_SECONDS: int = 300
OLLAMA_MAX_RETRIES: int = 2

MODEL_GEMMA_EXEC: str = "gemma2:2b"
MODEL_LLAMA_TECH: str = "llama3:8b"

DETERMINISTIC_OPTIONS: dict = {
    "temperature": 0,
    "top_p": 1,
    "seed": 42,
    "num_predict": 2048,
}

# System-level instruction injected into every Ollama call to prevent
# hallucination and enforce evidence-only responses.
SYSTEM_PROMPT: str = (
    "You are a security audit assistant. You MUST base your output "
    "EXCLUSIVELY on the vulnerability data provided in the user prompt. "
    "Do NOT invent, assume, or reference any systems, CVEs, scores, "
    "controls, or impacts not explicitly present in the data. "
    "If information is missing, state: 'Unavailable in provided evidence.'"
)

# ---------------------------------------------------------------------------
# Ingestion / filtering
# ---------------------------------------------------------------------------
ALLOWED_SEVERITIES: set[str] = {"high", "critical"}

# Aliases that scanners may use for High / Critical severity values.
SEVERITY_ALIASES: dict[str, str] = {
    "4": "high",
    "5": "critical",
    "severe": "critical",
    "important": "high",
}

MAX_ZIP_SIZE_MB: int = 100

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
OUTPUT_DIR: Path = Path(__file__).resolve().parents[1] / "output"
