"""Dynamic model routing based on task type.

Maps logical task names to the appropriate Ollama model tag:
- Executive / business summaries → Gemma 2 2B (lightweight, concise)
- Technical analysis & detailed findings → LLaMA 3 8B (deeper reasoning)
"""

from __future__ import annotations

import logging
from enum import Enum

from config import MODEL_GEMMA_EXEC, MODEL_LLAMA_TECH

log = logging.getLogger(__name__)


class TaskType(str, Enum):
    """Supported LLM task types."""

    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    DETAILED_FINDINGS = "detailed_findings"


# Legacy string aliases (kept for backward-compatibility)
TASK_EXECUTIVE_SUMMARY = TaskType.EXECUTIVE_SUMMARY.value
TASK_TECHNICAL_ANALYSIS = TaskType.TECHNICAL_ANALYSIS.value
TASK_DETAILED_FINDINGS = TaskType.DETAILED_FINDINGS.value

# Mapping from task → model
_TASK_MODEL_MAP: dict[TaskType, str] = {
    TaskType.EXECUTIVE_SUMMARY: MODEL_GEMMA_EXEC,
    TaskType.TECHNICAL_ANALYSIS: MODEL_LLAMA_TECH,
    TaskType.DETAILED_FINDINGS: MODEL_LLAMA_TECH,
}


def select_model(task_type: str | TaskType) -> str:
    """Return the Ollama model tag for the given *task_type*."""
    if isinstance(task_type, str):
        try:
            task_type = TaskType(task_type)
        except ValueError:
            log.warning("Unknown task type '%s' – defaulting to LLaMA", task_type)
            return MODEL_LLAMA_TECH

    model = _TASK_MODEL_MAP.get(task_type, MODEL_LLAMA_TECH)
    log.debug("Task '%s' → model '%s'", task_type.value, model)
    return model
