"""Ollama HTTP client for local LLM inference.

All requests go to ``http://localhost:11434`` with streaming disabled
and deterministic generation options (temperature 0, fixed seed).
A system-level prompt is injected into every call to prevent hallucination.
"""

from __future__ import annotations

import json
import logging
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from config import (
    DETERMINISTIC_OPTIONS,
    OLLAMA_BASE_URL,
    OLLAMA_MAX_RETRIES,
    OLLAMA_TIMEOUT_SECONDS,
    SYSTEM_PROMPT,
)

log = logging.getLogger(__name__)


class OllamaError(RuntimeError):
    """Raised when communication with Ollama fails."""


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------
def ping_ollama() -> bool:
    """Return True if Ollama is reachable, False otherwise."""
    try:
        req = Request(f"{OLLAMA_BASE_URL}/api/tags", method="GET")
        with urlopen(req, timeout=5):
            return True
    except Exception:
        return False


def call_ollama(model: str, prompt: str, *, system: str | None = None) -> str:
    """Send a generation request to Ollama and return the response text.

    Parameters
    ----------
    model:
        Ollama model tag (e.g. ``gemma2:2b``, ``llama3:8b``).
    prompt:
        User prompt containing vulnerability data and task instructions.
    system:
        Optional override for the system prompt.  Defaults to
        :data:`app.config.SYSTEM_PROMPT`.
    """
    endpoint = f"{OLLAMA_BASE_URL}/api/generate"
    body = {
        "model": model,
        "prompt": prompt,
        "system": system or SYSTEM_PROMPT,
        "stream": False,
        "options": DETERMINISTIC_OPTIONS,
    }
    request = Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    last_exc: Exception | None = None
    for attempt in range(1, OLLAMA_MAX_RETRIES + 2):  # 1 initial + retries
        try:
            log.info(
                "Ollama request [model=%s, attempt=%d/%d]",
                model,
                attempt,
                OLLAMA_MAX_RETRIES + 1,
            )
            t0 = time.perf_counter()
            with urlopen(request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
            elapsed = time.perf_counter() - t0
            log.info("Ollama responded in %.1fs [model=%s]", elapsed, model)
            break
        except HTTPError as exc:
            last_exc = exc
            log.warning("Ollama HTTP %d on attempt %d", exc.code, attempt)
        except URLError as exc:
            last_exc = exc
            log.warning("Ollama unreachable on attempt %d: %s", attempt, exc.reason)
        except Exception as exc:
            last_exc = exc
            log.warning("Unexpected error on attempt %d: %s", attempt, exc)

        if attempt <= OLLAMA_MAX_RETRIES:
            time.sleep(2 ** attempt)  # simple exponential back-off
    else:
        raise OllamaError(
            f"Ollama request failed after {OLLAMA_MAX_RETRIES + 1} attempts: {last_exc}"
        ) from last_exc

    output = payload.get("response", "")
    if not output:
        raise OllamaError(f"Empty response from Ollama model '{model}'")
    return output.strip()
