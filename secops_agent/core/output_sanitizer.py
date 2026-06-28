"""
Sanitize tool outputs before LLM ingestion.

Strips known prompt-injection patterns from raw tool output and wraps the
result in data-boundary markers so the LLM treats it as external data rather
than instructions.

Addresses OWASP ASI01 (Agent Goal Hijacking) and ASI04 (Memory Poisoning).
"""

from __future__ import annotations

import re
from typing import Sequence

# ---------------------------------------------------------------------------
# Known injection patterns — compiled once at import time
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: Sequence[re.Pattern[str]] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(previous|all|above|prior)\s+instructions",
        r"disregard\s+(previous|all|above|prior)\s+instructions",
        r"forget\s+(previous|all|above|prior)\s+(instructions|context)",
        r"you\s+are\s+now\s+a",
        r"you\s+must\s+now",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*",
        r"assistant\s*:\s*",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"\[INST\]",
        r"\[/INST\]",
        r"<<SYS>>",
        r"<</SYS>>",
        r"Human\s*:\s*",
        r"AI\s*:\s*",
    )
)

_FILTERED_MARKER = "[FILTERED]"


def sanitize_tool_output(tool_name: str, output: str) -> str:
    """Clean tool output and wrap it in data-boundary markers.

    Parameters
    ----------
    tool_name:
        Name of the tool that produced the output (used in boundary markers).
    output:
        Raw stdout/stderr content from the tool execution.

    Returns
    -------
    str
        Sanitized output with injection patterns stripped and boundary markers
        added so the LLM recognises it as external data.
    """
    if not output:
        return output

    cleaned = output
    for pattern in _INJECTION_PATTERNS:
        cleaned = pattern.sub(_FILTERED_MARKER, cleaned)

    return (
        f"── TOOL DATA [{tool_name}] ──\n"
        f"{cleaned}\n"
        f"── END TOOL DATA ──"
    )
