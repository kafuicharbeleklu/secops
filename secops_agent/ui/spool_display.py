"""
Helpers for rendering supervised process spool files in TUI detail views.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping


MAX_SPOOL_DETAIL_CHARS = 200_000
_EXIT_CODE_RE = re.compile(r"\[Exit Code:\s*[^\]]+\]")


def should_use_spool_detail(text: str) -> bool:
    """Return True when compact output points to omitted supervised output."""
    normalized = str(text or "")
    lowered = normalized.casefold()
    return (
        "[output truncated in memory;" in lowered
        or "[spool:" in lowered
        or "\nspool:" in lowered
        or "tool execution timed out" in lowered
        or "command timed out" in lowered
        or "command stopped after" in lowered
        or "… [output truncated:" in normalized
    )


def supervised_detail_text(metadata: Mapping[str, Any] | None, fallback: str) -> str:
    """Read clean stdout/stderr spool details when available and relevant."""
    fallback_text = str(fallback or "")
    if not metadata or not should_use_spool_detail(fallback_text):
        return fallback_text

    stdout_text = _read_path(_metadata_path(metadata, "stdout_path"))
    stderr_text = _read_path(_metadata_path(metadata, "stderr_path"))
    if stdout_text or stderr_text:
        parts: list[str] = []
        if stdout_text:
            parts.append(stdout_text.rstrip())
        if stderr_text:
            if parts:
                parts.append("")
            parts.extend(["[STDERR]", stderr_text.rstrip()])
        exit_match = _EXIT_CODE_RE.search(fallback_text)
        if exit_match:
            parts.extend(["", exit_match.group(0)])
        return "\n".join(part for part in parts if part is not None).strip() or fallback_text

    combined = _read_path(_metadata_path(metadata, "spool_path"))
    return combined.strip() if combined else fallback_text


def spool_reference(metadata: Mapping[str, Any] | None) -> str:
    """Return the combined supervised log path when it is available."""
    if not metadata:
        return ""
    path = _metadata_path(metadata, "spool_path")
    return str(path) if path else ""


def should_show_spool_reference(
    metadata: Mapping[str, Any] | None,
    fallback: str,
    *,
    execution_time: float = 0.0,
) -> bool:
    """Show log paths for long, truncated, or timed-out supervised executions."""
    if not spool_reference(metadata):
        return False
    if should_use_spool_detail(fallback):
        return True
    if metadata and metadata.get("timeout_reason"):
        return True
    try:
        return float(execution_time or 0.0) >= 2.0
    except (TypeError, ValueError):
        return False


def _metadata_path(metadata: Mapping[str, Any], key: str) -> Path | None:
    raw = metadata.get(key)
    if not raw:
        return None
    try:
        path = Path(str(raw)).expanduser()
    except (TypeError, ValueError):
        return None
    return path if path.exists() and path.is_file() else None


def _read_path(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_SPOOL_DETAIL_CHARS + 1)
    except OSError:
        return ""
    if len(text) <= MAX_SPOOL_DETAIL_CHARS:
        return text
    return (
        text[:MAX_SPOOL_DETAIL_CHARS].rstrip()
        + "\n\n"
        + f"... spool detail truncated after {MAX_SPOOL_DETAIL_CHARS:,} chars ..."
    )
