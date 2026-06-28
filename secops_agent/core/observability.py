"""
Structured local observability for SecOps agent runs.

The tracer is intentionally small and optional. It records metadata needed to
debug agent decisions without dumping full prompts, tool outputs, passwords, or
secret-bearing arguments.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from secops_agent.config import settings


_SENSITIVE_KEY_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "key",
    "password",
    "secret",
    "token",
)
_MAX_STRING_LENGTH = 500


class TraceSink(Protocol):
    def write(self, event: dict[str, Any]) -> None:
        ...


class NullTraceSink:
    """Trace sink used when structured tracing is disabled."""

    def write(self, event: dict[str, Any]) -> None:
        return


class JsonlTraceSink:
    """Append trace events as JSON Lines."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class InMemoryTraceSink:
    """Trace sink for tests and local diagnostics."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


@dataclass
class StructuredTracer:
    sink: TraceSink = field(default_factory=NullTraceSink)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def emit(self, event_type: str, **fields: Any) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event": str(event_type),
        }
        event.update(_safe_json(fields))
        try:
            self.sink.write(event)
        except OSError:
            # Observability must never interrupt the agent loop.
            return


def trace_sink_from_settings() -> TraceSink:
    trace_file = getattr(settings, "TRACE_FILE", "")
    if trace_file:
        return JsonlTraceSink(trace_file)
    return NullTraceSink()


def _safe_json(value: Any, *, key: str = "") -> Any:
    lowered_key = key.casefold()
    if lowered_key and any(marker in lowered_key for marker in _SENSITIVE_KEY_MARKERS):
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        compact = " ".join(value.split())
        if len(compact) > _MAX_STRING_LENGTH:
            return compact[:_MAX_STRING_LENGTH] + "...[truncated]"
        return compact
    if isinstance(value, dict):
        return {
            str(item_key): _safe_json(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_safe_json(item) for item in list(value)[:50]]
    return str(value)
