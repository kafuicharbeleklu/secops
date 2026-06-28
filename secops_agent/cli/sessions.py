"""Pure parsing helpers for session slash commands."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SAVE_USAGE = "Usage: /save <name>"
LOAD_USAGE = "Usage: /load <name>"
MISSION_ACTIVITY_FIELDS = (
    "targets",
    "hosts",
    "services",
    "findings",
    "credentials",
    "blocked_reasons",
    "completed_objectives",
)


@dataclass(frozen=True)
class SessionNameArgument:
    name: str = ""
    error: str = ""


@dataclass(frozen=True)
class ResumeTarget:
    action: str
    target: str = ""


@dataclass(frozen=True)
class SessionModelSelection:
    raw_model: str = ""
    thinking_level: str | None = None


def _parse_session_name(argument: str, usage: str) -> SessionNameArgument:
    name = str(argument or "").strip()
    if not name:
        return SessionNameArgument(error=usage)
    return SessionNameArgument(name=name)


def parse_save_argument(argument: str) -> SessionNameArgument:
    return _parse_session_name(argument, SAVE_USAGE)


def parse_load_argument(argument: str) -> SessionNameArgument:
    return _parse_session_name(argument, LOAD_USAGE)


def parse_export_argument(argument: str, *, now: datetime | None = None) -> SessionNameArgument:
    name = str(argument or "").strip()
    if name:
        return SessionNameArgument(name=name)
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return SessionNameArgument(name=f"secops_{timestamp}")


def mission_has_autosave_activity(mission: object | None) -> bool:
    if mission is None:
        return False
    return any(bool(getattr(mission, field, None)) for field in MISSION_ACTIVITY_FIELDS)


def should_autosave_session(
    *,
    message_count: int,
    artifact_count: int,
    mission: object | None = None,
) -> bool:
    return message_count > 0 or artifact_count > 0 or mission_has_autosave_activity(mission)


def build_session_metadata(
    session_name: str,
    *,
    auto_saved: bool = False,
    reason: str = "manual",
    model_name: str = "",
    thinking_level: str = "",
    model_auto_routing: bool = False,
    cwd: str = "",
    now: datetime | None = None,
) -> dict[str, object]:
    return {
        "name": session_name,
        "auto_saved": auto_saved,
        "reason": reason,
        "saved_at": (now or datetime.now(timezone.utc)).isoformat(),
        "model": model_name,
        "thinking_level": thinking_level,
        "model_auto_routing": model_auto_routing,
        "cwd": cwd,
    }


def resolve_session_model(metadata: object) -> SessionModelSelection:
    if not isinstance(metadata, dict):
        return SessionModelSelection()
    raw_model = "auto" if metadata.get("model_auto_routing") else str(metadata.get("model") or "").strip()
    if not raw_model:
        return SessionModelSelection()
    thinking = str(metadata.get("thinking_level") or "").strip() or None
    return SessionModelSelection(raw_model=raw_model, thinking_level=thinking)


def build_session_summary(
    name: str,
    payload: object,
    *,
    modified_at: str = "",
) -> dict[str, object]:
    metadata: dict[str, object] = {}
    messages: list[object] = []
    runtime: dict[str, object] = {}
    if isinstance(payload, list):
        messages = payload
    elif isinstance(payload, dict):
        raw_metadata = payload.get("metadata", {})
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        raw_messages = payload.get("messages", [])
        messages = raw_messages if isinstance(raw_messages, list) else []
        raw_runtime = payload.get("runtime", {})
        runtime = raw_runtime if isinstance(raw_runtime, dict) else {}

    artifacts = runtime.get("artifacts", [])
    artifact_count = len(artifacts) if isinstance(artifacts, list) else 0
    saved_at = str(metadata.get("saved_at") or "")
    return {
        "name": name,
        "label": name.replace(".json", ""),
        "messages": len(messages),
        "artifacts": artifact_count,
        "model": str(metadata.get("model") or ""),
        "cwd": str(metadata.get("cwd") or ""),
        "saved_at": saved_at or str(modified_at or ""),
        "auto_saved": bool(metadata.get("auto_saved", False)),
    }


def format_session_description(summary: dict[str, object]) -> str:
    saved_at = str(summary.get("saved_at") or "")
    when = saved_at[:16].replace("T", " ") if saved_at else "unknown date"
    model = str(summary.get("model") or "unknown model")
    cwd = str(summary.get("cwd") or "")
    cwd_name = Path(cwd).name if cwd else ""
    counts = f"{summary.get('messages', 0)} msg"
    artifacts = int(summary.get("artifacts") or 0)
    if artifacts:
        counts += f" · {artifacts} artifact"
    parts = [when, model, counts]
    if cwd_name:
        parts.append(cwd_name)
    return " · ".join(parts)


def resolve_resume_target(
    argument: str,
    *,
    interactive_surface: bool,
    selected_session: str = "",
    latest_session: str = "",
) -> ResumeTarget:
    explicit = str(argument or "").strip()
    if explicit:
        return ResumeTarget(action="load", target=explicit)
    if interactive_surface:
        selected = str(selected_session or "").strip()
        if selected:
            return ResumeTarget(action="load", target=selected)
        return ResumeTarget(action="exit")
    latest = str(latest_session or "").strip()
    if latest:
        return ResumeTarget(action="load", target=latest)
    return ResumeTarget(action="empty")
