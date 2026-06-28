"""
Persistent CLI preferences shared across SecOps launches.

This module intentionally writes to the same settings.json file used by the
permission engine, while preserving unrelated keys such as ``permissions``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def default_settings_path() -> Path:
    configured = os.getenv("SECOPS_SETTINGS_FILE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".secops_agent" / "settings.json"


def _read_settings(path: Path | None = None) -> dict[str, Any]:
    settings_path = path or default_settings_path()
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_settings(data: dict[str, Any], path: Path | None = None) -> None:
    settings_path = path or default_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_preferences(path: Path | None = None) -> dict[str, Any]:
    data = _read_settings(path)
    preferences = data.get("preferences", {})
    return dict(preferences) if isinstance(preferences, dict) else {}


def save_model_preference(
    raw_model: str,
    *,
    resolved_model: str,
    thinking_level: str = "",
    auto_routing: bool = False,
    path: Path | None = None,
) -> None:
    data = _read_settings(path)
    preferences = data.get("preferences", {})
    if not isinstance(preferences, dict):
        preferences = {}
    preferences["model"] = {
        "raw_model": raw_model,
        "resolved_model": resolved_model,
        "thinking_level": thinking_level,
        "auto_routing": bool(auto_routing),
    }
    data["preferences"] = preferences
    _write_settings(data, path)


def load_model_preference(path: Path | None = None) -> dict[str, Any]:
    model = load_preferences(path).get("model", {})
    return dict(model) if isinstance(model, dict) else {}


# ── Display / verbosity preferences (❌ §5.7) ────────────────────────

_DISPLAY_DEFAULTS: dict[str, Any] = {
    "verbosity": "medium",          # low | medium | high
    "show_thought": True,           # show ▸ Thought blocks
    "show_lesson_detail": False,    # show Lesson:/Match: on suggestions
    "archived_call_alert": True,    # warn on [Archived tool call] markers
    "auto_retry_api": True,         # hint user to retry on transient errors
    "max_suggestions": 5,           # max suggested next-actions shown
}


def load_display_preferences(path: Path | None = None) -> dict[str, Any]:
    """Load display preferences, filling missing keys with defaults."""
    prefs = load_preferences(path)
    display = prefs.get("display", {})
    if not isinstance(display, dict):
        display = {}
    merged = dict(_DISPLAY_DEFAULTS)
    merged.update({k: v for k, v in display.items() if k in _DISPLAY_DEFAULTS})
    return merged


def save_display_preference(
    key: str,
    value: Any,
    *,
    path: Path | None = None,
) -> None:
    """Persist a single display preference to settings.json."""
    if key not in _DISPLAY_DEFAULTS:
        return
    data = _read_settings(path)
    preferences = data.get("preferences", {})
    if not isinstance(preferences, dict):
        preferences = {}
    display = preferences.get("display", {})
    if not isinstance(display, dict):
        display = {}
    display[key] = value
    preferences["display"] = display
    data["preferences"] = preferences
    _write_settings(data, path)
