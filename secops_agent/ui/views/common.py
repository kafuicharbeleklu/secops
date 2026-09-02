"""Shared view primitives and data structures (extracted from renderer.py)."""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

from rich.console import Console
from secops_agent.ui import layout

@dataclass(frozen=True)
class SettingsItem:
    label: str
    value: str
    description: str
    editable: bool = False
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class SettingsSelection:
    item: SettingsItem
    value: str | None = None


@dataclass(frozen=True)
class AgentProfileSummary:
    name: str
    description: str
    source: str
    path: Path


@dataclass(frozen=True)
class AgentViewEntry:
    value: str
    label: str
    status: str
    description: str
    kind: str


@dataclass(frozen=True)
class _MCPViewItem:
    label: str
    detail: str
    kind: str = "server"


@dataclass(frozen=True)
class _SkillViewItem:
    label: str
    detail: str
    kind: str = "skill"


def _turn_separator(width: int) -> str:
    """Return a transcript separator that avoids terminal-edge wrapping."""
    return "─" * max(1, width - 1)


def _surface_width(console: Console | None = None, default: int = 80) -> int:
    """Current usable width in cells (P2: via the central layout layer)."""
    return layout.terminal_size(console, default_width=default)[0]


def _surface_height(console: Console | None = None, default: int = 24) -> int:
    """Current usable height in rows (P2: via the central layout layer)."""
    return layout.terminal_size(console, default_height=default)[1]


def _ctrl_o_output_visible_limit(console: Console | None = None, *, default: int = 40) -> int:
    """Keep ctrl+o detail surfaces short enough to clear in-place."""
    return max(1, min(default, _surface_height(console, 24) - 8))


def _display_path(path: Path) -> str:
    text = str(path.expanduser())
    home = str(Path.home())
    if text.startswith(home):
        return "~" + text[len(home):]
    return text


def agent_profile_template_paths(*, cwd: Path | None = None, home: Path | None = None) -> tuple[Path, Path]:
    base_cwd = cwd or Path.cwd()
    base_home = home or Path.home()
    return (
        base_cwd / ".agents" / "agents" / "{agent_name}" / "agent.json",
        base_home / ".secops_agent" / "agents" / "{agent_name}" / "agent.json",
    )


def load_agent_profiles(*, cwd: Path | None = None, home: Path | None = None) -> list[AgentProfileSummary]:
    """Load display-only SecOps agent profile definitions from real JSON files."""
    base_cwd = cwd or Path.cwd()
    base_home = home or Path.home()
    roots = [
        ("workspace", base_cwd / ".agents" / "agents"),
        ("user", base_home / ".secops_agent" / "agents"),
    ]
    profiles: list[AgentProfileSummary] = []
    seen: set[tuple[str, Path]] = set()

    for source, root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for profile_path in sorted(root.glob("*/agent.json")):
            key = (source, profile_path)
            if key in seen:
                continue
            seen.add(key)
            try:
                data = json.loads(profile_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            name = str(data.get("name") or profile_path.parent.name).strip() or profile_path.parent.name
            description = (
                data.get("description")
                or data.get("role")
                or data.get("summary")
                or "SecOps agent profile"
            )
            description = " ".join(str(description).split())
            profiles.append(
                AgentProfileSummary(
                    name=name,
                    description=description,
                    source=source,
                    path=profile_path,
                )
            )

    return profiles

def _transient_content_height(terminal_height: int, *, prompt_frame: bool = False) -> int:
    """Reserve rows for inline prompt chrome and the cancel/model statusline."""
    overhead = (3 if prompt_frame else 0) + 2
    return max(5, terminal_height - overhead)


def _fit_cell(text: str, width: int) -> str:
    """Cell-accurate truncation (P2); delegates to the central layout layer."""
    return layout.fit_cell(text, width)

