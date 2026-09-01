"""
Interactive permission mode selection overlay.
"""

from __future__ import annotations

from typing import Optional

from secops_agent.ui.overlay import OverlayChoice, choose_overlay


PERMISSION_MODES: tuple[tuple[str, str], ...] = (
    ("plan", "Build and review a plan; deny every tool and shell execution"),
    ("request-review", "Prompt for write, bash, and web tools"),
    ("proceed-in-sandbox", "Auto-approve terminal commands in sandbox"),
    ("always-proceed", "Auto-approve all tools"),
    ("strict", "Prompt for all non-read tools"),
)


def _permission_choices(current_mode: str) -> list[OverlayChoice]:
    return [
        OverlayChoice(
            value=value,
            label=value,
            description=description,
            current=value == current_mode,
        )
        for value, description in PERMISSION_MODES
    ]


def switch_permissions_menu(
    current_mode: str,
    *,
    status_right: str = "",
    prompt_frame: bool = False,
) -> Optional[str]:
    """Open the Antigravity-style active permissions picker."""
    return choose_overlay(
        "Active Permissions",
        _permission_choices(current_mode),
        status_right=status_right,
        prompt_frame=prompt_frame,
        show_descriptions=True,
        footer="Keyboard: ↑/↓ Navigate  enter Select  esc Close",
    )
