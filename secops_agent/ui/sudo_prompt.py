"""
Local sudo authentication prompt for the interactive TUI.

The password is read and used inside this module only. The agent receives only a
success/failure decision.
"""

from __future__ import annotations

import getpass
from typing import Any

from rich.markup import escape

from secops_agent.core.sudo import (
    SudoAuthenticationDecision,
    authenticate_sudo_with_password,
    can_prompt_for_sudo,
)
from secops_agent.ui.theme import COLORS
from secops_agent.ui import layout


async def request_sudo_authentication(
    console: Any,
    *,
    command: str,
    reason: str = "",
) -> SudoAuthenticationDecision:
    if not can_prompt_for_sudo():
        return SudoAuthenticationDecision(
            False,
            "sudo authentication requires an interactive terminal",
        )

    display_command = " ".join(str(command or "").split())
    if len(display_command) > 120:
        display_command = display_command[:119] + "…"
    console.print()
    console.print(
        f"{layout.INDENT_STR}[{COLORS['warning']}]Sudo authentication required[/{COLORS['warning']}]"
    )
    if display_command:
        console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Command: {escape(display_command)}[/{COLORS['text_muted']}]")
    if reason:
        console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Reason: {escape(reason)}[/{COLORS['text_muted']}]")
    console.print(
        f"{layout.INDENT_STR}[{COLORS['text_dim']}]Password is used locally for sudo -v and is not sent to the model or saved.[/{COLORS['text_dim']}]"
    )

    return await authenticate_sudo_with_password(getpass.getpass)
