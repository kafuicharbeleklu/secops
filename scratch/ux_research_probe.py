#!/usr/bin/env python3
"""Throwaway feasibility probe for docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

Isolated under scratch/ — imports ONLY `rich` (already a project dep, v15.0.0),
touches nothing under secops_agent/. Validates that the proposals which sound
"advanced" are actually one-liners on the existing Rich stack, with prompt_toolkit
left untouched:

  1. FMT-02  severity-tiered colour for the R0-R8 risk badge (already rendered flat-grey)
  2. ANIM-03 determinate Rich Progress bar for long scans (nmap/gobuster/ffuf)
  3. ANIM-04 OSC 9;4 terminal taskbar progress (host terminal, survives across tools)
  4. X-02    NO_COLOR / reduced-motion honoured by a single Console factory

Run:  .venv/bin/python scratch/ux_research_probe.py
"""
from __future__ import annotations

import os
import time

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


# ── 1. FMT-02: severity-tiered badge colour ──────────────────────────────
# Current code (tool_display._tool_risk_badge) returns "R5" and prints it in a
# flat COLORS['text_dim'] grey — an R8 credentialed action looks like an R0 add.
# Proposal: map the risk tier -> colour so the eye catches destructive rows.
_BADGE_COLOUR = {
    0: "grey58", 1: "grey58", 2: "cyan", 3: "yellow",
    4: "yellow", 5: "orange1", 6: "red", 7: "magenta", 8: "bold red",
}


def render_badges(console: Console) -> None:
    console.rule("[bold]FMT-02  severity-tiered risk badge")
    for tier in range(9):
        colour = _BADGE_COLOUR[tier]
        badge = f"[{colour}]R{tier}[/]"
        console.print(f"  ● SomeTool(target)  {badge}  [dim](tier {tier})[/]")


# ── 2. ANIM-03: determinate progress bar for a long scan ─────────────────
def render_scan_progress(console: Console) -> None:
    console.rule("[bold]ANIM-03  determinate scan progress (Rich Progress)")
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Nmap 10.0.0.5  (1000 ports)", total=1000)
        for _ in range(20):
            progress.update(task, advance=50)
            time.sleep(0.01)  # fast — this is a smoke check, not a real scan


# ── 3. ANIM-04: OSC 9;4 host-terminal taskbar progress ───────────────────
# ConEmu/WezTerm/Windows Terminal/some others render this as a taskbar bar.
# Claude Code emits exactly this (changelog: "OSC 9;4 ... stays visible across
# the full turn"). Pure stdout write — no library, no prompt_toolkit interaction.
def emit_osc_progress(console: Console) -> None:
    console.rule("[bold]ANIM-04  OSC 9;4 terminal taskbar progress")
    seq_set = "\x1b]9;4;1;42\x07"   # state 1 (normal), 42%
    seq_clear = "\x1b]9;4;0;0\x07"  # state 0 (clear)
    console.print(f"  set 42%:  {seq_set!r}")
    console.print(f"  clear:    {seq_clear!r}")
    console.print("  [dim](repr shown so this probe never mangles its own output)[/]")


# ── 4. X-02: one Console factory that honours NO_COLOR + reduced motion ───
def console_factory() -> tuple[Console, bool]:
    no_color = bool(os.environ.get("NO_COLOR"))
    reduced_motion = os.environ.get("SECOPS_REDUCED_MOTION") == "1"
    console = Console(force_terminal=True, no_color=no_color)
    return console, reduced_motion


def main() -> None:
    console, reduced_motion = console_factory()
    console.print(
        f"[bold]probe[/]  rich Console  no_color={console.no_color}  "
        f"reduced_motion={reduced_motion}  width={console.width}"
    )
    render_badges(console)
    render_scan_progress(console)
    emit_osc_progress(console)
    console.rule("[bold green]all four probes rendered without error")


if __name__ == "__main__":
    main()
