#!/usr/bin/env python3
"""P4 contrast report — WCAG 2.1 contrast of every theme token on its tuned ground.

Prints, for each palette (8 dark + 1 light), the contrast ratio of each foreground
token against that palette's reference ground, plus the two composed surfaces that
carry their own background (the warning highlight and the diff-line tints). Every
row is labelled with the threshold for its role and PASS / low.

Thresholds (WCAG 2.1): body text >= 7.0, secondary/muted text and colour signals
>= 4.5, non-text UI (dividers, borders, large glyphs) >= 3.0. The light palette
documents that its warm/green signals cannot reach 4.5 on white and sit at the
non-text 3.0 floor as bold glyphs — those are reported against 3.0.

Run:  .venv/bin/python scratch/contrast_report.py
The enforcing regression guard is tests/test_contrast.py.
"""

from __future__ import annotations

import sys

from secops_agent.ui import theme as T

# token -> (role label, threshold) for the foreground-vs-ground rows.
_FG_ROLES = {
    "text": ("body", 7.0),
    "text_secondary": ("secondary", 4.5),
    "text_muted": ("muted", 4.5),
    "text_dim": ("non-text", 3.0),
    "accent": ("signal", 4.5),
    "accent_bright": ("signal", 4.5),
    "success": ("signal", 4.5),
    "warning": ("signal", 4.5),
    "error": ("signal", 4.5),
    "danger": ("signal", 4.5),
    "danger_bright": ("signal", 4.5),
    "tool_border": ("non-text", 3.0),
}

# Light-theme signals that the palette documents as non-text (3.0 floor) glyphs.
_LIGHT_NONTEXT = {"success", "warning", "accent_bright", "danger", "danger_bright"}


def _threshold(palette_name: str, token: str, default: float) -> float:
    if T.is_light_theme(palette_name) and token in _LIGHT_NONTEXT:
        return 3.0
    return default


def _row(label: str, fg: str, bg: str, threshold: float) -> tuple[str, bool]:
    ratio = T.contrast_ratio(fg, bg)
    ok = ratio >= threshold
    mark = "PASS" if ok else "low "
    return (f"  {label:26} {fg} on {bg}  {ratio:5.1f}:1  [>= {threshold:>3}]  {mark}", ok)


def report() -> int:
    lows = 0
    for name in T.available_themes():
        palette = T._PALETTES[name]
        ground = T.ground_for(name)
        kind = "light" if T.is_light_theme(name) else "dark"
        print(f"\nPalette: {name}  (ground {ground}, {kind})")
        # Foreground tokens vs the ground.
        for token, (role, default) in _FG_ROLES.items():
            if token not in palette:
                continue
            thr = _threshold(name, token, default)
            line, ok = _row(f"{token} [{role}]", palette[token], ground, thr)
            lows += not ok
            print(line)
        # Composed surfaces that carry their own background.
        line, ok = _row("on_warning / warning", palette["on_warning"], palette["warning"], 4.5)
        lows += not ok
        print(line)
        line, ok = _row("success / diff_add_bg", palette["success"], palette["diff_add_bg"], 3.0)
        lows += not ok
        print(line)
        line, ok = _row("error / diff_remove_bg", palette["error"], palette["diff_remove_bg"], 3.0)
        lows += not ok
        print(line)

    print(f"\n{'=' * 60}\nTokens below their role threshold: {lows}")
    return lows


if __name__ == "__main__":
    sys.exit(0 if report() == 0 else 0)  # a report, never a gate — see tests/test_contrast.py
