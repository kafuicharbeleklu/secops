"""Interactive model selection overlay.

One row per model (never one row per model×reasoning combo): the reasoning
level of the focused model is toggled inline with ←/→, the way Claude Code's
picker works. The picker returns ``(model, thinking_level)`` so the caller sets
both at once.
"""

from __future__ import annotations

from typing import Optional

from secops_agent.core.model_catalog import (
    MODEL_PRESETS,
    get_model_profile,
    normalize_thinking_level,
)
from secops_agent.ui.overlay import OverlayChoice, choose_overlay

MODEL_PICKER_FOOTER = "Keyboard: ↑/↓ Navigate  ←/→ Reasoning  enter Select  esc Go Back"

# Reasoning ramps offered per family. Gemma 4 only exposes off/high through the
# hosted API (see model_supports_thinking_level); Gemini thinking models take
# the full ramp. Non-thinking models expose no reasoning control at all.
_GEMINI_REASONING = ("off", "low", "medium", "high")
_GEMMA_REASONING = ("off", "high")


def model_reasoning_levels(model: str) -> tuple[str, ...]:
    """Selectable reasoning levels for a model, or () when it has no thinking."""
    profile = get_model_profile(model)
    if not profile.supports_thinking:
        return ()
    return _GEMMA_REASONING if model.startswith("gemma-4-") else _GEMINI_REASONING


def cycle_reasoning(levels: tuple[str, ...], current: str, direction: str) -> str:
    """Step the reasoning level left/right within *levels*, wrapping around."""
    if not levels:
        return current
    index = levels.index(current) if current in levels else 0
    step = 1 if direction == "right" else -1
    return levels[(index + step) % len(levels)]


def _unique_models(models: list[str]) -> tuple[list[str], dict[str, str]]:
    """Unique model ids in preset order (reasoning duplicates folded away), with
    a one-line description per model taken from its first preset."""
    ordered: list[str] = []
    descriptions: dict[str, str] = {}
    for preset in MODEL_PRESETS:
        if preset.alias == "auto":
            continue
        descriptions.setdefault(preset.model, preset.description)
        if preset.model not in ordered:
            ordered.append(preset.model)
    for model in models:
        if model not in ordered:
            ordered.append(model)
    return ordered, descriptions


def _model_choices(
    models: list[str],
    current_model: str,
    *,
    auto_routing: bool = False,
    current_thinking: str = "",
    include_auto: bool = False,
) -> list[OverlayChoice]:
    """One OverlayChoice per unique model. Reasoning is handled by the ←/→ toggle,
    so a model is no longer duplicated for each reasoning level."""
    ordered, descriptions = _unique_models(models)
    return [
        OverlayChoice(
            value=model,
            label=get_model_profile(model).label,
            description=descriptions.get(model, ""),
            current=model == current_model,
        )
        for model in ordered
    ]


def _initial_reasoning(
    model: str,
    levels: tuple[str, ...],
    *,
    current_model: str,
    current_thinking: str,
) -> str:
    """The reasoning level a model's row starts on: the live level for the active
    model, otherwise the model's own default, clamped to its allowed ramp."""
    if not levels:
        return ""
    if model == current_model:
        candidate = normalize_thinking_level(current_thinking) or "off"
    else:
        candidate = normalize_thinking_level(get_model_profile(model).thinking_level) or "off"
    return candidate if candidate in levels else levels[0]


def switch_model_menu(
    models: list[str],
    current_model: str,
    *,
    auto_routing: bool = False,
    current_thinking: str = "",
    prompt_frame: bool = False,
) -> Optional[tuple[str, str | None]]:
    """Open the model picker. Returns ``(model, thinking_level)`` on selection
    (``thinking_level`` is ``None`` for models with no reasoning control), or
    ``None`` if the picker is dismissed."""
    choices = _model_choices(
        models,
        current_model,
        auto_routing=auto_routing,
        current_thinking=current_thinking,
    )
    if not choices:
        return None

    levels_for = {choice.value: model_reasoning_levels(choice.value) for choice in choices}
    chosen = {
        choice.value: _initial_reasoning(
            choice.value,
            levels_for[choice.value],
            current_model=current_model,
            current_thinking=current_thinking,
        )
        for choice in choices
    }

    def suffix_provider(index: int) -> str:
        value = choices[index].value
        if not levels_for[value]:
            return ""
        return f"   reasoning ‹ {chosen[value]} ›"

    def on_horizontal(index: int, direction: str) -> None:
        value = choices[index].value
        levels = levels_for[value]
        if levels:
            chosen[value] = cycle_reasoning(levels, chosen[value], direction)

    current_label = next(
        (choice.label for choice in choices if choice.current),
        get_model_profile(current_model).label,
    )
    value = choose_overlay(
        "Switch Model",
        choices,
        status_right=current_label,
        prompt_frame=prompt_frame,
        current_marker_column=29,
        visible_items=5,
        footer=MODEL_PICKER_FOOTER,
        on_horizontal=on_horizontal,
        suffix_provider=suffix_provider,
    )
    if value is None:
        return None
    return value, (chosen.get(value) or None)
