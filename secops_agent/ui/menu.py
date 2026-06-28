"""
Interactive model selection overlay.
"""

from __future__ import annotations

from typing import Optional

from secops_agent.core.model_catalog import MODEL_PRESETS, get_model_profile, preset_effective_thinking
from secops_agent.ui.overlay import OverlayChoice, choose_overlay


def _normalized_current_thinking(current_thinking: str) -> str:
    return "" if str(current_thinking or "").strip().casefold() in {"", "off", "default"} else current_thinking


def _model_choices(
    models: list[str],
    current_model: str,
    *,
    auto_routing: bool = False,
    current_thinking: str = "",
    include_auto: bool = False,
) -> list[OverlayChoice]:
    choices = []
    active_thinking = _normalized_current_thinking(current_thinking)
    for preset in MODEL_PRESETS:
        if preset.alias == "auto" and not include_auto:
            continue
        preset_thinking = preset_effective_thinking(preset)
        choices.append(
            OverlayChoice(
                value=preset.alias,
                label=preset.label,
                description=preset.description,
                current=(
                    preset.alias == "auto" if auto_routing and include_auto
                    else preset.model == current_model and preset_thinking == active_thinking
                ),
            )
        )
    extra_models = [model for model in models if model not in {preset.model for preset in MODEL_PRESETS}]
    choices.extend([
        OverlayChoice(
            value=model,
            label=get_model_profile(model).label,
            description="active" if model == current_model else "",
            current=False if auto_routing else model == current_model,
        )
        for model in extra_models
    ])
    return choices


def switch_model_menu(
    models: list[str],
    current_model: str,
    *,
    auto_routing: bool = False,
    current_thinking: str = "",
    prompt_frame: bool = False,
) -> Optional[str]:
    choices = _model_choices(
        models,
        current_model,
        auto_routing=auto_routing,
        current_thinking=current_thinking,
    )
    current_label = next(
        (choice.label for choice in choices if choice.current),
        get_model_profile(current_model).label,
    )
    return choose_overlay(
        "Switch Model",
        choices,
        status_right=current_label,
        prompt_frame=prompt_frame,
        current_marker_column=29,
        visible_items=5,
    )
