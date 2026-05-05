"""Model profiles and routing helpers for Gemini/Gemma-backed reasoning."""

from dataclasses import dataclass


DEFAULT_MODEL = "gemini-2.5-flash"
GEMMA_FAST_MODEL = "gemma-4-26b-a4b-it"
GEMMA_STRATEGY_MODEL = "gemma-4-31b-it"


@dataclass(frozen=True)
class ModelProfile:
    name: str
    model: str
    max_prompt_chars: int = 18000
    max_system_chars: int = 9000
    max_transcript_messages: int = 8
    max_message_chars: int = 900
    max_tool_description_chars: int = 150
    max_argument_description_chars: int = 70
    max_output_tokens: int | None = 1200
    temperature: float | None = 0.2
    thinking_level: str = ""
    native_tool_calling: bool = False
    description: str = ""


MODEL_PROFILES = {
    DEFAULT_MODEL: ModelProfile(
        name="gemini",
        model=DEFAULT_MODEL,
        description="Modele actuel par defaut.",
    ),
    GEMMA_FAST_MODEL: ModelProfile(
        name="gemma",
        model=GEMMA_FAST_MODEL,
        max_prompt_chars=14000,
        max_system_chars=7000,
        max_transcript_messages=6,
        max_message_chars=750,
        max_output_tokens=1000,
        temperature=0.15,
        thinking_level="low",
        native_tool_calling=True,
        description="Gemma via Gemini API, bon candidat pour comparer le quota.",
    ),
    GEMMA_STRATEGY_MODEL: ModelProfile(
        name="gemma-31b",
        model=GEMMA_STRATEGY_MODEL,
        max_prompt_chars=22000,
        max_system_chars=11000,
        max_transcript_messages=10,
        max_message_chars=1000,
        max_output_tokens=1800,
        temperature=0.2,
        thinking_level="high",
        native_tool_calling=True,
        description="Gemma plus large pour strategie, pivot et reporting.",
    ),
}


MODEL_ALIASES = {
    "auto": "auto",
    "flash": DEFAULT_MODEL,
    "gemini": DEFAULT_MODEL,
    "gemini-flash": DEFAULT_MODEL,
    "gemma": GEMMA_FAST_MODEL,
    "gemma-4": GEMMA_FAST_MODEL,
    "gemma-fast": GEMMA_FAST_MODEL,
    "gemma-26b": GEMMA_FAST_MODEL,
    "gemma-31b": GEMMA_STRATEGY_MODEL,
}


MODEL_PRESETS = (
    ("auto", "routage automatique", "choisit Gemma 26B ou 31B selon l'objectif"),
    ("gemini", DEFAULT_MODEL, MODEL_PROFILES[DEFAULT_MODEL].description),
    ("gemma", GEMMA_FAST_MODEL, MODEL_PROFILES[GEMMA_FAST_MODEL].description),
    ("gemma-31b", GEMMA_STRATEGY_MODEL, MODEL_PROFILES[GEMMA_STRATEGY_MODEL].description),
)


STRATEGY_MARKERS = (
    "analyse profonde",
    "benchmark",
    "compare",
    "corrige tout",
    "feuille de route",
    "full pentest",
    "plan d'action",
    "plan d’attaque",
    "plan d'attaque",
    "pivote",
    "pourquoi",
    "rapport",
    "strategie",
    "stratégie",
    "synthese",
    "synthèse",
    "trouve le flag",
)


def resolve_model_name(raw_model: str) -> str:
    candidate = (raw_model or "").strip()
    if not candidate:
        return ""
    normalized = candidate.casefold()
    if normalized in MODEL_ALIASES:
        return MODEL_ALIASES[normalized]
    if normalized.startswith(("gemini-", "gemma-")):
        return candidate
    return ""


def get_model_profile(model: str) -> ModelProfile:
    if model in MODEL_PROFILES:
        return MODEL_PROFILES[model]
    native_tool_calling = model.startswith("gemma-")
    return ModelProfile(
        name=model,
        model=model,
        native_tool_calling=native_tool_calling,
        thinking_level="low" if native_tool_calling else "",
        description="Modele personnalise.",
    )


def route_model(prompt: str, phase: str = "") -> str:
    lowered = (prompt or "").casefold()
    if phase == "reporting":
        return GEMMA_STRATEGY_MODEL
    if any(marker in lowered for marker in STRATEGY_MARKERS):
        return GEMMA_STRATEGY_MODEL
    return GEMMA_FAST_MODEL
