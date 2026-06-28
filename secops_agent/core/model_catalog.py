"""
Model profiles and routing helpers — updated from live API response.
"""

from __future__ import annotations

from dataclasses import dataclass


# ── Core models ───────────────────────────────────────────────────────────────
DEFAULT_MODEL         = "gemini-2.5-flash"
GEMINI_25_PRO         = "gemini-2.5-pro"
GEMINI_35_FLASH       = "gemini-3.5-flash"
GEMINI_3_FLASH        = "gemini-3-flash-preview"
GEMINI_3_PRO          = "gemini-3-pro-preview"
GEMINI_31_PRO         = "gemini-3.1-pro-preview"
GEMINI_31_FLASH_LITE  = "gemini-3.1-flash-lite"
GEMINI_20_FLASH       = "gemini-2.0-flash"
GEMMA_FAST_MODEL      = "gemma-4-26b-a4b-it"   # MoE 26B active / experimental
GEMMA_STRATEGY_MODEL  = "gemma-4-31b-it"


@dataclass(frozen=True)
class ModelProfile:
    name: str
    model: str
    label: str
    max_output_tokens: int | None = None
    temperature: float | None = None
    thinking_level: str = ""
    supports_thinking: bool = False
    native_tool_calling: bool = False
    supports_image_input: bool = False
    supports_google_search: bool = False
    description: str = ""
    best_for: str = ""


@dataclass(frozen=True)
class ModelSelection:
    model: str
    thinking_level: str | None = None


@dataclass(frozen=True)
class ModelPreset:
    alias: str
    model: str
    label: str
    thinking_level: str | None
    description: str


MODEL_PROFILES: dict[str, ModelProfile] = {
    DEFAULT_MODEL: ModelProfile(
        name="gemini-flash",
        model=DEFAULT_MODEL,
        label="Gemini 2.5 Flash",
        supports_image_input=True,
        supports_google_search=True,
        description="Stable version of Gemini 2.5 Flash — rapide, stable, recommande par defaut.",
        best_for="recon, command planning, responsive chat, tool chaining",
    ),
    GEMINI_25_PRO: ModelProfile(
        name="gemini-pro",
        model=GEMINI_25_PRO,
        label="Gemini 2.5 Pro",
        supports_thinking=True,
        supports_image_input=True,
        supports_google_search=True,
        description="Stable release of Gemini 2.5 Pro — analyse profonde, contextes complexes.",
        best_for="deep analysis, privilege escalation chains, complex reporting, CVE research",
    ),
    GEMINI_35_FLASH: ModelProfile(
        name="gemini-3.5-flash",
        model=GEMINI_35_FLASH,
        label="Gemini 3.5 Flash",
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 3.5 Flash — generation suivante stable, rapide et performant.",
        best_for="general pentesting, recon, enumeration, fast responses",
    ),
    GEMINI_3_FLASH: ModelProfile(
        name="gemini-3-flash",
        model=GEMINI_3_FLASH,
        label="Gemini 3 Flash Preview",
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 3 Flash Preview — acces anticipe a la generation 3.",
        best_for="testing, preview features, recon",
    ),
    GEMINI_3_PRO: ModelProfile(
        name="gemini-3-pro",
        model=GEMINI_3_PRO,
        label="Gemini 3 Pro Preview",
        supports_thinking=True,
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 3 Pro Preview — modele Pro generation 3, tres capable.",
        best_for="strategy, exploit research, post-exploitation, final reports",
    ),
    GEMINI_20_FLASH: ModelProfile(
        name="gemini-2.0-flash",
        model=GEMINI_20_FLASH,
        label="Gemini 2.0 Flash",
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 2.0 Flash — stable, leger, faible latence.",
        best_for="lightweight tasks, simple queries, low-latency tool calls",
    ),
    GEMMA_FAST_MODEL: ModelProfile(
        name="gemma",
        model=GEMMA_FAST_MODEL,
        label="Gemma 4 26B A4B IT",
        thinking_level="",
        supports_thinking=True,
        native_tool_calling=True,
        supports_image_input=True,
        supports_google_search=True,
        description="Gemma 4 26B A4B IT — MoE experimental via Gemini API, peut etre instable.",
        best_for="local-style reasoning, native tool calling experiments",
    ),
    GEMMA_STRATEGY_MODEL: ModelProfile(
        name="gemma-31b",
        model=GEMMA_STRATEGY_MODEL,
        label="Gemma 4 31B IT",
        thinking_level="high",
        supports_thinking=True,
        native_tool_calling=True,
        supports_image_input=True,
        supports_google_search=True,
        description="Gemma 4 31B IT — avec thinking pour strategie et reporting.",
        best_for="strategy, pivot analysis, structured reporting",
    ),
    GEMINI_31_PRO: ModelProfile(
        name="gemini-3.1-pro",
        model=GEMINI_31_PRO,
        label="Gemini 3.1 Pro Preview",
        supports_thinking=True,
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 3.1 Pro Preview — modele de pointe de la generation 3.1.",
        best_for="complex analysis, privilege escalation, planning",
    ),
    GEMINI_31_FLASH_LITE: ModelProfile(
        name="gemini-3.1-flash-lite",
        model=GEMINI_31_FLASH_LITE,
        label="Gemini 3.1 Flash Lite",
        supports_image_input=True,
        supports_google_search=True,
        description="Gemini 3.1 Flash Lite — version ultra-legere et rapide de la generation 3.1.",
        best_for="simple recon, low-latency tasks",
    ),
}


MODEL_ALIASES: dict[str, str] = {
    "auto":            "auto",
    "default":         DEFAULT_MODEL,
    "defaut":          DEFAULT_MODEL,
    "flash":           DEFAULT_MODEL,
    "gemini":          DEFAULT_MODEL,
    "gemini-flash":    DEFAULT_MODEL,
    "gemini-2.5":      DEFAULT_MODEL,
    "gemini-25-flash": DEFAULT_MODEL,
    # Gemini 2.5 Pro
    "pro":             GEMINI_25_PRO,
    "gemini-pro":      GEMINI_25_PRO,
    "gemini-2.5-pro":  GEMINI_25_PRO,
    "25-pro":          GEMINI_25_PRO,
    # Gemini 3.5 Flash
    "gemini-3.5":          GEMINI_35_FLASH,
    "gemini-3.5-flash":    GEMINI_35_FLASH,
    "flash-3.5":           GEMINI_35_FLASH,
    # Gemini 3 Flash Preview
    "gemini-3":            GEMINI_3_FLASH,
    "gemini-3-flash":      GEMINI_3_FLASH,
    "3-flash":             GEMINI_3_FLASH,
    # Gemini 3 Pro Preview
    "gemini-3-pro":        GEMINI_3_PRO,
    "3-pro":               GEMINI_3_PRO,
    # Gemini 2.0 Flash
    "gemini-2.0":          GEMINI_20_FLASH,
    "gemini-2.0-flash":    GEMINI_20_FLASH,
    "2.0-flash":           GEMINI_20_FLASH,
    # Gemma
    "gemma":           GEMMA_FAST_MODEL,
    "gemma-4":         GEMMA_FAST_MODEL,
    "gemma-fast":      GEMMA_FAST_MODEL,
    "gemma-26b":       GEMMA_FAST_MODEL,
    "gemma-high":      GEMMA_FAST_MODEL,
    "gemma-26b-high":  GEMMA_FAST_MODEL,
    "gemma-thinking":  GEMMA_FAST_MODEL,
    "gemma-31b":       GEMMA_STRATEGY_MODEL,
    "gemma-31b-high":  GEMMA_STRATEGY_MODEL,
    "gemma-31b-off":   GEMMA_STRATEGY_MODEL,
    # Gemini 3.1 Pro
    "gemini-3.1-pro":      GEMINI_31_PRO,
    "3.1-pro":             GEMINI_31_PRO,
    # Gemini 3.1 Flash Lite
    "gemini-3.1-flash-lite": GEMINI_31_FLASH_LITE,
    "3.1-flash-lite":      GEMINI_31_FLASH_LITE,
}


MODEL_ALIAS_THINKING: dict[str, str | None] = {
    "default":         "default",
    "defaut":          "default",
    "flash":           "default",
    "gemini":          "default",
    "gemini-flash":    "default",
    "gemini-2.5":      "default",
    "gemini-25-flash": "default",
    "pro":             "default",
    "gemini-pro":      "default",
    "gemini-2.5-pro":  "default",
    "25-pro":          "default",
    "gemini-3.5":          "default",
    "gemini-3.5-flash":    "default",
    "flash-3.5":           "default",
    "gemini-3":            "default",
    "gemini-3-flash":      "default",
    "3-flash":             "default",
    "gemini-3-pro":        "default",
    "3-pro":               "default",
    "gemini-2.0":          "default",
    "gemini-2.0-flash":    "default",
    "2.0-flash":           "default",
    "gemma":           "default",
    "gemma-4":         "default",
    "gemma-fast":      "default",
    "gemma-26b":       "default",
    "gemma-high":      "high",
    "gemma-26b-high":  "high",
    "gemma-thinking":  "high",
    "gemma-31b":       "default",
    "gemma-31b-high":  "default",
    "gemma-31b-off":   "off",
    "gemini-3.1-pro":  "default",
    "3.1-pro":         "default",
    "gemini-3.1-flash-lite": "default",
    "3.1-flash-lite":  "default",
}


MODEL_PRESETS: tuple[ModelPreset, ...] = (
    ModelPreset("auto",          "auto",          "Auto",                    None,    "choisit le modele optimal selon l'objectif"),
    # ── Gemini stable ────────────────────────────────────────────────────────
    ModelPreset("gemini",        DEFAULT_MODEL,   "Gemini 2.5 Flash",        None,    "Defaut (Free Tier) — rapide, stable, tool calling"),
    ModelPreset("pro",           GEMINI_25_PRO,   "Gemini 2.5 Pro",          None,    "Plan Payant recommande (quotas Pro) — analyse profonde"),
    # ── Gemini next-gen ──────────────────────────────────────────────────────
    ModelPreset("gemini-3.5",    GEMINI_35_FLASH, "Gemini 3.5 Flash",        None,    "Gen suivante (Free Tier) — rapide, recommande pour pentest"),
    ModelPreset("gemini-3-pro",  GEMINI_3_PRO,    "Gemini 3 Pro Preview",    None,    "Gen 3 Pro (Plan Payant) — strategie, rapports"),
    ModelPreset("gemini-3.1-pro", GEMINI_31_PRO,  "Gemini 3.1 Pro Preview",  None,    "Gen 3.1 Pro (Plan Payant) — raisonnement de pointe"),
    ModelPreset("gemini-3.1-flash-lite", GEMINI_31_FLASH_LITE, "Gemini 3.1 Flash Lite", None, "Gen 3.1 Flash Lite (Free Tier) — rapide, economique"),
    ModelPreset("gemini-3",      GEMINI_3_FLASH,  "Gemini 3 Flash Preview",  None,    "Gen 3 Flash preview (Free Tier)"),
    # ── Gemini legacy ────────────────────────────────────────────────────────
    ModelPreset("gemini-2.0",    GEMINI_20_FLASH, "Gemini 2.0 Flash",        None,    "Leger (Free Tier) — faible latence, taches simples"),
    # ── Gemma (experimental) ─────────────────────────────────────────────────────
    ModelPreset("gemma",         GEMMA_FAST_MODEL,     "Gemma 4 26B A4B IT (Off)",  None,    "Open-weights (Apache 2.0) — MoE experimental"),
    ModelPreset("gemma-high",    GEMMA_FAST_MODEL,     "Gemma 4 26B A4B IT (High)", "high",  "Open-weights (Apache 2.0) — MoE avec thinking"),
    ModelPreset("gemma-31b-off", GEMMA_STRATEGY_MODEL, "Gemma 4 31B IT (Off)",      "off",   "Open-weights (Apache 2.0) — Gemma 4 31B sans thinking"),
    ModelPreset("gemma-31b",     GEMMA_STRATEGY_MODEL, "Gemma 4 31B IT (High)",     None,    "Open-weights (Apache 2.0) — Gemma 4 31B avec thinking"),
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


THINKING_LEVEL_ORDER = {
    "off": 0,
    "minimal": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "max": 4,
}

THINKING_LEVEL_BY_SCORE = {
    0: "",
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
}


def resolve_model_name(raw_model: str) -> str:
    selection = resolve_model_selection(raw_model)
    return selection.model if selection else ""


def resolve_model_selection(raw_model: str) -> ModelSelection | None:
    candidate = (raw_model or "").strip()
    if not candidate:
        return None
    normalized = candidate.casefold()
    if normalized in MODEL_ALIASES:
        return ModelSelection(
            MODEL_ALIASES[normalized],
            MODEL_ALIAS_THINKING.get(normalized),
        )
    if normalized.startswith(("gemini-", "gemma-")):
        return ModelSelection(candidate, None)
    return None


def get_model_profile(model: str) -> ModelProfile:
    if model in MODEL_PROFILES:
        return MODEL_PROFILES[model]
    native_tool_calling = model.startswith("gemma-")
    hosted_google_model = model.startswith(("gemini-", "gemma-"))
    return ModelProfile(
        name=model,
        model=model,
        label=model,
        native_tool_calling=native_tool_calling,
        supports_image_input=hosted_google_model,
        supports_google_search=hosted_google_model,
        thinking_level="",
        supports_thinking=False,
        description="Modele personnalise.",
        best_for="custom Gemini/Gemma model",
    )


def route_model(prompt: str, phase: str = "") -> str:
    lowered = (prompt or "").casefold()
    if phase == "reporting":
        return GEMMA_STRATEGY_MODEL
    if any(marker in lowered for marker in STRATEGY_MARKERS):
        return GEMMA_STRATEGY_MODEL
    return GEMMA_FAST_MODEL


def adaptive_thinking_level(
    profile: ModelProfile,
    *,
    prompt: str = "",
    phase: str = "",
    context: dict | None = None,
) -> str:
    if not profile.supports_thinking:
        return ""

    context = context or {}
    if profile.model.startswith("gemma-4-"):
        return normalize_thinking_level(profile.thinking_level)

    base = normalize_thinking_level(profile.thinking_level) or "low"
    score = THINKING_LEVEL_ORDER.get(base, 2)
    lowered = str(prompt or "").casefold()
    phase = str(phase or context.get("phase") or "").casefold()

    if phase in {"exploitation", "post_exploitation", "reporting"}:
        score = max(score, 3)
    if phase == "reporting":
        score = max(score, 4)
    if any(marker in lowered for marker in STRATEGY_MARKERS):
        score = max(score, 4)
    if any(marker in lowered for marker in ("autonome", "full pentest", "jusqu'au flag")):
        score = max(score, 4)
    if any(marker in lowered for marker in ("pourquoi", "compare", "analyse", "corrige", "plan")):
        score = max(score, 3)
    if context.get("blocked_reason") or int(context.get("failed_commands", 0) or 0):
        score = max(score, 4)
    if int(context.get("findings_count", 0) or 0) >= 3:
        score = max(score, 3)
    if int(context.get("tool_budget", 1) or 1) > 1:
        score = max(score, 3)

    return THINKING_LEVEL_BY_SCORE.get(min(max(score, 0), 4), "low")


def normalize_thinking_level(level: str) -> str:
    normalized = str(level or "").strip().casefold()
    if normalized in {"", "default"}:
        return ""
    if normalized == "max":
        return "high"
    if normalized == "minimal":
        return "low"
    if normalized in {"off", "low", "medium", "high"}:
        return normalized
    return ""


def model_display_name(model_name: str) -> str:
    return get_model_profile(model_name).label


def selectable_models() -> list[str]:
    values = []
    for preset in MODEL_PRESETS:
        if preset.alias == "auto":
            continue
        if preset.model not in values:
            values.append(preset.model)
    return values


def completion_values() -> list[str]:
    values = [preset.alias for preset in MODEL_PRESETS]
    values.extend(model for model in selectable_models() if model not in values)
    return values


def preset_effective_thinking(preset: ModelPreset) -> str:
    if preset.thinking_level == "off":
        return ""
    if preset.thinking_level:
        return normalize_thinking_level(preset.thinking_level)
    return normalize_thinking_level(get_model_profile(preset.model).thinking_level)


def model_supports_thinking_level(model: str, thinking_level: str) -> bool:
    normalized = normalize_thinking_level(thinking_level)
    if not model.startswith("gemma-4-"):
        return True
    return normalized in {"", "off", "high"}
