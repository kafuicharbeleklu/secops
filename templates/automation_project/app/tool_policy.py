"""Central policy checks applied before tool dispatch."""

import re
from dataclasses import dataclass


_IP_TARGET_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"
)

_PHASE_ALIASES = {
    "recon": "recon",
    "reconnaissance": "recon",
    "enum": "enumeration",
    "enumeration": "enumeration",
    "exploit": "exploitation",
    "exploitation": "exploitation",
    "post": "post_exploitation",
    "post-exploit": "post_exploitation",
    "post_exploit": "post_exploitation",
    "post-exploitation": "post_exploitation",
    "post_exploitation": "post_exploitation",
    "rapport": "reporting",
    "report": "reporting",
    "reporting": "reporting",
}

_TARGET_ARGUMENT_KEYS = {
    "domain",
    "host",
    "rhost",
    "rhosts",
    "target",
    "target_ip",
    "target_url",
    "url",
}

_COMMAND_ARGUMENT_KEYS = {
    "command",
    "manual_command",
}


@dataclass(frozen=True)
class ToolPolicyDecision:
    allowed: bool
    reason: str = ""
    remediation: str = ""
    code: str = ""


class ToolPolicyError(ValueError):
    """Raised when central policy blocks a tool before execution."""

    def __init__(self, reason: str, *, remediation: str = "", code: str = ""):
        super().__init__(reason)
        self.remediation = remediation
        self.code = code


class ToolPolicy:
    """Evaluate phase, scope and risk constraints before a tool handler runs."""

    def __init__(self, *, placeholder_tokens=(), strict_phase_risks=None):
        self.placeholder_tokens = tuple(placeholder_tokens or ())
        self.strict_phase_risks = set(strict_phase_risks or {"high"})

    def evaluate(self, plugin, arguments, *, executor) -> ToolPolicyDecision:
        arguments = arguments if isinstance(arguments, dict) else {}

        placeholder = self._find_placeholder(arguments)
        if placeholder:
            return ToolPolicyDecision(
                False,
                (
                    f"Argument interdit pour {plugin.spec.name}: placeholder cible "
                    f"detecte ({placeholder}). Precise une cible reelle autorisee."
                ),
                (
                    "Remplace le placeholder par une cible fournie par l'utilisateur "
                    "ou definis la cible active avec /target <ip|url>."
                ),
                "placeholder_target",
            )

        phase_decision = self._evaluate_phase(plugin, executor)
        if not phase_decision.allowed:
            return phase_decision

        try:
            self._validate_scope(arguments, executor)
        except Exception as exc:
            if exc.__class__.__name__ == "ScopeViolationError":
                return ToolPolicyDecision(
                    False,
                    str(exc),
                    (
                        "Utilise une cible incluse dans le scope autorise ou ajuste le scope "
                        "avec /scope <ip|cidr|domaine|url> apres validation d'autorisation."
                    ),
                    "scope_violation",
                )
            raise
        return ToolPolicyDecision(True)

    def _evaluate_phase(self, plugin, executor) -> ToolPolicyDecision:
        phase = self._current_phase(executor)
        if not phase or not plugin.phases:
            return ToolPolicyDecision(True)

        allowed_phases = {
            self._normalize_phase(raw_phase)
            for raw_phase in plugin.phases
        }
        allowed_phases.discard("")
        if not allowed_phases or phase in allowed_phases:
            return ToolPolicyDecision(True)

        should_block = plugin.risk in self.strict_phase_risks or phase == "reporting"
        if not should_block:
            return ToolPolicyDecision(True)

        allowed_label = ", ".join(sorted(allowed_phases))
        return ToolPolicyDecision(
            False,
            (
                f"Outil {plugin.spec.name} bloque par la politique de phase: "
                f"phase actuelle {phase}, phase(s) autorisee(s): {allowed_label}."
            ),
            (
                "Choisis un outil compatible avec la phase actuelle ou change de phase "
                "avec /phase <phase> confirm apres avoir defini le scope requis."
            ),
            "phase_violation",
        )

    def _validate_scope(self, arguments, executor) -> None:
        if not getattr(executor, "authorized_scope", set()):
            return

        for key, value in self._walk_arguments(arguments):
            lowered = key.lower()
            text = str(value)
            if lowered in _COMMAND_ARGUMENT_KEYS:
                executor._validate_scope_in_command(text)
                continue
            if lowered in _TARGET_ARGUMENT_KEYS:
                executor._validate_scope(text)
                for ip_target in _IP_TARGET_RE.findall(text):
                    executor._validate_scope(ip_target)

    def _find_placeholder(self, value):
        for _, item in self._walk_arguments(value):
            text = str(item)
            text_lower = text.lower()
            for placeholder in self.placeholder_tokens:
                placeholder_text = str(placeholder)
                if placeholder_text in text or placeholder_text.lower() in text_lower:
                    return placeholder_text
        return ""

    def _walk_arguments(self, value, key=""):
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                yield from self._walk_arguments(child_value, str(child_key))
            return
        if isinstance(value, (list, tuple, set)):
            for child_value in value:
                yield from self._walk_arguments(child_value, key)
            return
        yield key, value

    def _current_phase(self, executor) -> str:
        engagement = getattr(executor, "_engagement", None)
        phase = getattr(engagement, "phase", None)
        value = getattr(phase, "value", phase)
        return self._normalize_phase(value)

    def _normalize_phase(self, value) -> str:
        normalized = str(value or "").strip().lower().replace(" ", "_")
        return _PHASE_ALIASES.get(normalized, normalized)
