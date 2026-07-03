"""Autonomy policy — how much the agent does without pausing for the user.

This is the first-class home for the decision sketched by the legacy
``allow_automatic_planner_execution`` flag. See ``docs/ARCHITECTURE.md`` §7.

Default: *semi-autonomous by risk*. Low-risk reconnaissance/enumeration runs
autonomously; exploitation/destructive actions pause for approval and their tool
schemas are withheld from the model until a plan is approved. The policy adapts
to the environment: trusted lab/CTF contexts escalate to *supervised* autonomy.

Invariant: this layer only decides *when to pause* and *what schemas to expose*.
It never authorises execution — the PermissionEngine remains the gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secops_agent.core.request_context import (
    EnvironmentHint,
    RequestDecision,
    RequestRisk,
    UserIntent,
)


class AutonomyLevel(str, Enum):
    COPILOT = "copilot"        # pause before every action
    RISK_BASED = "risk_based"  # default: act on low-risk, pause on high-risk
    SUPERVISED = "supervised"  # pause at destructive actions / phase transitions
    SANDBOX = "sandbox"        # act freely within scope (authorised lab/CTF)


_HIGH_RISK = frozenset({RequestRisk.EXPLOIT, RequestRisk.DESTRUCTIVE})
_APPROVED_INTENTS = frozenset({UserIntent.APPROVED_BATCH, UserIntent.EXECUTE_SELECTED})


@dataclass(frozen=True)
class AutonomyPolicy:
    """Decides how much the agent does without pausing for the user."""

    level: AutonomyLevel = AutonomyLevel.RISK_BASED

    @classmethod
    def for_environment(cls, hint: EnvironmentHint) -> "AutonomyPolicy":
        """Adaptive default: trusted lab/CTF escalates to supervised autonomy."""
        if hint in (EnvironmentHint.CTF_ONLINE, EnvironmentHint.PRIVATE_LAB):
            return cls(level=AutonomyLevel.SUPERVISED)
        return cls(level=AutonomyLevel.RISK_BASED)

    def exposes_tool_schemas(self, decision: RequestDecision) -> bool:
        """Whether high-risk tool schemas may be sent to the model this turn.

        Low-risk goals always expose their schemas. Exploitation/destructive
        schemas are withheld until the user has approved a plan, except in an
        explicit sandbox context.
        """
        if decision.risk not in _HIGH_RISK:
            return True
        if self.level == AutonomyLevel.SANDBOX:
            return True
        return decision.user_intent in _APPROVED_INTENTS

    def pauses_for(self, risk: RequestRisk) -> bool:
        """Whether an action of this risk must pause for explicit approval."""
        if self.level == AutonomyLevel.SANDBOX:
            return False
        if self.level == AutonomyLevel.COPILOT:
            return True
        if self.level == AutonomyLevel.SUPERVISED:
            return risk == RequestRisk.DESTRUCTIVE
        return risk in _HIGH_RISK  # RISK_BASED (default)

    @property
    def label(self) -> str:
        """Short human-readable posture label for the statusline (G4).

        Display only — surfacing the posture must never change what
        exposes_tool_schemas()/pauses_for() decide.
        """
        return {
            AutonomyLevel.COPILOT: "copilote",
            AutonomyLevel.RISK_BASED: "semi-auto",
            AutonomyLevel.SUPERVISED: "supervisé",
            AutonomyLevel.SANDBOX: "sandbox",
        }.get(self.level, self.level.value)
