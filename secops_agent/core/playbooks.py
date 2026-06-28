"""
Controlled technical playbooks derived from reviewed experience.

Playbooks are structured proposals. They do not execute tools, bypass scope, or
skip the existing permission flow. Creation is gated by reviewed lessons,
passing replay scores, and enough successful suggestion signals.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from secops_agent.core.experience import (
    CaseLesson,
    SuggestionSignal,
    _lesson_required_access,
    _normalize_required_access,
    _normalize_risk_class,
    _risk_band,
)
from secops_agent.core.planner import NextAction
from secops_agent.core.replay_evaluation import (
    LearningGateDecision,
    ReplayScore,
    evaluate_learning_gate,
)


PLAYBOOK_SAFETY_CONSTRAINTS = (
    "proposal_only",
    "requires_user_selection",
    "normal_permission_flow",
    "respect_scope_guard",
    "evidence_bound",
    "no_automatic_execution",
)


@dataclass(frozen=True)
class TechnicalPlaybook:
    """A gated, proposal-only reusable technical procedure."""

    title: str
    source_lesson_id: str
    tool_name: str = ""
    method: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    prerequisites: tuple[str, ...] = ()
    service_fingerprints: tuple[str, ...] = ()
    endpoint_hints: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    replay_scenarios: tuple[str, ...] = ()
    risk_class: str = ""
    required_access: str = ""
    matched_successes: int = 0
    confidence: float = 0.0
    safety_constraints: tuple[str, ...] = PLAYBOOK_SAFETY_CONSTRAINTS
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        object.__setattr__(self, "risk_class", _normalize_risk_class(self.risk_class))
        object.__setattr__(
            self,
            "required_access",
            _normalize_required_access(self.required_access),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "source_lesson_id": self.source_lesson_id,
            "tool_name": self.tool_name,
            "method": self.method,
            "arguments": dict(self.arguments),
            "prerequisites": list(self.prerequisites),
            "service_fingerprints": list(self.service_fingerprints),
            "endpoint_hints": list(self.endpoint_hints),
            "evidence_refs": list(self.evidence_refs),
            "replay_scenarios": list(self.replay_scenarios),
            "risk_class": self.risk_class,
            "required_access": self.required_access,
            "matched_successes": self.matched_successes,
            "confidence": self.confidence,
            "safety_constraints": list(self.safety_constraints),
        }

    def to_next_action(self, *, priority: int = 0) -> NextAction:
        """Expose the playbook as a proposal that still needs user action."""
        return NextAction(
            title=f"Use playbook: {self.title}",
            rationale=(
                "Reviewed technical playbook proposal. It still requires user "
                "selection, normal permission checks, scope validation, and "
                "current evidence."
            ),
            priority=priority,
            phase="proposal",
            tool_name=self.tool_name,
            arguments=dict(self.arguments),
            risk=_playbook_action_risk(self.risk_class),
            requires_approval=True,
            method=self.method,
            prerequisites=list(self.prerequisites),
            evidence=list(self.evidence_refs[:3]),
            experience=[f"controlled playbook from reviewed lesson: {self.source_lesson_id}"],
            experience_details=[
                {
                    "effect": "playbook-proposal",
                    "reason": "reviewed lesson passed replay and signal gates",
                    "why_matches": [
                        f"replays: {', '.join(self.replay_scenarios[:3])}",
                        f"success signals: {self.matched_successes}",
                    ],
                    "missing_evidence": [
                        "user approval still required",
                        "scope and permission checks still apply",
                    ],
                }
            ],
        )


@dataclass(frozen=True)
class PlaybookBuildResult:
    """Result of attempting to promote a lesson into a playbook."""

    playbook: TechnicalPlaybook | None
    decision: LearningGateDecision
    reasons: tuple[str, ...]

    @property
    def eligible(self) -> bool:
        return self.playbook is not None and not self.reasons


def build_technical_playbook(
    lesson: CaseLesson,
    replay_scores: Iterable[ReplayScore],
    *,
    signals: Iterable[SuggestionSignal] = (),
    min_successes: int = 2,
) -> PlaybookBuildResult:
    """Build a proposal-only playbook when all safety gates pass."""
    scores = list(replay_scores or [])
    decision = evaluate_learning_gate(
        lesson,
        scores,
        signals=signals,
        min_successes=min_successes,
    )
    reasons = list(decision.reasons)

    if not lesson.action_tool_name and not lesson.action_method:
        reasons.append("lesson has no reusable action family")

    evidence_refs = _playbook_evidence_refs(lesson)
    if not evidence_refs:
        reasons.append("lesson has no evidence references")

    if reasons:
        return PlaybookBuildResult(
            playbook=None,
            decision=decision,
            reasons=tuple(reasons),
        )

    playbook = TechnicalPlaybook(
        title=lesson.title,
        source_lesson_id=lesson.id,
        tool_name=lesson.action_tool_name,
        method=lesson.action_method,
        arguments=dict(lesson.action_arguments),
        prerequisites=tuple(lesson.prerequisites),
        service_fingerprints=tuple(lesson.service_fingerprints),
        endpoint_hints=tuple(lesson.endpoint_hints),
        evidence_refs=tuple(evidence_refs),
        replay_scenarios=tuple(score.scenario for score in scores if score.passed),
        risk_class=_playbook_risk_class(lesson),
        required_access=_lesson_required_access(lesson),
        matched_successes=decision.matched_successes,
        confidence=_playbook_confidence(lesson, decision),
    )
    return PlaybookBuildResult(
        playbook=playbook,
        decision=decision,
        reasons=(),
    )


def _playbook_evidence_refs(lesson: CaseLesson) -> list[str]:
    refs = list(lesson.evidence_refs or [])
    refs.extend(item for item in lesson.evidence if item not in refs)
    return [item for item in refs if str(item or "").strip()]


def _playbook_confidence(lesson: CaseLesson, decision: LearningGateDecision) -> float:
    base = max(0.0, min(1.0, float(lesson.confidence or 0.0)))
    bonus = min(0.2, max(0, decision.matched_successes - 1) * 0.05)
    return round(min(0.95, base + bonus), 4)


def _playbook_risk_class(lesson: CaseLesson) -> str:
    risk_class = _normalize_risk_class(lesson.risk_class)
    if risk_class:
        return risk_class
    try:
        from secops_agent.core.tools import _BUILTIN_TOOL_RISK_CLASSES

        inferred = _BUILTIN_TOOL_RISK_CLASSES.get(str(lesson.action_tool_name or ""))
        return _normalize_risk_class(getattr(inferred, "value", "") or inferred)
    except Exception:
        return ""


def _playbook_action_risk(risk_class: str) -> str:
    return _risk_band(risk_class) or "medium"
