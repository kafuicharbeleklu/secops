"""
Auditable local case lessons for proposal ranking.

Lessons are not findings and do not authorize execution. They only annotate and
rank candidate next actions that the deterministic planner already generated
from current in-scope mission evidence.
"""

from __future__ import annotations

import json
import hashlib
import math
import re
import shutil
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from secops_agent.config import settings


_TOKEN_RE = re.compile(r"[a-z0-9_.:/-]{3,}", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_TARGET_ARGUMENT_KEYS = {"target", "url", "domain"}
_REVIEW_STATUSES = {"unreviewed", "reviewed", "deprecated", "blocked"}
_SUGGESTION_SIGNAL_OUTCOMES = {"suggested", "selected", "ignored", "succeeded", "failed"}
_ACCESS_LEVEL_RANK = {"none": 0, "credentials": 1, "user": 2, "root": 3, "admin": 3}
_RISK_BAND_BY_CLASS = {
    "r0_pure_local_computation": "low",
    "r1_local_observation": "low",
    "r2_network_observation": "low",
    "r3_active_enumeration": "medium",
    "r4_local_file_access": "medium",
    "r5_privileged_local_action": "high",
    "r6_offensive_payload_or_exploit_assistance": "high",
    "r7_extension_supply_chain_execution": "high",
    "r8_credentialed_remote_or_identity_action": "high",
    "low": "low",
    "medium": "medium",
    "high": "high",
}
_ACCESS_ALIASES = {
    "": "",
    "none": "none",
    "no": "none",
    "credential": "credentials",
    "credentials": "credentials",
    "authenticated": "credentials",
    "auth": "credentials",
    "user": "user",
    "shell": "user",
    "foothold": "user",
    "root": "root",
    "admin": "admin",
    "administrator": "admin",
}
_EXPERIENCE_TOOL_NAMES = {
    "nmap_scan",
    "dns_lookup",
    "whois_lookup",
    "http_headers",
    "tech_detect",
    "dir_brute",
    "nikto_scan",
    "ssl_check",
    "ssl_audit",
    "searchsploit",
    "cve_lookup",
    "sql_injection_test",
    "xss_test",
    # Exploitation tools
    "http_request",
    "fetch_url",
    "write_file",
    "webshell_exec",
    "start_listener",
}
_USER_CONTROLLED_FAILURE_MARKERS = (
    "permission denied by user",
    "permission denied by policy",
    "interrupted ·",
)
_TECHNICAL_FAILURE_MARKERS = (
    "timed out",
    "timeout",
    "does not exist",
    "not found",
    "no such file",
    "error",
    "failed",
    "invalid",
    "host seems down",
    "malformed_response",
)
_RUN_SHELL_EXPERIENCE_POLICY = (
    "run_shell lesson capture is disabled by default because shell output may "
    "contain secrets, flags, credentials, local paths, or unrelated private data."
)
_SENSITIVE_LESSON_RE = re.compile(
    r"(?i)("
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|token|secret|api[_-]?key|cookie)\s*[:=]\s*\S+|"
    r"\bcat\s+(?:user|root)\.txt\b|"
    r"\b(?:user|root)\.txt\s*[:=]\s*\S+|"
    r"\b(?:flag|thm|htb|rootme|picoctf)\{[^}\s]{4,}\}"
    r")"
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Recency weighting (learn/adapt faster) ───────────────────────────────
# Signals and lessons decay with age so the agent weights RECENT evidence more
# than stale evidence: a tactic that stops working is down-weighted sooner, and a
# newly-effective one dominates once it has enough recent outcomes. This changes
# only ranking magnitude — never the review gate, the ≥2-outcome anti-noise gate,
# or authorization. A fresh signal has weight ~1.0, so existing (all-recent)
# behaviour is unchanged.
_DEFAULT_SIGNAL_HALF_LIFE_DAYS = 10.0
_DEFAULT_LESSON_HALF_LIFE_DAYS = 45.0
# Corroboration: repeated independent lessons confirming the same pattern make it
# more trustworthy, so a lesson corroborated by siblings gets a small, bounded
# score bonus ("acquire experience"). Ranking only — it never changes review
# status, prompt inclusion, or authorization; a lone lesson gets no bonus.
_MAX_CORROBORATION_BONUS = 0.4


def _env_float(name: str, default: float) -> float:
    import os

    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _recency_weight(created_at: str, *, half_life_days: float, now: datetime | None = None) -> float:
    """Exponential-decay weight in (0, 1] for an ISO timestamp: 1.0 when fresh,
    0.5 after one half-life. Unparseable/absent timestamps default to 1.0 so a
    missing date never silently erases a signal."""
    parsed = _parse_created_at(created_at)
    if parsed is None:
        return 1.0
    reference = now or datetime.now(timezone.utc)
    age_days = (reference - parsed).total_seconds() / 86400.0
    if age_days <= 0 or half_life_days <= 0:
        return 1.0
    return float(2.0 ** (-(age_days / half_life_days)))


def _tokens(*values: Any) -> set[str]:
    text = " ".join(str(value or "") for value in values)
    return {match.group(0).casefold() for match in _TOKEN_RE.finditer(text)}


def _clip(value: Any, limit: int = 240) -> str:
    return " ".join(str(value or "").split())[:limit]


def _redact_sensitive_lesson_text(value: Any, limit: int = 240) -> str:
    text = _clip(value, limit)
    return _SENSITIVE_LESSON_RE.sub("[REDACTED]", text)


def _safe_lesson_list(values: Iterable[Any], limit: int) -> list[str]:
    result: list[str] = []
    for item in values:
        redacted = _redact_sensitive_lesson_text(item, limit)
        if not redacted:
            continue
        if redacted == "[REDACTED]":
            continue
        result.append(redacted)
    return result


def _safe_arguments(arguments: dict[str, Any] | None) -> dict[str, str]:
    allowed = {
        "target",
        "url",
        "domain",
        "query",
        "cve_id",
        "payload_type",
        "scan_type",
        "ports",
        "method",
        "record_type",
    }
    clean: dict[str, str] = {}
    for key, value in (arguments or {}).items():
        if key in allowed:
            clean[key] = _clip(value, 160)
    return clean


@dataclass
class CaseLesson:
    """A sanitized lesson from a previous authorized assessment or lab."""

    title: str
    outcome: str
    action_tool_name: str = ""
    action_method: str = ""
    action_arguments: dict[str, Any] = field(default_factory=dict)
    platform_tags: list[str] = field(default_factory=list)
    target_fingerprints: list[str] = field(default_factory=list)
    service_fingerprints: list[str] = field(default_factory=list)
    technology_hints: list[str] = field(default_factory=list)
    endpoint_hints: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    failure_reason: str = ""
    prerequisites: list[str] = field(default_factory=list)
    confidence: float = 0.6
    review_status: str = "unreviewed"
    source_type: str = "tool_result"
    evidence_refs: list[str] = field(default_factory=list)
    risk_class: str = ""
    required_access: str = ""
    expires_at: str = ""
    review_note: str = ""
    reviewed_at: str = ""
    session_name: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        self.outcome = self.outcome if self.outcome in {"success", "failure"} else "failure"
        self.action_arguments = _safe_arguments(self.action_arguments)
        self.title = _redact_sensitive_lesson_text(self.title, 180) or "Unnamed lesson"
        self.failure_reason = _redact_sensitive_lesson_text(self.failure_reason, 180)
        self.platform_tags = _safe_lesson_list(self.platform_tags, 80)
        self.target_fingerprints = _safe_lesson_list(self.target_fingerprints, 120)
        self.service_fingerprints = _safe_lesson_list(self.service_fingerprints, 160)
        self.technology_hints = _safe_lesson_list(self.technology_hints, 120)
        self.endpoint_hints = _safe_lesson_list(self.endpoint_hints, 160)
        self.evidence = _safe_lesson_list(self.evidence, 240)
        self.prerequisites = _safe_lesson_list(self.prerequisites, 180)
        self.evidence_refs = _safe_lesson_list(self.evidence_refs, 120)
        self.risk_class = _normalize_risk_class(self.risk_class)
        self.required_access = _normalize_required_access(self.required_access)
        self.review_status = (
            self.review_status
            if self.review_status in _REVIEW_STATUSES
            else "unreviewed"
        )
        self.source_type = _clip(self.source_type, 80) or "tool_result"
        self.expires_at = _clip(self.expires_at, 80)
        self.review_note = _redact_sensitive_lesson_text(self.review_note, 240)
        self.reviewed_at = _clip(self.reviewed_at, 80)
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.6

    @property
    def is_success(self) -> bool:
        return self.outcome == "success"

    @property
    def is_reviewed(self) -> bool:
        return self.review_status == "reviewed" and not _is_expired(self.expires_at)

    @property
    def is_active(self) -> bool:
        return self.review_status not in {"blocked", "deprecated"} and not _is_expired(self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "outcome": self.outcome,
            "action_tool_name": self.action_tool_name,
            "action_method": self.action_method,
            "action_arguments": dict(self.action_arguments),
            "platform_tags": list(self.platform_tags),
            "target_fingerprints": list(self.target_fingerprints),
            "service_fingerprints": list(self.service_fingerprints),
            "technology_hints": list(self.technology_hints),
            "endpoint_hints": list(self.endpoint_hints),
            "evidence": list(self.evidence),
            "failure_reason": self.failure_reason,
            "prerequisites": list(self.prerequisites),
            "confidence": self.confidence,
            "review_status": self.review_status,
            "source_type": self.source_type,
            "evidence_refs": list(self.evidence_refs),
            "risk_class": self.risk_class,
            "required_access": self.required_access,
            "expires_at": self.expires_at,
            "review_note": self.review_note,
            "reviewed_at": self.reviewed_at,
            "session_name": self.session_name,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaseLesson":
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            title=str(data.get("title") or "Unnamed lesson"),
            outcome=str(data.get("outcome") or "failure"),
            action_tool_name=str(data.get("action_tool_name") or ""),
            action_method=str(data.get("action_method") or ""),
            action_arguments=dict(data.get("action_arguments") or {}),
            platform_tags=[str(item) for item in data.get("platform_tags", []) or []],
            target_fingerprints=[str(item) for item in data.get("target_fingerprints", []) or []],
            service_fingerprints=[str(item) for item in data.get("service_fingerprints", []) or []],
            technology_hints=[str(item) for item in data.get("technology_hints", []) or []],
            endpoint_hints=[str(item) for item in data.get("endpoint_hints", []) or []],
            evidence=[str(item) for item in data.get("evidence", []) or []],
            failure_reason=str(data.get("failure_reason") or ""),
            prerequisites=[str(item) for item in data.get("prerequisites", []) or []],
            confidence=data.get("confidence", 0.6) or 0.6,
            review_status=str(data.get("review_status") or "unreviewed"),
            source_type=str(data.get("source_type") or "tool_result"),
            evidence_refs=[str(item) for item in data.get("evidence_refs", []) or []],
            risk_class=str(data.get("risk_class") or ""),
            required_access=str(data.get("required_access") or ""),
            expires_at=str(data.get("expires_at") or ""),
            review_note=str(data.get("review_note") or ""),
            reviewed_at=str(data.get("reviewed_at") or ""),
            session_name=str(data.get("session_name") or ""),
            created_at=str(data.get("created_at") or _utc_now_iso()),
        )

    def fingerprint_tokens(self) -> set[str]:
        return _tokens(
            self.title,
            self.action_tool_name,
            self.action_method,
            *self.action_arguments.values(),
            *self.platform_tags,
            *self.target_fingerprints,
            *self.service_fingerprints,
            *self.technology_hints,
            *self.endpoint_hints,
            *self.evidence,
            self.risk_class,
            self.required_access,
            self.failure_reason,
        )

    def reason(self) -> str:
        prefix = "similar prior success" if self.is_success else "similar prior failure"
        detail = self.title
        if not self.is_success and self.failure_reason:
            detail = f"{detail}: {self.failure_reason}"
        if not self.is_reviewed:
            detail = f"{detail} (unreviewed, explanation only)"
        return f"{prefix}: {detail}"

    def reviewed_copy(self, status: str, note: str = "") -> "CaseLesson":
        status = status if status in _REVIEW_STATUSES else "unreviewed"
        data = self.to_dict()
        data["review_status"] = status
        data["review_note"] = note
        data["reviewed_at"] = _utc_now_iso()
        return CaseLesson.from_dict(data)


@dataclass
class ExperienceStoreOperationResult:
    """Summary for dry-run or applied experience-store maintenance."""

    operation: str
    dry_run: bool
    total: int
    kept: int
    removed: int = 0
    changed: int = 0
    backup_path: str = ""
    output_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "dry_run": self.dry_run,
            "total": self.total,
            "kept": self.kept,
            "removed": self.removed,
            "changed": self.changed,
            "backup_path": self.backup_path,
            "output_path": self.output_path,
        }


@dataclass
class SuggestionSignal:
    """A local learning signal for a proposed next action."""

    outcome: str
    action_key: str
    title: str = ""
    tool_name: str = ""
    action_method: str = ""
    action_arguments: dict[str, Any] = field(default_factory=dict)
    rank: int = 0
    risk: str = ""
    reason: str = ""
    audit_status: str = ""
    audit_reasons: list[str] = field(default_factory=list)
    session_name: str = ""
    batch_id: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        self.outcome = self.outcome if self.outcome in _SUGGESTION_SIGNAL_OUTCOMES else "suggested"
        self.action_key = _redact_sensitive_lesson_text(self.action_key, 240)
        self.title = _redact_sensitive_lesson_text(self.title, 180)
        self.tool_name = _clip(self.tool_name, 80)
        self.action_method = _clip(self.action_method, 120)
        self.action_arguments = _safe_arguments(self.action_arguments)
        self.risk = _clip(self.risk, 40)
        self.reason = _redact_sensitive_lesson_text(self.reason, 240)
        self.audit_status = _clip(self.audit_status, 40)
        self.audit_reasons = _safe_lesson_list(self.audit_reasons, 180)[:8]
        self.session_name = _clip(self.session_name, 120)
        self.batch_id = _clip(self.batch_id, 80)
        try:
            self.rank = max(0, int(self.rank))
        except (TypeError, ValueError):
            self.rank = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "outcome": self.outcome,
            "action_key": self.action_key,
            "title": self.title,
            "tool_name": self.tool_name,
            "action_method": self.action_method,
            "action_arguments": dict(self.action_arguments),
            "rank": self.rank,
            "risk": self.risk,
            "reason": self.reason,
            "audit_status": self.audit_status,
            "audit_reasons": list(self.audit_reasons),
            "session_name": self.session_name,
            "batch_id": self.batch_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SuggestionSignal":
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            outcome=str(data.get("outcome") or "suggested"),
            action_key=str(data.get("action_key") or ""),
            title=str(data.get("title") or ""),
            tool_name=str(data.get("tool_name") or ""),
            action_method=str(data.get("action_method") or ""),
            action_arguments=dict(data.get("action_arguments") or {}),
            rank=data.get("rank", 0) or 0,
            risk=str(data.get("risk") or ""),
            reason=str(data.get("reason") or ""),
            audit_status=str(data.get("audit_status") or ""),
            audit_reasons=[str(item) for item in data.get("audit_reasons", []) or []],
            session_name=str(data.get("session_name") or ""),
            batch_id=str(data.get("batch_id") or ""),
            created_at=str(data.get("created_at") or _utc_now_iso()),
        )


@dataclass(frozen=True)
class SuggestionLearningStats:
    """Aggregated local evidence about how a suggestion family performs."""

    key: str
    tool_name: str = ""
    action_method: str = ""
    suggested: int = 0
    selected: int = 0
    ignored: int = 0
    succeeded: int = 0
    failed: int = 0
    audit_applied: int = 0
    audit_rejected: int = 0
    audit_reasons: tuple[str, ...] = ()
    # Recency-weighted outcome mass (fresh signal ~1.0). 0.0 means "not computed"
    # (directly-constructed stats), which falls back to the raw integer counts.
    weighted_selected: float = 0.0
    weighted_ignored: float = 0.0
    weighted_succeeded: float = 0.0
    weighted_failed: float = 0.0

    @property
    def total(self) -> int:
        return self.suggested + self.selected + self.ignored + self.succeeded + self.failed

    @property
    def selection_rate(self) -> float:
        denominator = self.selected + self.ignored
        return round(self.selected / denominator, 4) if denominator else 0.0

    @property
    def success_rate(self) -> float:
        denominator = self.succeeded + self.failed
        return round(self.succeeded / denominator, 4) if denominator else 0.0

    @property
    def confidence_score(self) -> float:
        # Anti-noise gate stays on RAW counts (≥2 real outcomes, or ≥3 ignores):
        # recency never lets a single fresh outcome move priority.
        signal_count = self.selected + self.succeeded + self.failed
        if signal_count < 2 and self.ignored < 3:
            return 0.0
        # Magnitude comes from recency-weighted evidence so recent trends dominate
        # and stale outcomes fade; fall back to raw counts when weights are absent.
        ws = self.weighted_succeeded or float(self.succeeded)
        wsel = self.weighted_selected or float(self.selected)
        wf = self.weighted_failed or float(self.failed)
        wi = self.weighted_ignored or float(self.ignored)
        positive = (ws * 1.0) + (wsel * 0.25)
        negative = (wf * 1.0) + (wi * 0.2)
        score = (positive - negative) / max(1.0, positive + negative)
        return round(max(-1.0, min(1.0, score)), 4)

    @property
    def effect(self) -> str:
        if self.succeeded >= 2 and self.success_rate >= 0.6 and self.confidence_score > 0:
            return "boost"
        if self.failed >= 2 and self.failed > self.succeeded:
            return "downrank"
        if self.ignored >= 3 and self.selected == 0:
            return "downrank"
        # Recency-driven adaptation: with enough real outcomes (≥2), let a strongly
        # signed *recency-weighted* confidence decide even when the raw counts are
        # balanced — so a tactic that USED to work but now fails is dropped fast
        # (and a stale-failed one that now works is re-adopted). Anti-noise: needs
        # ≥2 outcomes and a decisive |score|, so a single fresh result never flips it.
        if self.confidence_score <= -0.5 and self.failed >= 2:
            return "downrank"
        if self.confidence_score >= 0.5 and self.succeeded >= 2:
            return "boost"
        return "explanation-only"

    @property
    def should_suppress(self) -> bool:
        """Bug 2.2: True if this suggestion family should be hidden entirely.

        Suppression rules (by signal family keyword):
        - ``missing_tool_install``: suppress after 3 consecutive ignores
        - ``scope_define``: suppress after 1 ignore (generic meta-suggestion)
        - default: suppress after 5 consecutive ignores with 0 selections

        The purpose is to stop showing suggestions the user is clearly not
        interested in, without losing the learning data.
        """
        if self.selected > 0 or self.succeeded > 0:
            return False
        key_lower = self.key.casefold()
        if "missing_tool_install" in key_lower or "install" in key_lower:
            return self.ignored >= 3
        if "scope_define" in key_lower or "define_scope" in key_lower:
            return self.ignored >= 1
        return self.ignored >= 5

    @property
    def priority_delta(self) -> int:
        if self.effect == "boost":
            return min(4, max(1, round(abs(self.confidence_score) * 4)))
        if self.effect == "downrank":
            return -min(5, max(1, round(abs(self.confidence_score) * 5)))
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "tool_name": self.tool_name,
            "action_method": self.action_method,
            "suggested": self.suggested,
            "selected": self.selected,
            "ignored": self.ignored,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "audit_applied": self.audit_applied,
            "audit_rejected": self.audit_rejected,
            "audit_reasons": list(self.audit_reasons),
            "selection_rate": self.selection_rate,
            "success_rate": self.success_rate,
            "confidence_score": self.confidence_score,
            "effect": self.effect,
            "priority_delta": self.priority_delta,
        }


@dataclass(frozen=True)
class LessonMatchDecision:
    """Single compatibility and ranking decision for one lesson/action pair."""

    lesson: CaseLesson
    status: str
    effect: str
    passed_gates: bool
    score: float | None = None
    reasons: tuple[str, ...] = ()
    why_matches: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    service_match: bool | None = None
    endpoint_match: bool | None = None
    risk_match: bool | None = None
    access_match: bool | None = None
    required_access: str = ""
    current_access: str = ""
    scope_allowed: bool | None = None
    action_family_match: bool | None = None

    @property
    def can_influence(self) -> bool:
        return self.status in {"applied", "explanation-only"} and self.score is not None


def build_suggestion_signal(
    action: Any,
    *,
    outcome: str,
    session_name: str = "",
    batch_id: str = "",
    rank: int = 0,
    reason: str = "",
    audit_status: str = "",
    audit_reasons: Iterable[Any] = (),
) -> SuggestionSignal:
    """Create a sanitized signal from a planner suggestion."""
    safe_arguments = _safe_arguments(dict(getattr(action, "arguments", {}) or {}))
    return SuggestionSignal(
        outcome=outcome,
        action_key=_suggestion_action_key(action, safe_arguments),
        title=str(getattr(action, "title", "") or ""),
        tool_name=str(getattr(action, "tool_name", "") or ""),
        action_method=str(getattr(action, "method", "") or ""),
        action_arguments=safe_arguments,
        rank=rank,
        risk=str(getattr(action, "risk", "") or ""),
        reason=reason,
        audit_status=audit_status,
        audit_reasons=[str(item) for item in audit_reasons or ()],
        session_name=session_name,
        batch_id=batch_id,
    )


def _suggestion_action_key(action: Any, safe_arguments: dict[str, str]) -> str:
    parts = [
        str(getattr(action, "tool_name", "") or getattr(action, "method", "") or ""),
        safe_arguments.get("target", ""),
        safe_arguments.get("domain", ""),
        safe_arguments.get("url", ""),
        safe_arguments.get("cve_id", ""),
        safe_arguments.get("query", ""),
        safe_arguments.get("payload_type", ""),
        safe_arguments.get("scan_type", ""),
        safe_arguments.get("ports", ""),
        safe_arguments.get("method", ""),
        str(getattr(action, "title", "") or "")[:80],
    ]
    return "|".join(" ".join(str(part).casefold().split()) for part in parts)


def aggregate_suggestion_signals(
    signals: Iterable[SuggestionSignal],
) -> list[SuggestionLearningStats]:
    """Aggregate sanitized suggestion signals by action family."""
    counters: dict[str, Counter[str]] = {}
    weighted: dict[str, dict[str, float]] = {}
    audit_status_counters: dict[str, Counter[str]] = {}
    audit_reason_counters: dict[str, Counter[str]] = {}
    labels: dict[str, tuple[str, str]] = {}
    now = datetime.now(timezone.utc)
    half_life = _env_float("SECOPS_SIGNAL_HALF_LIFE_DAYS", _DEFAULT_SIGNAL_HALF_LIFE_DAYS)
    for signal in signals or ():
        key = _signal_family_key(signal)
        if not key:
            continue
        if key not in counters:
            counters[key] = Counter()
            weighted[key] = {}
            audit_status_counters[key] = Counter()
            audit_reason_counters[key] = Counter()
            labels[key] = (signal.tool_name, signal.action_method)
        counters[key][signal.outcome] += 1
        weight = _recency_weight(signal.created_at, half_life_days=half_life, now=now)
        weighted[key][signal.outcome] = weighted[key].get(signal.outcome, 0.0) + weight
        if signal.audit_status:
            audit_status_counters[key][signal.audit_status] += 1
        for reason in signal.audit_reasons:
            audit_reason_counters[key][reason] += 1

    stats = [
        SuggestionLearningStats(
            key=key,
            tool_name=labels[key][0],
            action_method=labels[key][1],
            suggested=counts.get("suggested", 0),
            selected=counts.get("selected", 0),
            ignored=counts.get("ignored", 0),
            succeeded=counts.get("succeeded", 0),
            failed=counts.get("failed", 0),
            audit_applied=audit_status_counters[key].get("applied", 0),
            audit_rejected=audit_status_counters[key].get("rejected", 0),
            audit_reasons=tuple(
                reason
                for reason, _count in audit_reason_counters[key].most_common(5)
            ),
            weighted_selected=weighted[key].get("selected", 0.0),
            weighted_ignored=weighted[key].get("ignored", 0.0),
            weighted_succeeded=weighted[key].get("succeeded", 0.0),
            weighted_failed=weighted[key].get("failed", 0.0),
        )
        for key, counts in counters.items()
    ]
    stats.sort(key=lambda item: (abs(item.confidence_score), item.total), reverse=True)
    return stats


def suggestion_learning_detail_for_action(
    signals: Iterable[SuggestionSignal],
    action: Any,
    *,
    stats: Iterable[SuggestionLearningStats] | None = None,
) -> dict[str, Any] | None:
    """Return compact signal-learning context for a planner action.

    ``stats`` lets a caller pass the already-aggregated stats (computed once per
    plan) instead of re-aggregating all signals for every action."""
    key = _action_family_key(action)
    if not key:
        return None
    all_stats = stats if stats is not None else aggregate_suggestion_signals(signals)
    matching = [
        stat
        for stat in all_stats
        if stat.key == key
    ]
    if not matching:
        return None
    stat = matching[0]
    reason = (
        f"local suggestion signals: selected={stat.selected}, ignored={stat.ignored}, "
        f"succeeded={stat.succeeded}, failed={stat.failed}"
    )
    missing: list[str] = []
    if stat.effect == "explanation-only":
        missing.append("more repeated outcomes needed before priority changes")
    if stat.audit_rejected:
        missing.extend(stat.audit_reasons[:3])
    return {
        "lesson_id": "",
        "review_status": "signal",
        "effect": stat.effect,
        "reason": reason,
        "confidence_score": stat.confidence_score,
        "priority_delta": stat.priority_delta,
        "why_matches": [f"signal family: {stat.key}"],
        "missing_evidence": missing,
        "signal_counts": stat.to_dict(),
    }


def _signal_family_key(signal: SuggestionSignal) -> str:
    return "|".join(
        part
        for part in (
            str(signal.tool_name or "").casefold(),
            str(signal.action_method or "").casefold(),
        )
        if part
    )


def _action_family_key(action: Any) -> str:
    return "|".join(
        part
        for part in (
            str(getattr(action, "tool_name", "") or "").casefold(),
            str(getattr(action, "method", "") or "").casefold(),
        )
        if part
    )


def default_experience_path() -> Path:
    try:
        base = settings.sessions_dir.parent / "experience"
        base.mkdir(parents=True, exist_ok=True)
        return base / "case_lessons.jsonl"
    except OSError:
        path = Path("./.secops_experience")
        path.mkdir(parents=True, exist_ok=True)
        return path / "case_lessons.jsonl"


class ExperienceStore:
    """Append-only JSONL storage for local case lessons."""

    def __init__(self, path: Path | None = None, signal_path: Path | None = None) -> None:
        self.path = path or default_experience_path()
        self.signal_path = signal_path or self.path.with_name("suggestion_signals.jsonl")
        self._cache_signature: tuple[int, int] | None = None
        self._cache_lessons: list[CaseLesson] | None = None
        self._signal_cache_signature: tuple[int, int] | None = None
        self._signal_cache: list[SuggestionSignal] | None = None

    def _invalidate_cache(self) -> None:
        self._cache_signature = None
        self._cache_lessons = None

    def _invalidate_signal_cache(self) -> None:
        self._signal_cache_signature = None
        self._signal_cache = None

    def _signature(self) -> tuple[int, int] | None:
        if not self.path.exists():
            return None
        try:
            stat = self.path.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_size

    def _load_all(self) -> list[CaseLesson]:
        signature = self._signature()
        if signature is None:
            self._cache_signature = None
            self._cache_lessons = []
            return []
        if self._cache_signature == signature and self._cache_lessons is not None:
            return [_copy_lesson(lesson) for lesson in self._cache_lessons]

        lessons: list[CaseLesson] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                try:
                    lessons.append(CaseLesson.from_dict(data))
                except (TypeError, ValueError):
                    continue

        self._cache_signature = signature
        self._cache_lessons = [_copy_lesson(lesson) for lesson in lessons]
        return lessons

    def _signal_signature(self) -> tuple[int, int] | None:
        if not self.signal_path.exists():
            return None
        try:
            stat = self.signal_path.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_size

    def _load_all_signals(self) -> list[SuggestionSignal]:
        signature = self._signal_signature()
        if signature is None:
            self._signal_cache_signature = None
            self._signal_cache = []
            return []
        if self._signal_cache_signature == signature and self._signal_cache is not None:
            return [SuggestionSignal.from_dict(signal.to_dict()) for signal in self._signal_cache]

        signals: list[SuggestionSignal] = []
        try:
            lines = self.signal_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                try:
                    signals.append(SuggestionSignal.from_dict(data))
                except (TypeError, ValueError):
                    continue

        self._signal_cache_signature = signature
        self._signal_cache = [SuggestionSignal.from_dict(signal.to_dict()) for signal in signals]
        return signals

    def append(self, lesson: CaseLesson) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(lesson.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        self._invalidate_cache()
        return self.path

    def append_unique(self, lesson: CaseLesson, recent_limit: int = 200) -> Path:
        lesson_key = _lesson_identity(lesson)
        for existing in self.load(limit=recent_limit):
            if _lesson_identity(existing) == lesson_key:
                return self.path
        return self.append(lesson)

    def load(self, limit: int | None = 200) -> list[CaseLesson]:
        lessons = self._load_all()
        if limit is None:
            return lessons
        return lessons[-max(1, int(limit)):]

    def append_signal(self, signal: SuggestionSignal) -> Path:
        self.signal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.signal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(signal.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        self._invalidate_signal_cache()
        return self.signal_path

    def load_signals(self, limit: int | None = 200) -> list[SuggestionSignal]:
        signals = self._load_all_signals()
        if limit is None:
            return signals
        return signals[-max(1, int(limit)):]

    def signal_summary(self, limit: int | None = None) -> dict[str, Any]:
        """Return compact suggestion-learning metrics without exposing outputs."""
        signals = self.load_signals(limit=limit)
        by_outcome = Counter(signal.outcome for signal in signals)
        by_tool = Counter(signal.tool_name or "(method-only)" for signal in signals)
        selected = sum(1 for signal in signals if signal.outcome == "selected")
        succeeded = sum(1 for signal in signals if signal.outcome == "succeeded")
        failed = sum(1 for signal in signals if signal.outcome == "failed")
        stats = aggregate_suggestion_signals(signals)
        return {
            "path": str(self.signal_path),
            "total_signals": len(signals),
            "by_outcome": dict(sorted(by_outcome.items())),
            "by_tool": dict(sorted(by_tool.items())),
            "selected": selected,
            "succeeded": succeeded,
            "failed": failed,
            "success_rate": round(succeeded / selected, 4) if selected else 0.0,
            "top_signal_stats": [item.to_dict() for item in stats[:10]],
        }

    def audit(self, limit: int | None = None) -> dict[str, Any]:
        """Return a compact review summary without exposing full lesson output."""
        lessons = self.load(limit=limit)
        outcome_counts = Counter(lesson.outcome for lesson in lessons)
        tool_counts = Counter(lesson.action_tool_name or "(method-only)" for lesson in lessons)
        raw_targets = sorted({value for lesson in lessons for value in _raw_target_values(lesson)})
        return {
            "path": str(self.path),
            "total_lessons": len(lessons),
            "by_outcome": dict(sorted(outcome_counts.items())),
            "by_tool": dict(sorted(tool_counts.items())),
            "raw_target_value_count": len(raw_targets),
            "raw_target_examples": raw_targets[:5],
            "run_shell_capture_enabled": "run_shell" in _EXPERIENCE_TOOL_NAMES,
            "run_shell_policy": _RUN_SHELL_EXPERIENCE_POLICY,
        }

    def export(
        self,
        destination: str | Path,
        *,
        anonymize_targets: bool = False,
        hash_salt: str = "",
        limit: int | None = None,
    ) -> Path:
        """Export lessons as JSONL, optionally hashing target values in the export."""
        output_path = Path(destination).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        lessons = self.load(limit=limit)
        if anonymize_targets:
            lessons = [_anonymized_lesson(lesson, hash_salt=hash_salt) for lesson in lessons]
        with output_path.open("w", encoding="utf-8") as handle:
            for lesson in lessons:
                handle.write(json.dumps(lesson.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        return output_path

    def purge(
        self,
        *,
        outcome: str | None = None,
        tool_name: str | None = None,
        older_than_days: int | None = None,
        dry_run: bool = True,
        backup: bool = True,
    ) -> ExperienceStoreOperationResult:
        """Remove lessons matching explicit filters. Defaults to dry-run."""
        lessons = self.load(limit=None)
        kept: list[CaseLesson] = []
        removed = 0
        for lesson in lessons:
            if _matches_purge_filter(
                lesson,
                outcome=outcome,
                tool_name=tool_name,
                older_than_days=older_than_days,
            ):
                removed += 1
                continue
            kept.append(lesson)
        result = ExperienceStoreOperationResult(
            operation="purge",
            dry_run=dry_run,
            total=len(lessons),
            kept=len(kept),
            removed=removed,
        )
        if dry_run or removed == 0:
            return result
        backup_path = self._rewrite(kept, backup=backup)
        result.backup_path = str(backup_path) if backup_path else ""
        return result

    def apply_retention(
        self,
        *,
        max_lessons: int | None = None,
        max_age_days: int | None = None,
        dry_run: bool = True,
        backup: bool = True,
    ) -> ExperienceStoreOperationResult:
        """Apply age and count retention. Defaults to dry-run."""
        lessons = self.load(limit=None)
        kept = [
            lesson for lesson in lessons
            if not _is_older_than(lesson, max_age_days)
        ]
        if max_lessons is not None:
            keep_count = max(0, int(max_lessons))
            kept = kept[-keep_count:] if keep_count else []
        removed = len(lessons) - len(kept)
        result = ExperienceStoreOperationResult(
            operation="retention",
            dry_run=dry_run,
            total=len(lessons),
            kept=len(kept),
            removed=removed,
        )
        if dry_run or removed == 0:
            return result
        backup_path = self._rewrite(kept, backup=backup)
        result.backup_path = str(backup_path) if backup_path else ""
        return result

    def anonymize_targets(
        self,
        *,
        hash_salt: str = "",
        dry_run: bool = True,
        backup: bool = True,
    ) -> ExperienceStoreOperationResult:
        """Hash target values across stored lessons. Defaults to dry-run."""
        lessons = self.load(limit=None)
        anonymized = [_anonymized_lesson(lesson, hash_salt=hash_salt) for lesson in lessons]
        changed = sum(
            1
            for original, updated in zip(lessons, anonymized)
            if original.to_dict() != updated.to_dict()
        )
        result = ExperienceStoreOperationResult(
            operation="anonymize_targets",
            dry_run=dry_run,
            total=len(lessons),
            kept=len(anonymized),
            changed=changed,
        )
        if dry_run or changed == 0:
            return result
        backup_path = self._rewrite(anonymized, backup=backup)
        result.backup_path = str(backup_path) if backup_path else ""
        return result

    def review_lesson(
        self,
        lesson_id: str,
        *,
        status: str,
        note: str = "",
        dry_run: bool = True,
        backup: bool = True,
    ) -> ExperienceStoreOperationResult:
        """Update review metadata for one lesson. Defaults to dry-run."""
        lessons = self.load(limit=None)
        updated: list[CaseLesson] = []
        changed = 0
        normalized_id = str(lesson_id or "").strip()
        for lesson in lessons:
            if lesson.id == normalized_id:
                replacement = lesson.reviewed_copy(status, note)
                changed += int(replacement.to_dict() != lesson.to_dict())
                updated.append(replacement)
            else:
                updated.append(lesson)

        result = ExperienceStoreOperationResult(
            operation="review_lesson",
            dry_run=dry_run,
            total=len(lessons),
            kept=len(updated),
            changed=changed,
        )
        if dry_run or changed == 0:
            return result
        backup_path = self._rewrite(updated, backup=backup)
        result.backup_path = str(backup_path) if backup_path else ""
        return result

    def _rewrite(self, lessons: list[CaseLesson], *, backup: bool = True) -> Path | None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        backup_path: Path | None = None
        if backup and self.path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            backup_path = self.path.with_name(f"{self.path.name}.bak-{stamp}")
            shutil.copy2(self.path, backup_path)

        tmp_path = self.path.with_name(f"{self.path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            for lesson in lessons:
                handle.write(json.dumps(lesson.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        tmp_path.replace(self.path)
        self._invalidate_cache()
        return backup_path

    def retrieve(
        self,
        mission: Any,
        action: Any | None = None,
        *,
        limit: int = 5,
        min_score: float = 0.18,
    ) -> list[tuple[CaseLesson, float]]:
        return retrieve_similar_lessons(self.load(), mission, action, limit=limit, min_score=min_score)


def retrieve_similar_lessons(
    lessons: Iterable[CaseLesson],
    mission: Any,
    action: Any | None = None,
    *,
    limit: int = 5,
    min_score: float = 0.18,
) -> list[tuple[CaseLesson, float]]:
    lessons = list(lessons)
    counts = corroboration_counts(lessons)
    idf = lesson_idf(lessons)
    tokens = _mission_tokens(mission)
    if action is not None:
        tokens = tokens | _action_tokens(action)
    decisions = [
        evaluate_lesson_match(
            lesson, mission, action, min_score=min_score,
            corroboration=counts.get(lesson.id, 1), idf=idf,
            precomputed_tokens=tokens,
        )
        for lesson in lessons
    ]
    scored = [
        (decision.lesson, decision.score)
        for decision in decisions
        if decision.can_influence and decision.score is not None
    ]
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:limit]


def lesson_is_compatible(lesson: CaseLesson, mission: Any, action: Any | None = None) -> bool:
    """Return whether a lesson can influence the current technical situation."""
    return evaluate_lesson_match(lesson, mission, action).passed_gates


def evaluate_lesson_match(
    lesson: CaseLesson,
    mission: Any,
    action: Any | None = None,
    *,
    min_score: float = 0.18,
    corroboration: int = 1,
    idf: dict[str, float] | None = None,
    precomputed_tokens: set[str] | None = None,
) -> LessonMatchDecision:
    """Evaluate one lesson against the current mission/action using one decision path."""
    reasons: list[str] = []
    why: list[str] = []
    missing: list[str] = []

    if not lesson.is_active:
        reasons.append("lesson is inactive, blocked, deprecated, or expired")

    action_family_match = _action_family_compatible(lesson, action) if action is not None else None
    if action_family_match is False:
        reasons.append("action family mismatch")
    if lesson.action_tool_name and action is not None and lesson.action_tool_name == str(getattr(action, "tool_name", "") or ""):
        why.append(f"same tool: {lesson.action_tool_name}")
    if lesson.action_method and action is not None and lesson.action_method == str(getattr(action, "method", "") or ""):
        why.append(f"same method: {lesson.action_method}")

    service_match = _service_match_detail(lesson, mission, reasons, why, missing)
    endpoint_match = _endpoint_match_detail(lesson, mission, action, reasons, why, missing)
    risk_match = _risk_match_detail(lesson, action, reasons, why, missing)
    required_access = _lesson_required_access(lesson)
    current_access = _mission_access_state(mission)
    access_match = _access_match_detail(
        required_access,
        current_access,
        reasons,
        why,
        missing,
    )
    scope_allowed = _action_scope_allowed(mission, action) if action is not None else None
    if scope_allowed is False:
        reasons.append("action target is out of scope")

    failure_mode_match = _failure_mode_compatible(lesson, action)
    if not failure_mode_match:
        reasons.append("failure mode mismatch")

    passed_gates = not reasons
    score: float | None = None
    if passed_gates:
        # mission+action tokens are identical across every lesson in a scoring
        # pass, so a caller can compute them once and pass them in.
        if precomputed_tokens is not None:
            current = precomputed_tokens
        else:
            current = _mission_tokens(mission)
            if action is not None:
                current |= _action_tokens(action)
        lesson_tokens = lesson.fingerprint_tokens()
        if not lesson_tokens:
            reasons.append("lesson has no reusable fingerprint tokens")
        else:
            overlap = current & lesson_tokens
            if not overlap:
                reasons.append("insufficient compatible evidence overlap")
            else:
                # TF-IDF weighting (precision): weigh matched tokens by how
                # distinctive they are across the corpus. With no idf supplied this
                # is exactly the count-based ratio (backward-compatible).
                if idf:
                    weighted_overlap = sum(idf.get(token, 1.0) for token in overlap)
                    weighted_total = sum(idf.get(token, 1.0) for token in lesson_tokens)
                else:
                    weighted_overlap = float(len(overlap))
                    weighted_total = float(len(lesson_tokens))
                raw_score = (weighted_overlap / max(6.0, weighted_total)) * (0.5 + lesson.confidence / 2)
                if _matches_action(lesson, action):
                    raw_score += 0.25
                # Recency decay for AUTO (unreviewed) lessons so stale auto-captured
                # noise fades from retrieval over time and recent experience ranks
                # higher. Human-REVIEWED lessons are curated, durable knowledge and
                # keep full weight (they never decay). Ranking only — never the
                # review gate or authorization; a fresh lesson keeps weight ~1.0.
                if not lesson.is_reviewed:
                    raw_score *= _recency_weight(
                        lesson.created_at,
                        half_life_days=_env_float(
                            "SECOPS_LESSON_HALF_LIFE_DAYS", _DEFAULT_LESSON_HALF_LIFE_DAYS
                        ),
                    )
                # Repeatedly-confirmed pattern → bounded ranking bonus (P1c).
                raw_score *= _corroboration_multiplier(corroboration)
                score = round(raw_score, 4)
                if score < min_score:
                    reasons.append("insufficient compatible evidence overlap")

    if score is not None and score >= min_score and lesson.is_reviewed:
        status = "applied"
        effect = _lesson_effect_label(lesson)
    elif score is not None and score >= min_score:
        status = "explanation-only"
        effect = "explanation-only"
        missing.append("review lesson before it changes priority")
    else:
        status = "rejected"
        effect = "none"

    if action is not None and score is not None and bool(getattr(action, "requires_approval", False)):
        missing.append("user approval still required")
    if score is not None and not why:
        why.append("token overlap only")
    if not reasons and status in {"applied", "explanation-only"}:
        reasons.append(lesson.reason())

    return LessonMatchDecision(
        lesson=lesson,
        status=status,
        effect=effect,
        passed_gates=passed_gates,
        score=score if score is not None and score >= min_score else None,
        reasons=tuple(_unique_clipped(reasons, 180)),
        why_matches=tuple(_unique_clipped(why, 180)),
        missing_evidence=tuple(_unique_clipped(missing, 180)),
        service_match=service_match,
        endpoint_match=endpoint_match,
        risk_match=risk_match,
        access_match=access_match,
        required_access=required_access,
        current_access=current_access,
        scope_allowed=scope_allowed,
        action_family_match=action_family_match,
    )


def lesson_influence_detail(lesson: CaseLesson, mission: Any, action: Any | None = None) -> dict[str, Any]:
    """Build a compact explanation for why a lesson matched a suggestion."""
    decision = evaluate_lesson_match(lesson, mission, action)

    return {
        "lesson_id": lesson.id,
        "review_status": lesson.review_status,
        "effect": decision.effect if decision.status != "rejected" else _lesson_effect_label(lesson),
        "reason": lesson.reason(),
        "why_matches": list(decision.why_matches[:4]) or ["token overlap only"],
        "missing_evidence": list(decision.missing_evidence[:4]),
    }


def _lesson_effect_label(lesson: CaseLesson) -> str:
    if not lesson.is_reviewed:
        return "explanation-only"
    return "boost" if lesson.is_success else "downrank"


def _action_family_compatible(lesson: CaseLesson, action: Any) -> bool:
    lesson_tool = str(lesson.action_tool_name or "")
    lesson_method = str(lesson.action_method or "")
    action_tool = str(getattr(action, "tool_name", "") or "")
    action_method = str(getattr(action, "method", "") or "")
    if lesson_tool and action_tool and lesson_tool != action_tool:
        return False
    if lesson_method and action_method and lesson_method != action_method:
        return False
    if lesson_tool and not action_tool and not lesson_method:
        return False
    if lesson_method and not action_method and not lesson_tool:
        return False
    return True


def _service_compatible(lesson: CaseLesson, mission: Any) -> bool:
    return _service_match_detail(lesson, mission, [], [], []) is not False


def _endpoint_compatible(lesson: CaseLesson, mission: Any, action: Any | None) -> bool:
    return _endpoint_match_detail(lesson, mission, action, [], [], []) is not False


def _service_match_detail(
    lesson: CaseLesson,
    mission: Any,
    reasons: list[str],
    why: list[str],
    missing: list[str],
) -> bool | None:
    lesson_services = _service_families_from_values(lesson.service_fingerprints)
    if not lesson_services:
        return None
    mission_services = _service_families_from_values(_service_fingerprints(mission))
    if not mission_services:
        missing.append("confirm matching service family")
        return None
    shared_services = sorted(lesson_services & mission_services)
    if shared_services:
        why.append(f"service: {', '.join(shared_services[:3])}")
        return True
    reasons.append("service family mismatch")
    missing.append("confirm matching service family")
    return False


def _endpoint_match_detail(
    lesson: CaseLesson,
    mission: Any,
    action: Any | None,
    reasons: list[str],
    why: list[str],
    missing: list[str],
) -> bool | None:
    lesson_paths = _path_hints(lesson.endpoint_hints)
    if not lesson_paths:
        return None

    current_paths = _path_hints(_mission_endpoint_values(mission))
    if action is not None:
        values: list[Any] = [
            getattr(action, "title", ""),
            getattr(action, "rationale", ""),
            *list(getattr(action, "evidence", []) or []),
        ]
        values.extend((getattr(action, "arguments", {}) or {}).values())
        current_paths |= _path_hints(values)

    if not current_paths:
        reasons.append("confirm matching endpoint evidence")
        missing.append("current endpoint evidence is missing")
        return False
    shared_paths = sorted(lesson_paths & current_paths)
    if shared_paths:
        why.append(f"endpoint: {', '.join(shared_paths[:3])}")
        return True
    reasons.append("endpoint evidence mismatch")
    missing.append("confirm matching endpoint evidence")
    return False


def _risk_match_detail(
    lesson: CaseLesson,
    action: Any | None,
    reasons: list[str],
    why: list[str],
    missing: list[str],
) -> bool | None:
    lesson_band = _risk_band(lesson.risk_class)
    if not lesson_band:
        return None
    action_band = _risk_band(getattr(action, "risk", "") if action is not None else "")
    if not action_band:
        missing.append("confirm matching risk class")
        return None
    if lesson_band == action_band:
        why.append(f"risk: {lesson_band}")
        return True
    reasons.append("risk class mismatch")
    missing.append("confirm matching risk class")
    return False


def _access_match_detail(
    required_access: str,
    current_access: str,
    reasons: list[str],
    why: list[str],
    missing: list[str],
) -> bool | None:
    if not required_access or required_access == "none":
        return None
    if _access_satisfies(current_access, required_access):
        why.append(f"access: {current_access}")
        return True
    reasons.append("required access state missing")
    missing.append(f"requires {required_access} access")
    return False


def _normalize_risk_class(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    return text if text in _RISK_BAND_BY_CLASS else ""


def _risk_band(value: Any) -> str:
    return _RISK_BAND_BY_CLASS.get(_normalize_risk_class(value), "")


def _normalize_required_access(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    return _ACCESS_ALIASES.get(text, "")


def _lesson_required_access(lesson: CaseLesson) -> str:
    explicit = _normalize_required_access(lesson.required_access)
    if explicit:
        return explicit
    haystack = " ".join(
        str(value or "").casefold()
        for value in (
            lesson.action_method,
            lesson.action_tool_name,
            lesson.source_type,
            lesson.title,
            *lesson.prerequisites,
        )
    )
    if any(marker in haystack for marker in ("privilege", "privesc", "suid", "post_exploitation")):
        return "user"
    if any(marker in haystack for marker in ("authenticated", "credential", "login", "session cookie")):
        return "credentials"
    return ""


def _mission_access_state(mission: Any) -> str:
    best = "none"
    for credential in getattr(mission, "credentials", []) or []:
        if bool(getattr(credential, "valid", False)):
            best = _higher_access(best, "credentials")
    for host in getattr(mission, "hosts", []) or []:
        level = _normalize_required_access(getattr(host, "access_level", "") or "")
        if level:
            best = _higher_access(best, level)
    return best


def _higher_access(left: str, right: str) -> str:
    left_norm = _normalize_required_access(left) or "none"
    right_norm = _normalize_required_access(right) or "none"
    return (
        right_norm
        if _ACCESS_LEVEL_RANK.get(right_norm, 0) > _ACCESS_LEVEL_RANK.get(left_norm, 0)
        else left_norm
    )


def _access_satisfies(current_access: str, required_access: str) -> bool:
    current = _normalize_required_access(current_access) or "none"
    required = _normalize_required_access(required_access) or "none"
    if required == "credentials":
        return _ACCESS_LEVEL_RANK.get(current, 0) >= _ACCESS_LEVEL_RANK["credentials"]
    return _ACCESS_LEVEL_RANK.get(current, 0) >= _ACCESS_LEVEL_RANK.get(required, 0)


def _failure_mode_compatible(lesson: CaseLesson, action: Any | None) -> bool:
    if lesson.is_success or not lesson.failure_reason or action is None:
        return True
    method = str(getattr(action, "method", "") or "")
    if method in {"missing_tool_install", "host_discovery_retry", "content_discovery_retry", "timeout_retry", "tool_prerequisite_retry"}:
        return True
    return True


def _action_scope_allowed(mission: Any, action: Any | None) -> bool | None:
    if action is None:
        return None
    scope = getattr(mission, "scope", None)
    if scope is None or not hasattr(scope, "is_in_scope"):
        return None
    checked = False
    for key in ("target", "url", "domain"):
        value = str((getattr(action, "arguments", {}) or {}).get(key) or "").strip()
        if not value:
            continue
        checked = True
        if not scope.is_in_scope(value):
            return False
    return True if checked else True


def _service_families_from_values(values: Iterable[Any]) -> set[str]:
    families: set[str] = set()
    text = " ".join(str(value or "").casefold() for value in values)
    markers = {
        "http": ("http", "apache", "nginx", "iis", "php", "tomcat"),
        "ssh": ("ssh", "openssh"),
        "ftp": ("ftp", "vsftpd", "proftpd"),
        "smb": ("smb", "microsoft-ds", "samba", "netbios"),
        "database": ("mysql", "postgres", "postgresql", "mssql", "oracle", "mongodb"),
        "dns": ("dns", "bind", "domain"),
        "smtp": ("smtp", "mail", "postfix", "exim"),
        "ssl": ("ssl", "tls", "https"),
    }
    for family, family_markers in markers.items():
        if any(marker in text for marker in family_markers):
            families.add(family)
    return families


def _path_hints(values: Iterable[Any]) -> set[str]:
    paths: set[str] = set()
    for value in values:
        raw = str(value or "")
        for match in re.finditer(r"(?:https?://[^\s\"'<>]+)|(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)", raw):
            token = match.group(0).rstrip(".,;)")
            parsed = urlparse(token)
            path = parsed.path if parsed.scheme else token
            path = path.rstrip("/") or "/"
            if path and path != "/":
                paths.add(path.casefold())
    return paths


def _mission_endpoint_values(mission: Any) -> list[Any]:
    values: list[Any] = []
    for finding in getattr(mission, "findings", []) or []:
        values.extend([
            getattr(finding, "title", ""),
            getattr(finding, "target", ""),
            getattr(finding, "evidence", ""),
        ])
        for evidence in getattr(finding, "evidence_items", []) or []:
            values.append(getattr(evidence, "snippet", ""))
            metadata = getattr(evidence, "metadata", {}) or {}
            values.extend(metadata.values())
    return values


def build_lesson_from_tool_result(
    tool_name: str,
    arguments: dict[str, Any] | None,
    result: Any,
    *,
    mission: Any | None = None,
    parsed: Any | None = None,
    session_name: str = "",
) -> CaseLesson | None:
    """Create a sanitized reusable lesson from a completed tool result."""
    if tool_name not in _EXPERIENCE_TOOL_NAMES:
        return None

    output = str(getattr(result, "output", "") or "")
    error = str(getattr(result, "error", "") or "")
    combined = f"{error}\n{output}".strip()
    combined_lc = combined.casefold()
    if any(marker in combined_lc for marker in _USER_CONTROLLED_FAILURE_MARKERS):
        return None

    success = bool(getattr(result, "success", False))
    technical_failure = (not success) or any(
        marker in combined_lc for marker in _TECHNICAL_FAILURE_MARKERS
    )
    if not combined and not technical_failure:
        return None

    args = dict(arguments or {})
    target = _target_from_arguments(args)
    parsed_summary = _clip(getattr(parsed, "summary", "") or "", 220)
    evidence = parsed_summary or _first_significant_line(combined)
    outcome = "failure" if technical_failure else "success"
    verb = "failed" if technical_failure else "succeeded"

    return CaseLesson(
        title=f"{tool_name} {verb}{f' for {target}' if target else ''}",
        outcome=outcome,
        action_tool_name=tool_name,
        action_arguments=args,
        platform_tags=_platform_tags(mission),
        target_fingerprints=_target_fingerprints(args, mission),
        service_fingerprints=_service_fingerprints(mission),
        technology_hints=_technology_hints(mission, parsed),
        endpoint_hints=_endpoint_hints(args, mission, parsed),
        evidence=[evidence] if evidence else [],
        failure_reason=_failure_reason(combined) if technical_failure else "",
        risk_class=_result_risk_class(tool_name, result),
        required_access=_result_required_access(result),
        session_name=session_name,
        confidence=0.75 if technical_failure else 0.7,
    )


def _matches_action(lesson: CaseLesson, action: Any | None) -> bool:
    if action is None:
        return False
    tool = str(getattr(action, "tool_name", "") or "")
    method = str(getattr(action, "method", "") or "")
    if lesson.action_tool_name and lesson.action_tool_name == tool:
        return True
    if lesson.action_method and lesson.action_method == method:
        return True
    action_args = dict(getattr(action, "arguments", {}) or {})
    lesson_args = lesson.action_arguments
    return bool(action_args and lesson_args and set(action_args.items()) & set(lesson_args.items()))


def _corroboration_key(lesson: CaseLesson) -> tuple[str, str, frozenset[str]] | None:
    """Signature grouping lessons that confirm the same pattern: same action
    family + outcome + service family. Returns None when there is nothing
    distinctive to corroborate (no family and no service), so unrelated lessons
    are never lumped together."""
    family = (lesson.action_tool_name or lesson.action_method or "").casefold()
    services = frozenset(_service_families_from_values(lesson.service_fingerprints))
    if not family and not services:
        return None
    return (family, lesson.outcome, services)


def corroboration_counts(lessons: Iterable[CaseLesson]) -> dict[str, int]:
    """Map each lesson id to how many stored lessons (including itself) confirm the
    same pattern. Used to give repeatedly-confirmed lessons a bounded ranking
    bonus."""
    keyed: list[tuple[str, tuple[str, str, frozenset[str]] | None]] = []
    counts: Counter[tuple[str, str, frozenset[str]]] = Counter()
    for lesson in lessons:
        key = _corroboration_key(lesson)
        keyed.append((lesson.id, key))
        if key is not None:
            counts[key] += 1
    return {lid: (counts[key] if key is not None else 1) for lid, key in keyed}


def _corroboration_multiplier(corroboration: int) -> float:
    if corroboration <= 1:
        return 1.0
    return 1.0 + min(_MAX_CORROBORATION_BONUS, 0.1 * (corroboration - 1))


def lesson_idf(lessons: Iterable[CaseLesson]) -> dict[str, float]:
    """Inverse-document-frequency weight per fingerprint token across the lesson
    corpus. Distinctive tokens (a specific CVE, path, version) get a high weight;
    ubiquitous ones ('http', 'tcp') tend toward 1.0, so retrieval matches on what
    actually distinguishes a lesson rather than on common words. Smoothed so a
    token present in every lesson weighs ~1.0 (never below), keeping this a
    precision refinement layered on top of the count-based score."""
    documents = [lesson.fingerprint_tokens() for lesson in lessons]
    total = len(documents)
    if total == 0:
        return {}
    document_frequency: Counter[str] = Counter()
    for tokens in documents:
        for token in tokens:
            document_frequency[token] += 1
    return {
        token: math.log((1 + total) / (1 + freq)) + 1.0
        for token, freq in document_frequency.items()
    }


def _lesson_identity(lesson: CaseLesson) -> str:
    return "|".join([
        lesson.outcome,
        lesson.action_tool_name,
        lesson.action_method,
        json.dumps(lesson.action_arguments, sort_keys=True),
        lesson.failure_reason,
        ";".join(lesson.endpoint_hints[:5]),
    ])


def _target_from_arguments(arguments: dict[str, Any]) -> str:
    for key in ("target", "url", "domain", "query", "cve_id"):
        value = str(arguments.get(key) or "").strip()
        if value:
            return _clip(value, 120)
    return ""


def _first_significant_line(text: str) -> str:
    for line in str(text or "").splitlines():
        stripped = " ".join(line.split())
        if stripped:
            return _clip(stripped, 220)
    return ""


def _failure_reason(text: str) -> str:
    for line in str(text or "").splitlines():
        stripped = " ".join(line.split())
        if stripped and any(marker in stripped.casefold() for marker in _TECHNICAL_FAILURE_MARKERS):
            return _clip(stripped, 180)
    return _first_significant_line(text)


def _result_risk_class(tool_name: str, result: Any) -> str:
    metadata = getattr(result, "metadata", {}) or {}
    risk_class = _normalize_risk_class(metadata.get("risk_class"))
    if risk_class:
        return risk_class
    try:
        from secops_agent.core.tools import _BUILTIN_TOOL_RISK_CLASSES

        inferred = _BUILTIN_TOOL_RISK_CLASSES.get(str(tool_name or ""))
        return _normalize_risk_class(getattr(inferred, "value", "") or inferred)
    except Exception:
        return ""


def _result_required_access(result: Any) -> str:
    metadata = getattr(result, "metadata", {}) or {}
    return _normalize_required_access(metadata.get("required_access"))


def _platform_tags(mission: Any | None) -> list[str]:
    text = str(getattr(mission, "name", "") or "").casefold()
    tags = []
    for marker, tag in (
        ("tryhackme", "tryhackme"),
        ("hackthebox", "hackthebox"),
        ("htb", "hackthebox"),
        ("rootme", "rootme"),
        ("portswigger", "portswigger"),
        ("ctf", "ctf"),
    ):
        if marker in text and tag not in tags:
            tags.append(tag)
    return tags


def _target_fingerprints(arguments: dict[str, Any], mission: Any | None) -> list[str]:
    values: list[Any] = []
    for key in ("target", "url", "domain"):
        values.append(arguments.get(key, ""))
    for target in getattr(mission, "targets", []) or []:
        values.append(getattr(target, "value", ""))
    for host in getattr(mission, "hosts", []) or []:
        values.append(getattr(host, "ip", ""))
        values.append(getattr(host, "hostname", ""))
    return _unique_clipped(values, 120)


def _service_fingerprints(mission: Any | None) -> list[str]:
    values: list[str] = []
    services = list(getattr(mission, "services", []) or [])
    for host in getattr(mission, "hosts", []) or []:
        services.extend(getattr(host, "services", []) or [])
    for svc in services:
        values.append(
            " ".join(
                str(part).strip()
                for part in (
                    getattr(svc, "host", ""),
                    getattr(svc, "port", ""),
                    getattr(svc, "service", ""),
                    getattr(svc, "version", ""),
                    getattr(svc, "banner", ""),
                )
                if str(part).strip()
            )
        )
    return _unique_clipped(values, 160)


def _technology_hints(mission: Any | None, parsed: Any | None) -> list[str]:
    values: list[Any] = []
    for finding in getattr(mission, "findings", []) or []:
        values.extend([getattr(finding, "title", ""), getattr(finding, "category", "")])
    for finding in getattr(parsed, "findings", []) or []:
        values.extend([getattr(finding, "title", ""), getattr(finding, "category", "")])
    return _unique_clipped(values, 120)


def _endpoint_hints(arguments: dict[str, Any], mission: Any | None, parsed: Any | None) -> list[str]:
    values: list[Any] = []
    url = str(arguments.get("url") or "").strip()
    if url:
        parsed_url = urlparse(url)
        if parsed_url.path and parsed_url.path != "/":
            values.append(parsed_url.path)
    for source in (mission, parsed):
        for finding in getattr(source, "findings", []) or []:
            for evidence in getattr(finding, "evidence_items", []) or []:
                metadata = getattr(evidence, "metadata", {}) or {}
                values.append(metadata.get("path", ""))
            target = str(getattr(finding, "target", "") or "")
            if target.startswith("/"):
                values.append(target)
    return _unique_clipped(values, 160)


def _unique_clipped(values: Iterable[Any], limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        clipped = _clip(value, limit)
        if not clipped:
            continue
        key = clipped.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(clipped)
    return result


def _mission_tokens(mission: Any) -> set[str]:
    values: list[Any] = [getattr(mission, "name", "")]
    for target in getattr(mission, "targets", []) or []:
        values.extend([getattr(target, "value", ""), getattr(target, "type", "")])
    for host in getattr(mission, "hosts", []) or []:
        values.extend([getattr(host, "ip", ""), getattr(host, "hostname", ""), getattr(host, "os", "")])
        for svc in getattr(host, "services", []) or []:
            values.extend(_service_values(svc))
    for svc in getattr(mission, "services", []) or []:
        values.extend(_service_values(svc))
    for finding in getattr(mission, "findings", []) or []:
        values.extend([
            getattr(finding, "title", ""),
            getattr(finding, "category", ""),
            getattr(finding, "target", ""),
            getattr(finding, "evidence", ""),
        ])
        for evidence in getattr(finding, "evidence_items", []) or []:
            values.append(getattr(evidence, "snippet", ""))
            metadata = getattr(evidence, "metadata", {}) or {}
            values.extend(metadata.values())
    return _tokens(*values)


def _service_values(service: Any) -> list[Any]:
    return [
        getattr(service, "host", ""),
        getattr(service, "port", ""),
        getattr(service, "service", ""),
        getattr(service, "version", ""),
        getattr(service, "banner", ""),
    ]


def _action_tokens(action: Any) -> set[str]:
    args = dict(getattr(action, "arguments", {}) or {})
    return _tokens(
        getattr(action, "title", ""),
        getattr(action, "rationale", ""),
        getattr(action, "tool_name", ""),
        getattr(action, "method", ""),
        *args.values(),
        *list(getattr(action, "evidence", []) or []),
    )


def _copy_lesson(lesson: CaseLesson) -> CaseLesson:
    return CaseLesson.from_dict(lesson.to_dict())


def _parse_created_at(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_expired(value: str) -> bool:
    parsed = _parse_created_at(value)
    if parsed is None:
        return False
    return parsed < datetime.now(timezone.utc)


def _is_older_than(lesson: CaseLesson, max_age_days: int | None) -> bool:
    if max_age_days is None:
        return False
    created = _parse_created_at(lesson.created_at)
    if created is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, int(max_age_days)))
    return created < cutoff


def _matches_purge_filter(
    lesson: CaseLesson,
    *,
    outcome: str | None = None,
    tool_name: str | None = None,
    older_than_days: int | None = None,
) -> bool:
    has_filter = any(value is not None for value in (outcome, tool_name, older_than_days))
    if not has_filter:
        return False
    if outcome is not None and lesson.outcome != str(outcome):
        return False
    if tool_name is not None and lesson.action_tool_name != str(tool_name):
        return False
    if older_than_days is not None and not _is_older_than(lesson, older_than_days):
        return False
    return True


def _hash_target_value(value: str, *, hash_salt: str = "") -> str:
    raw = str(value or "").strip()
    digest = hashlib.sha256(f"{hash_salt}\0{raw}".encode("utf-8")).hexdigest()[:16]
    return f"target_hash:{digest}"


def _should_hash_target_value(value: str) -> bool:
    raw = str(value or "").strip()
    if len(raw) < 3:
        return False
    if raw.startswith("target_hash:"):
        return False
    return True


def _collect_target_values_from_payload(payload: Any) -> set[str]:
    values: set[str] = set()

    def add(value: Any) -> None:
        raw = str(value or "").strip()
        if _should_hash_target_value(raw):
            values.add(raw)

    args = payload.get("action_arguments", {}) if isinstance(payload, dict) else {}
    if isinstance(args, dict):
        for key in _TARGET_ARGUMENT_KEYS:
            add(args.get(key, ""))

    for item in payload.get("target_fingerprints", []) if isinstance(payload, dict) else []:
        add(item)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
            return
        if isinstance(value, list):
            for child in value:
                walk(child)
            return
        if not isinstance(value, str):
            return
        for match in _URL_RE.finditer(value):
            add(match.group(0))
        for match in _IPV4_RE.finditer(value):
            add(match.group(0))

    walk(payload)
    return values


def _replace_targets(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_targets(child, replacements) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_targets(child, replacements) for child in value]
    if not isinstance(value, str):
        return value

    updated = value
    for raw, hashed in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        updated = updated.replace(raw, hashed)
    return updated


def _anonymized_lesson(lesson: CaseLesson, *, hash_salt: str = "") -> CaseLesson:
    payload = lesson.to_dict()
    values = _collect_target_values_from_payload(payload)
    replacements = {
        value: _hash_target_value(value, hash_salt=hash_salt)
        for value in values
        if _should_hash_target_value(value)
    }
    if not replacements:
        return _copy_lesson(lesson)
    return CaseLesson.from_dict(_replace_targets(payload, replacements))


def _raw_target_values(lesson: CaseLesson) -> set[str]:
    payload = lesson.to_dict()
    values = _collect_target_values_from_payload(payload)
    return {
        value for value in values
        if _should_hash_target_value(value) and not value.startswith("target_hash:")
    }
