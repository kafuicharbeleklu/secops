"""
Mission context, data models, and phase management for autonomous pentesting.

This module provides the structured data layer that transforms the agent from
a reactive chatbot into a mission-aware pentesting system.  All dataclasses
are JSON-serialisable via `to_dict()` / `from_dict()` for session persistence.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PentestPhase(str, Enum):
    """Ordered phases of a penetration testing engagement."""

    SCOPING = "scoping"
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"

    # --- helpers ---

    _phase_order = None  # type: ignore[assignment]

    @classmethod
    def _order(cls) -> Dict[str, int]:
        return {
            p.value: i
            for i, p in enumerate(cls)
            if isinstance(p.value, str) and p.name != "_phase_order"
        }

    @property
    def rank(self) -> int:
        return self._order().get(self.value, -1)

    def next_phase(self) -> Optional["PentestPhase"]:
        """Return the next phase in sequence, or *None* if already at REPORTING."""
        order = self._order()
        idx = order.get(self.value, -1) + 1
        for phase in PentestPhase:
            if isinstance(phase.value, str) and order.get(phase.value) == idx:
                return phase
        return None


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementType(str, Enum):
    BLACK_BOX = "black-box"
    GREY_BOX = "grey-box"
    WHITE_BOX = "white-box"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------

@dataclass
class Target:
    """A single target (IP, domain, CIDR, or URL) inside the engagement scope."""

    value: str
    type: str = "ip"  # ip | domain | cidr | url
    in_scope: bool = True
    notes: str = ""

    # --- serialisation ---

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "type": self.type, "in_scope": self.in_scope, "notes": self.notes}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Target":
        return cls(**d)


_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp for persisted mission state."""
    return datetime.now(timezone.utc).isoformat()


def _clean_scope_value(value: str) -> str:
    return str(value or "").strip().strip("'\"").rstrip(".")


def _scope_url(value: str):
    raw = _clean_scope_value(value)
    if not raw:
        return urlparse("")
    if _URL_SCHEME_RE.match(raw):
        return urlparse(raw)
    return urlparse(f"//{raw}")


def _scope_host(value: str) -> str:
    raw = _clean_scope_value(value)
    if not raw:
        return ""
    try:
        ipaddress.ip_network(raw, strict=False)
        return ""
    except ValueError:
        pass

    parsed = _scope_url(raw)
    host = parsed.hostname or raw
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if "/" in host:
        host = host.split("/", 1)[0]
    if host.count(":") == 1 and host.rsplit(":", 1)[-1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host.strip("[]").lower().rstrip(".")


def _scope_path(value: str) -> str:
    raw = _clean_scope_value(value)
    if not raw or not _URL_SCHEME_RE.match(raw):
        return ""
    path = _scope_url(raw).path or ""
    return "" if path == "/" else path.rstrip("/")


def _scope_network(value: str):
    raw = _clean_scope_value(value)
    if not raw:
        return None
    candidates = [raw]
    host = _scope_host(raw)
    if host:
        candidates.append(host)
    for candidate in candidates:
        try:
            return ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
    return None


def _host_matches(scope_host: str, value_host: str) -> bool:
    if not scope_host or not value_host:
        return False
    if scope_host.startswith("*."):
        base = scope_host[2:]
        return value_host.endswith(f".{base}")
    return value_host == scope_host or value_host.endswith(f".{scope_host}")


def _path_matches(scope_entry: str, value: str) -> bool:
    entry_path = _scope_path(scope_entry)
    if not entry_path:
        return True
    value_path = _scope_path(value)
    return value_path == entry_path or value_path.startswith(f"{entry_path}/")


def _scope_entry_matches(scope_entry: str, value: str, *, out_of_scope: bool = False) -> bool:
    entry = _clean_scope_value(scope_entry)
    candidate = _clean_scope_value(value)
    if not entry or not candidate:
        return False

    entry_net = _scope_network(entry)
    candidate_net = _scope_network(candidate)
    if entry_net and candidate_net:
        return entry_net.overlaps(candidate_net) if out_of_scope else candidate_net.subnet_of(entry_net)

    entry_host = _scope_host(entry)
    candidate_host = _scope_host(candidate)
    if entry_host and candidate_host and _host_matches(entry_host, candidate_host):
        return _path_matches(entry, candidate)

    return entry.casefold() == candidate.casefold()


@dataclass
class Scope:
    """Engagement scope — what the agent is and is not authorised to touch."""

    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)

    def has_explicit_in_scope(self) -> bool:
        return any(_clean_scope_value(entry) for entry in self.in_scope)

    def matches_out_of_scope(self, value: str) -> bool:
        return any(
            _scope_entry_matches(entry, value, out_of_scope=True)
            for entry in self.out_of_scope
        )

    def matches_in_scope(self, value: str) -> bool:
        return any(_scope_entry_matches(entry, value) for entry in self.in_scope)

    def is_in_scope(self, value: str) -> bool:
        """Return true only when a target is authorized by scope rules.

        Matching supports IPs, CIDRs, domains, subdomains, URLs, and URL path
        prefixes. Out-of-scope entries always win. When no in-scope entries are
        configured, the scope remains permissive except for explicit
        out-of-scope blocks to preserve existing interactive behavior.
        """
        if not _clean_scope_value(value):
            return False
        if self.matches_out_of_scope(value):
            return False
        if not self.has_explicit_in_scope():
            return True
        return self.matches_in_scope(value)

    def to_dict(self) -> Dict[str, Any]:
        return {"in_scope": self.in_scope, "out_of_scope": self.out_of_scope, "rules": self.rules}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Scope":
        return cls(**d)


@dataclass
class Service:
    """A discovered network service."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"
    banner: str = ""
    vulns: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host, "port": self.port, "protocol": self.protocol,
            "service": self.service, "version": self.version, "state": self.state,
            "banner": self.banner, "vulns": list(self.vulns),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Service":
        return cls(**d)


@dataclass
class Host:
    """A discovered host."""

    ip: str
    hostname: str = ""
    os: str = ""
    role: str = ""
    services: List[Service] = field(default_factory=list)
    access_level: str = "none"  # none | user | root | admin

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip, "hostname": self.hostname, "os": self.os,
            "role": self.role, "access_level": self.access_level,
            "services": [s.to_dict() for s in self.services],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Host":
        data = dict(d)
        svcs = [Service.from_dict(s) for s in data.pop("services", [])]
        return cls(services=svcs, **data)


@dataclass
class Credential:
    """A discovered credential."""

    username: str
    secret: str  # password, hash, key …
    secret_type: str = "password"  # password | hash | key | token
    host: str = ""
    service: str = ""
    valid: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username, "secret": "***REDACTED***",
            "secret_type": self.secret_type, "host": self.host,
            "service": self.service, "valid": self.valid, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Credential":
        return cls(**d)


@dataclass
class Evidence:
    """A structured proof snippet attached to a finding."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str = ""
    source_tool: str = ""
    target: str = ""
    snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now_iso)

    @property
    def key(self) -> str:
        parts = (self.title, self.source_tool, self.target, self.snippet[:500])
        return "|".join(" ".join(str(part).casefold().split()) for part in parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "source_tool": self.source_tool,
            "target": self.target,
            "snippet": self.snippet[:2000],
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(
            id=d.get("id", uuid.uuid4().hex[:8]),
            title=d.get("title", ""),
            source_tool=d.get("source_tool") or d.get("tool_used", ""),
            target=d.get("target", ""),
            snippet=d.get("snippet") or d.get("evidence", ""),
            metadata=dict(d.get("metadata", {}) or {}),
            timestamp=d.get("timestamp", _utc_now_iso()),
        )


@dataclass
class Finding:
    """A vulnerability or notable observation discovered during the mission."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str = ""
    severity: str = "info"  # critical | high | medium | low | info
    category: str = ""      # sqli, xss, rce, misconfig, info …
    target: str = ""        # host / URL affected
    evidence: str = ""      # raw proof
    tool_used: str = ""
    remediation: str = ""
    phase: str = ""
    confirmed: bool = False
    timestamp: str = field(default_factory=_utc_now_iso)
    evidence_items: List[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        items: List[Evidence] = []
        for item in self.evidence_items:
            if isinstance(item, Evidence):
                items.append(item)
            elif isinstance(item, dict):
                items.append(Evidence.from_dict(item))
        self.evidence_items = items

        if self.evidence:
            self.add_evidence(Evidence(
                title=self.title,
                source_tool=self.tool_used,
                target=self.target,
                snippet=self.evidence,
            ))

    @property
    def key(self) -> str:
        parts = (self.title, self.target, self.category, self.tool_used)
        return "|".join(" ".join(str(part).casefold().split()) for part in parts)

    def add_evidence(self, evidence: Evidence) -> None:
        if not evidence.snippet:
            return
        if not evidence.title:
            evidence.title = self.title
        if not evidence.source_tool:
            evidence.source_tool = self.tool_used
        if not evidence.target:
            evidence.target = self.target
        existing_keys = {item.key for item in self.evidence_items}
        if evidence.key not in existing_keys:
            self.evidence_items.append(evidence)

    def merge_from(self, other: "Finding") -> None:
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_order.get(other.severity, 0) > severity_order.get(self.severity, 0):
            self.severity = other.severity
        for attr in ("category", "target", "tool_used", "remediation", "phase"):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
        if other.evidence and other.evidence not in self.evidence:
            self.evidence = (
                f"{self.evidence}\n{other.evidence}" if self.evidence else other.evidence
            )[:2000]
        for evidence in other.evidence_items:
            self.add_evidence(evidence)
        self.confirmed = self.confirmed or other.confirmed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "category": self.category, "target": self.target,
            "evidence": self.evidence[:2000],  # cap evidence in serialised form
            "tool_used": self.tool_used, "remediation": self.remediation,
            "phase": self.phase, "confirmed": self.confirmed,
            "timestamp": self.timestamp,
            "evidence_items": [item.to_dict() for item in self.evidence_items[:20]],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        data = dict(d)
        data["evidence_items"] = [
            Evidence.from_dict(item)
            for item in data.get("evidence_items", []) or []
            if isinstance(item, dict)
        ]
        return cls(**data)


@dataclass
class PhaseTransition:
    """Records a phase change during the mission."""

    from_phase: str
    to_phase: str
    reason: str = ""
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {"from_phase": self.from_phase, "to_phase": self.to_phase,
                "reason": self.reason, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PhaseTransition":
        return cls(**d)


_SENSITIVE_ARGUMENT_MARKERS = (
    "api_key",
    "apikey",
    "auth",
    "credential",
    "key",
    "password",
    "secret",
    "token",
)


def _redact_trace_value(value: Any, key: str = "") -> Any:
    """Return a JSON-safe, redacted representation for persisted action traces."""
    lowered_key = str(key or "").casefold()
    if any(marker in lowered_key for marker in _SENSITIVE_ARGUMENT_MARKERS):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {
            str(item_key): _redact_trace_value(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_redact_trace_value(item, key) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        text = str(value) if isinstance(value, str) else value
        if isinstance(text, str) and len(text) > 500:
            return text[:500] + "..."
        return text
    return str(value)[:500]


@dataclass
class ActionTraceEntry:
    """Auditable, compact record of one ReAct action step.

    This stores decisions and structured deltas, not raw tool output.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    turn_id: str = ""
    source: str = "llm"  # llm | local_preflight | planner | user_selection
    phase: str = ""
    tool_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    permission: str = ""
    risk_class: str = ""
    status: str = "proposed"  # proposed | blocked | denied | running | succeeded | failed
    user_intent: str = ""
    result_summary: str = ""
    error: str = ""
    state_changes: List[str] = field(default_factory=list)
    suggested_actions: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=_utc_now_iso)
    completed_at: str = ""
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "turn_id": self.turn_id,
            "source": self.source,
            "phase": self.phase,
            "tool_name": self.tool_name,
            "arguments": _redact_trace_value(self.arguments),
            "permission": self.permission,
            "risk_class": self.risk_class,
            "status": self.status,
            "user_intent": str(self.user_intent or "")[:500],
            "result_summary": str(self.result_summary or "")[:1000],
            "error": str(self.error or "")[:1000],
            "state_changes": [str(change)[:500] for change in self.state_changes[:20]],
            "suggested_actions": [
                _redact_trace_value(action)
                for action in self.suggested_actions[:10]
                if isinstance(action, dict)
            ],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "execution_time": self.execution_time,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ActionTraceEntry":
        return cls(
            id=d.get("id", uuid.uuid4().hex[:8]),
            turn_id=d.get("turn_id", ""),
            source=d.get("source", "llm"),
            phase=d.get("phase", ""),
            tool_name=d.get("tool_name", ""),
            arguments=dict(d.get("arguments", {}) or {}),
            permission=d.get("permission", ""),
            risk_class=d.get("risk_class", ""),
            status=d.get("status", "proposed"),
            user_intent=d.get("user_intent", ""),
            result_summary=d.get("result_summary", ""),
            error=d.get("error", ""),
            state_changes=[str(change) for change in d.get("state_changes", []) or []],
            suggested_actions=[
                dict(action)
                for action in d.get("suggested_actions", []) or []
                if isinstance(action, dict)
            ],
            started_at=d.get("started_at", _utc_now_iso()),
            completed_at=d.get("completed_at", ""),
            execution_time=float(d.get("execution_time", 0.0) or 0.0),
        )

    def prompt_line(self) -> str:
        detail = self.result_summary or self.error
        if not detail and self.state_changes:
            detail = self.state_changes[0]
        suffix = f": {' '.join(str(detail).split())[:160]}" if detail else ""
        return f"- {self.tool_name or 'action'} [{self.status}] via {self.source}{suffix}"


# ---------------------------------------------------------------------------
# Mission context — the "brain state" of an engagement
# ---------------------------------------------------------------------------

@dataclass
class MissionContext:
    """Top-level state of a pentesting mission.

    Injected into the LLM system prompt to give the agent awareness of what has
    been found, what phase it is in, and what is authorised.
    """

    # Identity
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = "Unnamed mission"
    started_at: str = field(default_factory=_utc_now_iso)

    # Scope
    targets: List[Target] = field(default_factory=list)
    scope: Scope = field(default_factory=Scope)
    engagement_type: str = EngagementType.BLACK_BOX.value

    # Phase
    phase: PentestPhase = PentestPhase.SCOPING
    phase_reason: str = "Awaiting authorized scope and target definition."
    phase_history: List[PhaseTransition] = field(default_factory=list)

    # Knowledge
    findings: List[Finding] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)

    # Plan (free-form for now; will be structured in Phase 3)
    completed_objectives: List[str] = field(default_factory=list)
    blocked_reasons: List[str] = field(default_factory=list)
    action_trace: List[ActionTraceEntry] = field(default_factory=list)

    # ---------------------------------------------------------------
    # Convenience helpers
    # ---------------------------------------------------------------

    def add_target(self, value: str, target_type: str = "ip", **kwargs: Any) -> Target:
        t = Target(value=value, type=target_type, **kwargs)
        self.targets.append(t)
        self.scope.in_scope.append(value)
        return t

    def transition_phase(self, new_phase: PentestPhase, reason: str = "") -> None:
        old = self.phase
        if old == new_phase:
            if reason:
                self.phase_reason = reason
            return
        self.phase_history.append(PhaseTransition(
            from_phase=old.value,
            to_phase=new_phase.value,
            reason=reason,
        ))
        self.phase = new_phase
        if reason:
            self.phase_reason = reason

    def infer_phase_from_state(self) -> tuple[PentestPhase, str]:
        """Infer the mission phase from structured state.

        This is deliberately conservative: passive references such as CVE or
        ExploitDB results do not move the mission into exploitation.
        """
        has_targets = any(t.in_scope for t in self.targets) or bool(self.scope.in_scope)
        has_hosts = bool(self.hosts)
        has_open_services = any(s.state == "open" for s in self.services)
        has_access = bool(self.credentials) or any(
            h.access_level and h.access_level != "none" for h in self.hosts
        )
        actionable_categories = {"exploit_reference", "cve_reference"}
        has_actionable_findings = any(
            f.severity != "info" and f.category not in actionable_categories
            for f in self.findings
        )

        if has_access:
            return (
                PentestPhase.POST_EXPLOITATION,
                "Credentials or host access are recorded; preserve evidence and assess impact.",
            )
        if has_actionable_findings:
            return (
                PentestPhase.VULNERABILITY,
                "Actionable findings exist and need validation, prioritization, and remediation detail.",
            )
        if has_open_services:
            return (
                PentestPhase.ENUMERATION,
                "Open services are known; enumerate service details and attack surface.",
            )
        if has_hosts or has_targets:
            return (
                PentestPhase.RECON,
                "In-scope targets or hosts are known; continue reconnaissance before deeper testing.",
            )
        return (
            PentestPhase.SCOPING,
            "Awaiting authorized scope and target definition.",
        )

    def refresh_phase_from_state(self, allow_regression: bool = False) -> bool:
        """Update phase from current state. Returns True when phase/reason changed."""
        inferred, reason = self.infer_phase_from_state()
        old_phase = self.phase
        old_reason = self.phase_reason

        if allow_regression or inferred.rank > self.phase.rank:
            self.transition_phase(inferred, reason)
        elif inferred == self.phase and reason:
            self.phase_reason = reason

        return old_phase != self.phase or old_reason != self.phase_reason

    def upsert_finding(self, finding: Finding) -> Finding:
        if not finding.phase:
            finding.phase = self.phase.value
        for existing in self.findings:
            if existing.key == finding.key:
                existing.merge_from(finding)
                return existing
        self.findings.append(finding)
        return finding

    def add_finding(self, **kwargs: Any) -> Finding:
        kwargs.setdefault("phase", self.phase.value)
        f = Finding(**kwargs)
        return self.upsert_finding(f)

    def add_service(self, svc: Service) -> None:
        # Deduplicate by key
        existing_keys = {s.key for s in self.services}
        if svc.key not in existing_keys:
            self.services.append(svc)

    def add_host(self, host: Host) -> None:
        existing_ips = {h.ip for h in self.hosts}
        if host.ip not in existing_ips:
            self.hosts.append(host)
        else:
            # Merge services into existing host
            for existing in self.hosts:
                if existing.ip == host.ip:
                    existing_keys = {s.key for s in existing.services}
                    for svc in host.services:
                        if svc.key not in existing_keys:
                            existing.services.append(svc)
                    if host.os and not existing.os:
                        existing.os = host.os
                    if host.hostname and not existing.hostname:
                        existing.hostname = host.hostname
                    break

    def add_action_trace(self, entry: ActionTraceEntry, max_entries: int = 200) -> ActionTraceEntry:
        self.action_trace.append(entry)
        if len(self.action_trace) > max_entries:
            del self.action_trace[: len(self.action_trace) - max_entries]
        return entry

    def recent_action_trace(self, limit: int = 5) -> List[ActionTraceEntry]:
        return self.action_trace[-max(0, limit):] if limit else []

    # ---------------------------------------------------------------
    # Compact summary for the LLM system prompt
    # ---------------------------------------------------------------

    def build_prompt_summary(self, max_findings: int = 10) -> str:
        """Build a compact Markdown summary suitable for system prompt injection."""
        lines: List[str] = []
        lines.append("## Mission State")
        lines.append(f"- **Name:** {self.name}")
        lines.append(f"- **Phase:** {self.phase.value.upper()}")
        if self.phase_reason:
            lines.append(f"- **Phase reason:** {self.phase_reason}")
        lines.append(f"- **Type:** {self.engagement_type}")
        if self.targets:
            lines.append(f"- **Targets:** {', '.join(t.value for t in self.targets if t.in_scope)}")
        lines.append("")

        # Hosts & services
        if self.hosts or self.services:
            lines.append("## Known Attack Surface")
            lines.append(f"Hosts discovered: {len(self.hosts)}")
            for h in self.hosts[:10]:
                os_info = f" ({h.os})" if h.os else ""
                lines.append(f"  - **{h.ip}**{os_info}")
                for s in h.services[:15]:
                    vuln_flag = " ⚠" if s.vulns else ""
                    lines.append(f"    - {s.port}/{s.protocol} {s.service} {s.version}{vuln_flag}")
            # Standalone services not linked to a host
            host_ips = {h.ip for h in self.hosts}
            orphan_svcs = [s for s in self.services if s.host not in host_ips]
            for s in orphan_svcs[:10]:
                lines.append(f"  - {s.host}:{s.port}/{s.protocol} {s.service} {s.version}")
            lines.append("")

        # Findings
        if self.findings:
            lines.append(f"## Findings ({len(self.findings)})")
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))
            for f in sorted_findings[:max_findings]:
                flag = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "⚪")
                confirmed = " ✅" if f.confirmed else ""
                evidence_count = f" · evidence:{len(f.evidence_items)}" if f.evidence_items else ""
                lines.append(f"  {flag} [{f.severity.upper()}] {f.title} — {f.target}{confirmed}{evidence_count}")
            if len(self.findings) > max_findings:
                lines.append(f"  … and {len(self.findings) - max_findings} more")
            lines.append("")

        # Blocked
        if self.blocked_reasons:
            lines.append("## Blocked")
            for r in self.blocked_reasons[-5:]:
                lines.append(f"  - {r}")
            lines.append("")

        if self.action_trace:
            lines.append("## Recent Actions")
            for entry in self.recent_action_trace():
                lines.append(f"  {entry.prompt_line()}")
            lines.append("")

        return "\n".join(lines)

    # ---------------------------------------------------------------
    # Serialisation
    # ---------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "started_at": self.started_at,
            "targets": [t.to_dict() for t in self.targets],
            "scope": self.scope.to_dict(),
            "engagement_type": self.engagement_type,
            "phase": self.phase.value,
            "phase_reason": self.phase_reason,
            "phase_history": [p.to_dict() for p in self.phase_history],
            "findings": [f.to_dict() for f in self.findings],
            "services": [s.to_dict() for s in self.services],
            "hosts": [h.to_dict() for h in self.hosts],
            "credentials": [c.to_dict() for c in self.credentials],
            "completed_objectives": list(self.completed_objectives),
            "blocked_reasons": list(self.blocked_reasons),
            "action_trace": [entry.to_dict() for entry in self.action_trace],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MissionContext":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            started_at=d.get("started_at", ""),
            targets=[Target.from_dict(t) for t in d.get("targets", [])],
            scope=Scope.from_dict(d.get("scope", {})),
            engagement_type=d.get("engagement_type", EngagementType.BLACK_BOX.value),
            phase=PentestPhase(d.get("phase", "scoping")),
            phase_reason=d.get("phase_reason", "Awaiting authorized scope and target definition."),
            phase_history=[PhaseTransition.from_dict(p) for p in d.get("phase_history", [])],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            services=[Service.from_dict(s) for s in d.get("services", [])],
            hosts=[Host.from_dict(h) for h in d.get("hosts", [])],
            credentials=[Credential.from_dict(c) for c in d.get("credentials", [])],
            completed_objectives=d.get("completed_objectives", []),
            blocked_reasons=d.get("blocked_reasons", []),
            action_trace=[
                ActionTraceEntry.from_dict(entry)
                for entry in d.get("action_trace", []) or []
                if isinstance(entry, dict)
            ],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> "MissionContext":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
