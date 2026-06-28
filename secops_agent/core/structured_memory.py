"""
Structured memory with knowledge base for the SecOps Agent.

Provides a dual-layer memory system:
  1. ConversationMemory (existing) — sliding window of raw messages
  2. KnowledgeBase (new) — structured data extracted from tool results

The StructuredMemory class combines both and builds a compact context
string for injection into the LLM system prompt.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from secops_agent.core.memory import ConversationMemory, _truncate_output
from secops_agent.core.mission import (
    Credential,
    Finding,
    Host,
    MissionContext,
    Service,
)
from secops_agent.core.planner import MissionPlanner


# ---------------------------------------------------------------------------
# KnowledgeBase — structured store of discovered facts
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """Structured knowledge extracted from tool results during a mission."""

    def __init__(self) -> None:
        self.hosts: Dict[str, Host] = {}
        self.services: Dict[str, Service] = {}
        self.findings: List[Finding] = []
        self.credentials: List[Credential] = []
        self.notes: List[str] = []

    # ---------------------------------------------------------------
    # Integration helpers (called by ToolResultParser)
    # ---------------------------------------------------------------

    def add_host(self, host: Host) -> List[str]:
        """Add or merge a host.  Returns list of change descriptions."""
        changes: List[str] = []
        if host.ip not in self.hosts:
            self.hosts[host.ip] = host
            changes.append(f"New host: {host.ip}")
        else:
            existing = self.hosts[host.ip]
            if host.os and not existing.os:
                existing.os = host.os
                changes.append(f"Host {host.ip}: OS detected → {host.os}")
            if host.hostname and not existing.hostname:
                existing.hostname = host.hostname
                changes.append(f"Host {host.ip}: hostname → {host.hostname}")
            # Merge services
            existing_keys = {s.key for s in existing.services}
            for svc in host.services:
                if svc.key not in existing_keys:
                    existing.services.append(svc)
                    changes.append(f"Host {host.ip}: new service {svc.key}")
        return changes

    def add_service(self, svc: Service) -> List[str]:
        """Add or update a service.  Returns list of change descriptions."""
        changes: List[str] = []
        if svc.key not in self.services:
            self.services[svc.key] = svc
            changes.append(f"New service: {svc.key} ({svc.service} {svc.version})")
        else:
            existing = self.services[svc.key]
            if svc.version and not existing.version:
                existing.version = svc.version
                changes.append(f"Service {svc.key}: version → {svc.version}")
        return changes

    def add_finding(self, finding: Finding) -> List[str]:
        """Add or merge a finding. Returns list of change descriptions."""
        for existing in self.findings:
            if existing.key == finding.key:
                before = existing.to_dict()
                existing.merge_from(finding)
                if existing.to_dict() != before:
                    return [f"Updated finding [{existing.severity.upper()}]: {existing.title}"]
                return []
        self.findings.append(finding)
        return [f"New finding [{finding.severity.upper()}]: {finding.title}"]

    def add_credential(self, cred: Credential) -> List[str]:
        self.credentials.append(cred)
        return [f"New credential: {cred.username}@{cred.host}:{cred.service}"]

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def integrate(self, parsed: "ParsedResult") -> List[str]:
        """Integrate a ParsedResult into the knowledge base.  Returns all changes."""
        changes: List[str] = []
        for host in parsed.hosts_discovered:
            changes.extend(self.add_host(host))
        for svc in parsed.services_discovered:
            changes.extend(self.add_service(svc))
        for finding in parsed.findings:
            changes.extend(self.add_finding(finding))
        return changes

    def to_dict(self) -> Dict[str, Any]:
        """Serialize structured knowledge for session persistence."""
        return {
            "hosts": {
                ip: host.to_dict()
                for ip, host in sorted(self.hosts.items())
            },
            "services": {
                key: service.to_dict()
                for key, service in sorted(self.services.items())
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "credentials": [credential.to_dict() for credential in self.credentials],
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "KnowledgeBase":
        """Restore structured knowledge from a persisted snapshot."""
        kb = cls()
        if not isinstance(data, dict):
            return kb

        raw_hosts = data.get("hosts", {})
        if isinstance(raw_hosts, dict):
            host_items = raw_hosts.values()
        elif isinstance(raw_hosts, list):
            host_items = raw_hosts
        else:
            host_items = []
        for item in host_items:
            if isinstance(item, dict):
                host = Host.from_dict(item)
                kb.hosts[host.ip] = host

        raw_services = data.get("services", {})
        if isinstance(raw_services, dict):
            service_items = raw_services.values()
        elif isinstance(raw_services, list):
            service_items = raw_services
        else:
            service_items = []
        for item in service_items:
            if isinstance(item, dict):
                service = Service.from_dict(item)
                kb.services[service.key] = service

        for item in data.get("findings", []) or []:
            if isinstance(item, dict):
                kb.findings.append(Finding.from_dict(item))

        for item in data.get("credentials", []) or []:
            if isinstance(item, dict):
                kb.credentials.append(Credential.from_dict(item))

        kb.notes = [str(note) for note in data.get("notes", []) or []]
        return kb

    # ---------------------------------------------------------------
    # Query helpers
    # ---------------------------------------------------------------

    def get_open_ports(self, host_ip: str) -> List[Service]:
        """Return all open services for a host."""
        return [s for s in self.services.values()
                if s.host == host_ip and s.state == "open"]

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_attack_surface_summary(self) -> str:
        """One-line summary for quick reference."""
        n_hosts = len(self.hosts)
        n_services = len(self.services)
        n_findings = len(self.findings)
        crit = len(self.get_findings_by_severity("critical"))
        high = len(self.get_findings_by_severity("high"))
        return (
            f"{n_hosts} host(s), {n_services} service(s), "
            f"{n_findings} finding(s) ({crit} critical, {high} high)"
        )

    # ---------------------------------------------------------------
    # Prompt generation
    # ---------------------------------------------------------------

    def build_summary(self, max_services: int = 20, max_findings: int = 10) -> str:
        """Build a compact Markdown summary for injection into the system prompt."""
        lines: List[str] = []

        if self.hosts or self.services:
            lines.append("## Known Attack Surface")
            lines.append(f"Hosts: {len(self.hosts)} | Services: {len(self.services)}")
            for ip, host in list(self.hosts.items())[:10]:
                os_tag = f" ({host.os})" if host.os else ""
                lines.append(f"  - **{ip}**{os_tag}")
                for svc in host.services[:15]:
                    vuln = " ⚠" if svc.vulns else ""
                    lines.append(f"    {svc.port}/{svc.protocol} {svc.service} {svc.version}{vuln}")
            # Orphan services (not linked to a host)
            host_ips = set(self.hosts.keys())
            orphans = [s for s in self.services.values() if s.host not in host_ips]
            for svc in orphans[:max_services]:
                lines.append(f"  - {svc.host}:{svc.port}/{svc.protocol} {svc.service} {svc.version}")
            lines.append("")

        if self.findings:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_f = sorted(self.findings, key=lambda f: sev_order.get(f.severity, 5))
            lines.append(f"## Findings ({len(self.findings)})")
            for f in sorted_f[:max_findings]:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f.severity, "⚪")
                conf = " ✅" if f.confirmed else ""
                evidence_count = f" · evidence:{len(f.evidence_items)}" if f.evidence_items else ""
                lines.append(f"  {icon} [{f.severity.upper()}] {f.title} — {f.target}{conf}{evidence_count}")
            if len(self.findings) > max_findings:
                lines.append(f"  … +{len(self.findings) - max_findings} more")
            lines.append("")

        if self.credentials:
            lines.append(f"## Credentials ({len(self.credentials)})")
            for c in self.credentials[:5]:
                lines.append(f"  - {c.username}@{c.host}:{c.service} ({c.secret_type}, valid={c.valid})")
            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Avoid circular import — ParsedResult is defined in result_parser.py
# but used here; we import it lazily / accept it via duck typing.
# ---------------------------------------------------------------------------

class ParsedResult:
    """Minimal protocol expected by KnowledgeBase.integrate()."""
    hosts_discovered: List[Host]
    services_discovered: List[Service]
    findings: List[Finding]


# ---------------------------------------------------------------------------
# StructuredMemory — combines conversation + knowledge + mission
# ---------------------------------------------------------------------------

class StructuredMemory:
    """Dual-layer memory: raw conversation + structured knowledge base.

    Builds the full context string injected into the LLM system prompt.
    """

    def __init__(
        self,
        conversation: ConversationMemory | None = None,
        mission: MissionContext | None = None,
        planner: "MissionPlanner | None" = None,
    ) -> None:
        self.conversation = conversation or ConversationMemory()
        self.mission = mission
        self.knowledge = KnowledgeBase()
        self._planner = planner

    def to_dict(self) -> Dict[str, Any]:
        """Serialize mission state and knowledge base for session persistence."""
        return {
            "mission": self.mission.to_dict() if self.mission else None,
            "knowledge": self.knowledge.to_dict(),
        }

    def load_dict(self, data: Dict[str, Any] | None) -> "StructuredMemory":
        """Load mission state and knowledge base into this instance."""
        if not isinstance(data, dict):
            return self

        mission_data = data.get("mission")
        if isinstance(mission_data, dict):
            self.mission = MissionContext.from_dict(mission_data)
        elif self.mission is None:
            self.mission = MissionContext()

        self.knowledge = KnowledgeBase.from_dict(data.get("knowledge"))
        return self

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any] | None,
        *,
        conversation: ConversationMemory | None = None,
    ) -> "StructuredMemory":
        memory = cls(conversation=conversation)
        memory.load_dict(data)
        return memory

    def _build_mission_state_summary(self) -> str:
        """Build mission metadata without duplicating knowledge base entries."""
        if not self.mission:
            return ""

        mission = self.mission
        phase = mission.phase.value if hasattr(mission.phase, "value") else str(mission.phase)
        lines: List[str] = [
            "## Mission State",
            f"- **Name:** {mission.name}",
            f"- **Phase:** {phase.upper()}",
            f"- **Type:** {mission.engagement_type}",
        ]
        if mission.phase_reason:
            lines.append(f"- **Phase reason:** {mission.phase_reason}")
        if mission.targets:
            targets = ", ".join(t.value for t in mission.targets if t.in_scope)
            if targets:
                lines.append(f"- **Targets:** {targets}")
        if mission.blocked_reasons:
            lines.append("- **Blocked:** " + "; ".join(mission.blocked_reasons[-3:]))
        if mission.completed_objectives:
            lines.append("- **Completed:** " + "; ".join(mission.completed_objectives[-3:]))
        recent_actions = (
            mission.recent_action_trace()
            if hasattr(mission, "recent_action_trace")
            else []
        )
        if recent_actions:
            lines.append("- **Recent actions:**")
            for entry in recent_actions:
                lines.append(f"  {entry.prompt_line()}")
        return "\n".join(lines)

    def build_context_for_llm(
        self,
        budget_tokens: int = 16_000,
        include_conversation: bool = True,
    ) -> str:
        """Assemble a compact context block for the system prompt.

        Budget is split roughly as:
          - Mission state     ~500 tokens
          - Knowledge base    ~2000 tokens
          - Recent results    ~2000 tokens  (handled by conversation window)
          - Conversation tail fills the remainder
        """
        sections: List[str] = []

        # 1. Mission state (compact). If the knowledge base already has the
        # attack surface, keep mission metadata only to avoid duplicate prompt
        # sections.
        if self.mission:
            has_kb = bool(
                self.knowledge.hosts
                or self.knowledge.services
                or self.knowledge.findings
                or self.knowledge.credentials
            )
            sections.append(
                self._build_mission_state_summary()
                if has_kb
                else self.mission.build_prompt_summary()
            )

        # 2. Knowledge base (structured)
        kb_summary = self.knowledge.build_summary()
        if kb_summary:
            sections.append(kb_summary)

        # 3. Deterministic candidate actions. These are advisory only; tool
        # execution remains governed by the agent loop and permission engine.
        if self.mission:
            planner = self._planner or MissionPlanner()
            plan_summary = planner.build_prompt_summary(self.mission)
            if plan_summary:
                sections.append(plan_summary)

        # 4. Recent conversation (fits remaining budget). Agent callers that
        # already pass the transcript as model messages should disable this.
        used = sum(len(s) for s in sections) // 4  # rough token estimate
        remaining = max(2000, budget_tokens - used)
        recent_msgs = (
            self.conversation.trim_to_budget(remaining)
            if include_conversation
            else []
        )
        if recent_msgs:
            conv_lines = ["## Recent Conversation"]
            for msg in recent_msgs[-8:]:  # Last 8 messages max
                role_tag = {"user": "👤", "model": "🤖", "tool": "🔧"}.get(msg.role, "?")
                content = msg.content[:500] if msg.content else ""
                if msg.tool_results:
                    for tr in msg.tool_results:
                        content = f"[{tr['name']}] {tr['content'][:300]}"
                if content:
                    conv_lines.append(f"  {role_tag} {content}")
            sections.append("\n".join(conv_lines))

        return "\n\n".join(s for s in sections if s.strip())

    def sync_to_mission(self) -> None:
        """Push knowledge base data back into the MissionContext for persistence."""
        if not self.mission:
            return
        for f in self.knowledge.findings:
            self.mission.upsert_finding(f)
        # Sync hosts
        for ip, host in self.knowledge.hosts.items():
            self.mission.add_host(host)
        # Sync services
        for key, svc in self.knowledge.services.items():
            self.mission.add_service(svc)
        self.mission.refresh_phase_from_state()
