"""Attack Graph Planner — generates structured multi-step attack plans from findings.

Analyzes accumulated findings (ports, services, vulnerabilities, credentials)
and produces an ordered attack plan with dependencies and priorities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AttackPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


_PRIORITY_SCORE = {
    AttackPriority.CRITICAL: 90.0,
    AttackPriority.HIGH: 72.0,
    AttackPriority.MEDIUM: 50.0,
    AttackPriority.LOW: 30.0,
}

_TOOL_RISK = {
    "execute_admin_command": "high",
    "execute_command": "medium",
    "exploit_workflow": "high",
    "search_exploit": "medium",
    "test_credentials": "high",
    "scan_target": "medium",
    "enumerate_web": "medium",
    "enumerate_dns": "medium",
    "analyze_service": "medium",
}

_RISK_PENALTY = {
    "low": 0.0,
    "medium": 6.0,
    "high": 14.0,
    "critical": 24.0,
}


@dataclass
class AttackStep:
    """A single step in an attack plan."""

    index: int
    name: str
    tool: str
    arguments: dict = field(default_factory=dict)
    priority: AttackPriority = AttackPriority.MEDIUM
    depends_on: list[int] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    rationale: str = ""
    score: float = 0.0
    risk: str = "medium"

    @property
    def signature(self) -> tuple:
        normalized_args = tuple(
            sorted(
                (str(key), str(value))
                for key, value in (self.arguments or {}).items()
            )
        )
        return (self.tool, normalized_args)


@dataclass
class AttackPlan:
    """An ordered attack plan derived from findings analysis."""

    target: str
    steps: list[AttackStep] = field(default_factory=list)
    phase: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    @property
    def pending_steps(self) -> list[AttackStep]:
        return [s for s in self.steps if s.status == StepStatus.PENDING]

    @property
    def next_step(self) -> "AttackStep | None":
        """Return the next actionable step (pending with all deps satisfied)."""
        done_indices = {
            s.index for s in self.steps
            if s.status in (StepStatus.DONE, StepStatus.SKIPPED)
        }
        actionable = []
        for step in self.steps:
            if step.status != StepStatus.PENDING:
                continue
            if all(dep in done_indices for dep in step.depends_on):
                actionable.append(step)
        if not actionable:
            return None
        if any(step.score > 0 for step in actionable):
            return max(actionable, key=lambda step: (step.score, -self.steps.index(step)))
        return actionable[0]

    def mark_done(self, index: int) -> None:
        for step in self.steps:
            if step.index == index:
                step.status = StepStatus.DONE
                return

    def mark_skipped(self, index: int) -> None:
        for step in self.steps:
            if step.index == index:
                step.status = StepStatus.SKIPPED
                return

    def mark_failed(self, index: int) -> None:
        for step in self.steps:
            if step.index == index:
                step.status = StepStatus.FAILED
                return

    @property
    def is_complete(self) -> bool:
        return all(
            s.status in (StepStatus.DONE, StepStatus.SKIPPED, StepStatus.FAILED)
            for s in self.steps
        )

    @property
    def progress_summary(self) -> str:
        total = len(self.steps)
        done = sum(1 for s in self.steps if s.status == StepStatus.DONE)
        skipped = sum(1 for s in self.steps if s.status == StepStatus.SKIPPED)
        failed = sum(1 for s in self.steps if s.status == StepStatus.FAILED)
        pending = sum(1 for s in self.steps if s.status == StepStatus.PENDING)
        running = sum(1 for s in self.steps if s.status == StepStatus.RUNNING)
        return (
            f"{done}/{total} termine "
            f"({skipped} ignore, {failed} echec, {running} en cours, {pending} en attente)"
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "phase": self.phase,
            "created_at": self.created_at,
            "steps": [
                {
                    "index": step.index,
                    "name": step.name,
                    "tool": step.tool,
                    "arguments": dict(step.arguments),
                    "priority": step.priority.value,
                    "depends_on": list(step.depends_on),
                    "status": step.status.value,
                    "rationale": step.rationale,
                    "score": step.score,
                    "risk": step.risk,
                }
                for step in self.steps
            ],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AttackPlan | None":
        if not isinstance(payload, dict):
            return None
        steps = []
        for entry in payload.get("steps", []):
            try:
                priority = AttackPriority(entry.get("priority", AttackPriority.MEDIUM.value))
            except ValueError:
                priority = AttackPriority.MEDIUM
            try:
                status = StepStatus(entry.get("status", StepStatus.PENDING.value))
            except ValueError:
                status = StepStatus.PENDING
            steps.append(
                AttackStep(
                    index=int(entry.get("index", len(steps))),
                    name=entry.get("name", ""),
                    tool=entry.get("tool", ""),
                    arguments=entry.get("arguments", {}) or {},
                    priority=priority,
                    depends_on=list(entry.get("depends_on", []) or []),
                    status=status,
                    rationale=entry.get("rationale", ""),
                    score=float(entry.get("score", 0.0) or 0.0),
                    risk=entry.get("risk", "medium") or "medium",
                )
            )
        return cls(
            target=payload.get("target", "cible"),
            steps=steps,
            phase=payload.get("phase", ""),
            created_at=payload.get("created_at", datetime.now().isoformat(timespec="seconds")),
        )


def reconcile_attack_plan(previous_plan: AttackPlan | None, new_plan: AttackPlan) -> AttackPlan:
    """Carry step statuses forward when the underlying plan is refreshed."""
    if not previous_plan:
        return new_plan
    previous_steps = {step.signature: step for step in previous_plan.steps}
    for step in new_plan.steps:
        previous = previous_steps.get(step.signature)
        if previous:
            step.status = previous.status
    return new_plan


def _risk_for_step(step: AttackStep) -> str:
    return _TOOL_RISK.get(step.tool, "low")


def _step_markers(step: AttackStep) -> set[str]:
    markers = {step.tool.lower()}
    command = str((step.arguments or {}).get("command", "")).strip()
    if command:
        markers.add(command.split()[0].lower())
    if step.tool == "scan_target":
        markers.add("nmap")
    elif step.tool == "enumerate_web":
        markers.update({"gobuster", "nikto"})
    elif step.tool == "analyze_service":
        markers.update({"search_cve", "searchsploit"})
    elif step.tool == "search_exploit":
        markers.add("searchsploit")
    return markers


def estimate_step_score(step: AttackStep, *, phase: str = "", used_tools=None) -> float:
    """Estimate tactical value of a step from priority, phase, risk and history."""
    used_tools = {str(tool).lower() for tool in (used_tools or set())}
    phase = (phase or "").lower()
    score = _PRIORITY_SCORE.get(step.priority, _PRIORITY_SCORE[AttackPriority.MEDIUM])
    tool = step.tool.lower()
    args = step.arguments or {}

    if used_tools:
        if _step_markers(step) & used_tools:
            score -= 18.0
        else:
            score += 6.0

    if tool == "scan_target" and args.get("target") and args.get("target") != "cible":
        score += 10.0
    if tool == "analyze_service" and args.get("version"):
        score += 12.0
    if tool == "test_credentials" and args.get("username") and "password" in args:
        score += 18.0
    if tool == "search_exploit" and str(args.get("query", "")).upper().startswith("CVE-"):
        score += 10.0
    if tool == "enumerate_web" and args.get("port"):
        score += 6.0

    if phase == "recon":
        if tool == "scan_target":
            score += 18.0
        elif tool in {"test_credentials", "search_exploit", "exploit_workflow"}:
            score -= 16.0
    elif phase in {"enum", "enumeration"}:
        if tool in {"enumerate_web", "analyze_service", "route_services", "enumerate_dns"}:
            score += 14.0
        elif tool == "exploit_workflow":
            score -= 12.0
    elif phase in {"exploit", "exploitation"}:
        if tool in {"test_credentials", "search_exploit", "exploit_workflow"}:
            score += 14.0
    elif phase in {"post-exploit", "post_exploit"}:
        if tool in {"capture_evidence", "list_findings"}:
            score += 8.0

    risk = _risk_for_step(step)
    score -= _RISK_PENALTY.get(risk, 0.0)

    if step.status == StepStatus.FAILED:
        score -= 25.0

    return round(max(0.0, min(100.0, score)), 1)


def score_attack_plan(plan: AttackPlan, engagement=None) -> AttackPlan:
    phase = plan.phase
    used_tools = set()
    if engagement is not None:
        phase = getattr(getattr(engagement, "phase", None), "value", phase)
        used_tools = set(getattr(engagement, "tools_used", set()) or set())
    for step in plan.steps:
        step.risk = _risk_for_step(step)
        step.score = estimate_step_score(step, phase=phase, used_tools=used_tools)
    return plan


def build_attack_plan(findings_store, active_target, engagement) -> AttackPlan:
    """Generate an attack plan from current findings and engagement state.

    Parameters
    ----------
    findings_store : FindingsStore
        Accumulated findings from the session.
    active_target : Target or None
        The active target being tested.
    engagement : EngagementState
        Current engagement phase and tool history.

    Returns
    -------
    AttackPlan
        An ordered plan with steps, priorities, and dependencies.
    """
    from app.findings import FindingType, parse_credential_value

    target_label = active_target.label if active_target else "cible"
    plan = AttackPlan(target=target_label, phase=engagement.phase.value)
    step_index = 0
    used_tools = set(t.lower() for t in engagement.tools_used)

    def _finish_plan():
        return score_attack_plan(plan, engagement)

    # Gather current intelligence
    ports = {f.value for f in findings_store.ports}
    services = {}
    for f in findings_store.services:
        parts = f.value.split("/", 1)
        if len(parts) == 2:
            try:
                services[int(parts[0])] = parts[1]
            except ValueError:
                pass
    vulns = findings_store.vulnerabilities
    creds = findings_store.credentials
    paths = findings_store.by_type(FindingType.PATH)
    cves = findings_store.by_type(FindingType.CVE)

    web_ports = ports & {"80", "443", "8080", "8443"}
    smb_ports = ports & {"445", "139"}
    ssh_port = "22" in ports
    ftp_port = "21" in ports

    def _select_credential(service_name: str, port: str = ""):
        for finding in creds:
            details = dict(getattr(finding, "attributes", {}) or {})
            parsed = parse_credential_value(finding.value)
            for key, value in parsed.items():
                details.setdefault(key, value)
            if not details.get("username") or "password" not in details:
                continue
            cred_service = details.get("service", "").lower()
            cred_port = details.get("port", "")
            if cred_service == service_name:
                return finding, details
            if port and cred_port == port:
                return finding, details
            if not cred_service and not cred_port:
                return finding, details
        return None, {}

    # ---- Phase-dependent planning ----

    # RECON: If no ports discovered yet, start with scanning
    if not ports:
        plan.steps.append(AttackStep(
            index=step_index,
            name=f"Scan de reconnaissance {target_label}",
            tool="scan_target",
            arguments={"target": target_label, "mode": "quick"},
            priority=AttackPriority.CRITICAL,
            rationale="Aucun port decouvert. Scan initial requis.",
        ))
        step_index += 1
        return _finish_plan()  # Can't plan further without port data

    # ENUMERATION: web services
    if web_ports and "gobuster" not in used_tools and "nikto" not in used_tools:
        port = sorted(web_ports)[0]
        plan.steps.append(AttackStep(
            index=step_index,
            name=f"Enumeration web port {port}",
            tool="enumerate_web",
            arguments={"target": target_label, "port": port},
            priority=AttackPriority.HIGH,
            rationale=f"Port(s) web ouvert(s): {', '.join(sorted(web_ports))}.",
        ))
        step_index += 1

    # ENUMERATION: SMB
    if smb_ports and "enum4linux" not in used_tools:
        plan.steps.append(AttackStep(
            index=step_index,
            name="Enumeration SMB",
            tool="execute_command",
            arguments={"command": f"enum4linux -a {target_label}", "reason": "Enumeration SMB complete"},
            priority=AttackPriority.HIGH,
            rationale=f"Port(s) SMB ouvert(s): {', '.join(sorted(smb_ports))}.",
        ))
        step_index += 1

    # ENUMERATION: FTP anonymous
    if ftp_port and "ftp" not in used_tools:
        plan.steps.append(AttackStep(
            index=step_index,
            name="Test acces FTP anonyme",
            tool="test_credentials",
            arguments={"target": target_label, "service": "ftp", "username": "anonymous", "password": "guest"},
            priority=AttackPriority.MEDIUM,
            rationale="Port FTP (21) ouvert. Test d'acces anonyme.",
        ))
        step_index += 1

    # SERVICE ANALYSIS: For each service with a version, plan CVE + exploit analysis
    analyzed_services = set()
    for port_num, svc_name in services.items():
        # Extract version if present (format: "service_name version_info")
        svc_parts = svc_name.strip().split(None, 1)
        base_service = svc_parts[0].lower() if svc_parts else svc_name.lower()
        version = svc_parts[1] if len(svc_parts) > 1 else ""
        svc_key = f"{base_service}_{version}"

        if svc_key in analyzed_services:
            continue
        analyzed_services.add(svc_key)

        # Skip generic service names without version
        if not version or base_service in ("tcpwrapped", "unknown"):
            continue

        plan.steps.append(AttackStep(
            index=step_index,
            name=f"Analyse {base_service} {version} (port {port_num})",
            tool="analyze_service",
            arguments={"service": base_service, "version": version, "port": str(port_num)},
            priority=AttackPriority.HIGH,
            rationale=f"Service {base_service} {version} detecte sur port {port_num}.",
        ))
        step_index += 1

    # WordPress detection
    wp_paths = [p for p in paths if "/wp-" in p.value.lower() or "wordpress" in p.value.lower()]
    if wp_paths and "wpscan" not in used_tools:
        plan.steps.append(AttackStep(
            index=step_index,
            name="Audit WordPress",
            tool="execute_command",
            arguments={
                "command": f"wpscan --url http://{target_label} --enumerate u,p",
                "reason": "WordPress detecte, audit des users et plugins",
            },
            priority=AttackPriority.HIGH,
            rationale=f"Chemin WordPress decouvert: {wp_paths[0].value}.",
        ))
        step_index += 1

    # EXPLOITATION: Test credentials if found
    if creds and ssh_port and "ssh" not in used_tools:
        cred_finding, cred_details = _select_credential("ssh", "22")
        if cred_details:
            plan.steps.append(AttackStep(
                index=step_index,
                name="Test credentials SSH",
                tool="test_credentials",
                arguments={
                    "target": target_label,
                    "service": "ssh",
                    "username": cred_details.get("username", ""),
                    "password": cred_details.get("password", ""),
                },
                priority=AttackPriority.CRITICAL,
                depends_on=[],
                rationale=(
                    f"Credential(s) decouverte(s): "
                    f"{(cred_finding.value if cred_finding else '')[:50]}. Test SSH prioritaire."
                ),
            ))
            step_index += 1

    # EXPLOITATION: searchsploit for known vulns
    if vulns and "searchsploit" not in used_tools:
        # Pick the most promising vuln
        vuln_desc = vulns[0].value[:60]
        plan.steps.append(AttackStep(
            index=step_index,
            name="Recherche exploits publics",
            tool="search_exploit",
            arguments={"query": vuln_desc.split("[")[0].strip()},
            priority=AttackPriority.HIGH,
            rationale=f"Vulnerabilite(s) detectee(s): {vuln_desc}.",
        ))
        step_index += 1

    # POST-EXPLOITATION hints
    if creds and smb_ports:
        cred_finding, cred_details = _select_credential("smb", "445")
        if cred_details:
            plan.steps.append(AttackStep(
                index=step_index,
                name="Enumeration SMB avec credentials",
                tool="test_credentials",
                arguments={
                    "target": target_label,
                    "service": "smb",
                    "username": cred_details.get("username", ""),
                    "password": cred_details.get("password", ""),
                },
                priority=AttackPriority.MEDIUM,
                rationale=(
                    "Credentials + SMB ouvert. "
                    f"Tenter l'acces avec {cred_finding.value[:50]}."
                ),
            ))
            step_index += 1

    return _finish_plan()


def format_plan_prompt(plan: AttackPlan) -> str:
    """Format the attack plan as a prompt fragment for the agent."""
    if not plan.steps:
        return ""
    lines = [f"PLAN D'ATTAQUE ({plan.progress_summary}):"]
    for step in plan.steps:
        status_icon = {
            StepStatus.PENDING: "[ ]",
            StepStatus.RUNNING: "[>]",
            StepStatus.DONE: "[x]",
            StepStatus.SKIPPED: "[-]",
            StepStatus.FAILED: "[!]",
        }.get(step.status, "[ ]")
        deps = f" (apres etape(s) {step.depends_on})" if step.depends_on else ""
        score = f", score {step.score:.0f}" if step.score else ""
        lines.append(
            f"  {status_icon} #{step.index} [{step.priority.value}{score}] "
            f"{step.name} → {step.tool}{deps}"
        )
    next_step = plan.next_step
    if next_step:
        lines.append(
            f"PROCHAINE ETAPE RECOMMANDEE: #{next_step.index} {next_step.name} "
            f"(outil: {next_step.tool}, score: {next_step.score:.0f}, raison: {next_step.rationale})"
        )
    return "\n".join(lines)


def format_plan_display(plan: AttackPlan) -> list[str]:
    """Format the attack plan for terminal display."""
    if not plan.steps:
        return ["Aucun plan d'attaque. Lancez un scan pour generer un plan."]
    lines = [
        f"Cible: {plan.target} | Phase: {plan.phase} | {plan.progress_summary}",
        "",
    ]
    for step in plan.steps:
        status_icon = {
            StepStatus.PENDING: " ",
            StepStatus.RUNNING: ">",
            StepStatus.DONE: "x",
            StepStatus.SKIPPED: "-",
            StepStatus.FAILED: "!",
        }.get(step.status, " ")
        prio_label = step.priority.value.upper()[:4]
        score = f" S{step.score:.0f}" if step.score else ""
        deps = f" (dep: {step.depends_on})" if step.depends_on else ""
        lines.append(f"  [{status_icon}] #{step.index} [{prio_label}{score}] {step.name}{deps}")
        lines.append(f"      outil: {step.tool} | risque: {step.risk} | {step.rationale}")
    next_step = plan.next_step
    if next_step:
        lines.append("")
        lines.append(f"Prochaine etape: #{next_step.index} {next_step.name}")
    return lines
