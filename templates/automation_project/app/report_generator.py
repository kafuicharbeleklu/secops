"""Pentest report generator — produces structured Markdown reports.

Aggregates data from FindingsStore, EngagementState, and target context
to produce a professional pentest report.
"""

from datetime import datetime
from pathlib import Path

from app.findings import FindingType


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
EVIDENCE_TYPE_ORDER = {
    "vulnerability": 0,
    "cve": 1,
    "credential": 2,
    "path": 3,
    "service": 4,
    "port": 5,
    "os": 6,
}
SENSITIVE_ATTRIBUTE_KEYS = ("password", "passwd", "pwd", "secret", "token", "key")


def _is_sensitive_attribute(key: str) -> bool:
    normalized = key.lower()
    return any(marker in normalized for marker in SENSITIVE_ATTRIBUTE_KEYS)


def _format_evidence_attributes(finding) -> str:
    attributes = getattr(finding, "attributes", {}) or {}
    if not attributes:
        return ""
    parts = []
    for key, value in sorted(attributes.items()):
        display_value = "<redacted>" if _is_sensitive_attribute(str(key)) else value
        parts.append(f"{key}={display_value}")
    return ", ".join(parts)


def _evidence_excerpt(finding, *, max_lines: int = 8, max_chars: int = 700) -> str:
    raw = (getattr(finding, "raw_output", "") or "").strip()
    if not raw:
        return ""
    for key, value in (getattr(finding, "attributes", {}) or {}).items():
        if _is_sensitive_attribute(str(key)) and value:
            raw = raw.replace(str(value), "<redacted>")
    raw = raw.replace("```", "'''")
    lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    excerpt = "\n".join(lines[:max_lines])
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars].rstrip() + "..."
    if len(lines) > max_lines:
        excerpt += "\n..."
    return excerpt


def _evidence_findings(findings_store, *, limit: int = 20):
    findings = [
        finding
        for finding in getattr(findings_store, "all", [])
        if (
            getattr(finding, "raw_output", "")
            or getattr(finding, "target_ref", "")
            or getattr(finding, "attributes", None)
        )
    ]
    findings.sort(
        key=lambda finding: (
            EVIDENCE_TYPE_ORDER.get(finding.finding_type.value, 99),
            SEVERITY_ORDER.get(finding.normalized_severity, 5),
            finding.timestamp,
        )
    )
    return findings[:limit]


def generate_pentest_report(
    *,
    target_summary: str,
    findings_store,
    engagement_state,
    session_duration_minutes: int = 0,
    output_path: Path,
    audit_logger=None,
    attack_plan=None,
) -> Path:
    """Generate a structured pentest report in Markdown format.

    Parameters
    ----------
    target_summary : str
        Human-readable description of the target(s).
    findings_store : FindingsStore
        Accumulated findings from the session.
    engagement_state : EngagementState
        Phase transitions and tool usage history.
    session_duration_minutes : int
        Elapsed session time in minutes.
    output_path : Path
        Where to write the report.
    audit_logger : AuditLogger, optional
        Audit trail logger for action timeline.
    attack_plan : AttackPlan, optional
        Current attack plan with step statuses.

    Returns
    -------
    Path
        The path to the written report file.
    """
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ---- Header ----
    lines.append("# Rapport de Test de Penetration SECOPS")
    lines.append("")
    lines.append(f"**Date :** {now}")
    lines.append(f"**Cible :** {target_summary}")
    lines.append(f"**Duree session :** {session_duration_minutes} min")
    lines.append(f"**Phase finale :** {engagement_state.phase_label}")
    lines.append("")

    # ---- Resume executif ----
    vuln_count = len(findings_store.vulnerabilities)
    cred_count = len(findings_store.credentials)
    port_count = len(findings_store.ports)
    service_count = len(findings_store.services)
    path_count = len(findings_store.by_type(FindingType.PATH))

    lines.append("## Resume Executif")
    lines.append("")
    lines.append(f"- **{port_count}** port(s) ouvert(s) identifies")
    lines.append(f"- **{service_count}** service(s) detecte(s)")
    lines.append(f"- **{vuln_count}** vulnerabilite(s) detectee(s)")
    lines.append(f"- **{cred_count}** credential(s) compromise(s)")
    lines.append(f"- **{path_count}** chemin(s) decouverts")
    lines.append(f"- **{len(engagement_state.tools_used)}** outil(s) utilise(s)")
    lines.append("")

    # ---- Vulnerabilites ----
    if findings_store.vulnerabilities:
        lines.append("## Vulnerabilites Detectees")
        lines.append("")
        sorted_vulns = sorted(
            findings_store.vulnerabilities,
            key=lambda f: SEVERITY_ORDER.get(f.normalized_severity, 5),
        )
        for f in sorted_vulns:
            lines.append(f"### [{f.normalized_severity.upper()}] {f.value[:100]}")
            lines.append(f"- **Source :** {f.source_tool}")
            lines.append(f"- **Confiance :** {f.effective_confidence}")
            lines.append(f"- **Severite :** {f.normalized_severity}")
            if f.target_ref:
                lines.append(f"- **Cible :** {f.target_ref}")
            lines.append(f"- **Timestamp :** {f.timestamp}")
            lines.append("")

    # ---- Credentials ----
    if findings_store.credentials:
        lines.append("## Credentials Compromis")
        lines.append("")
        for f in findings_store.credentials:
            lines.append(f"- `{f.value}` (source: {f.source_tool})")
        lines.append("")

    # ---- Surface d'attaque ----
    if findings_store.services:
        lines.append("## Surface d'Attaque")
        lines.append("")
        lines.append("| Port | Service | Source |")
        lines.append("|------|---------|--------|")
        for f in findings_store.services:
            parts = f.value.split("/", 1)
            port = parts[0] if len(parts) == 2 else "-"
            svc = parts[1] if len(parts) == 2 else f.value
            lines.append(f"| {port} | {svc} | {f.source_tool} |")
        lines.append("")

    # ---- Chemins decouverts ----
    paths = findings_store.by_type(FindingType.PATH)
    if paths:
        lines.append("## Chemins Decouverts")
        lines.append("")
        for f in paths:
            lines.append(f"- `{f.value}` (source: {f.source_tool})")
        lines.append("")

    # ---- OS ----
    os_findings = findings_store.by_type(FindingType.OS)
    if os_findings:
        lines.append("## Systeme d'Exploitation")
        lines.append("")
        for f in os_findings:
            lines.append(f"- {f.value} (source: {f.source_tool})")
        lines.append("")

    # ---- Timeline des phases ----
    if engagement_state.phase_history:
        lines.append("## Timeline des Phases")
        lines.append("")
        for transition in engagement_state.phase_history:
            lines.append(
                f"- **{transition.from_phase.value}** -> "
                f"**{transition.to_phase.value}** : {transition.reason}"
            )
        lines.append("")

    # ---- Plan d'attaque ----
    if attack_plan and getattr(attack_plan, "steps", None):
        lines.append("## Plan d'Attaque")
        lines.append("")
        lines.append(f"**Cible planifiee :** {attack_plan.target}")
        lines.append(f"**Progression :** {attack_plan.progress_summary}")
        lines.append("")
        lines.append("| # | Statut | Priorite | Outil | Etape |")
        lines.append("|---|--------|----------|-------|-------|")
        for step in attack_plan.steps:
            lines.append(
                f"| {step.index} | {step.status.value} | {step.priority.value} | "
                f"`{step.tool}` | {step.name} |"
            )
        lines.append("")

    # ---- Preuves ----
    evidence_findings = _evidence_findings(findings_store)
    if evidence_findings:
        lines.append("## Preuves")
        lines.append("")
        for index, f in enumerate(evidence_findings, start=1):
            lines.append(f"### Preuve {index} - {f.finding_type.value}: {f.value[:100]}")
            lines.append(f"- **Source :** {f.source_tool}")
            if f.target_ref:
                lines.append(f"- **Cible :** {f.target_ref}")
            lines.append(f"- **Confiance :** {f.effective_confidence}")
            lines.append(f"- **Severite :** {f.normalized_severity}")
            attributes = _format_evidence_attributes(f)
            if attributes:
                lines.append(f"- **Attributs :** {attributes}")
            excerpt = _evidence_excerpt(f)
            if excerpt:
                lines.append("")
                lines.append("```text")
                lines.append(excerpt)
                lines.append("```")
            lines.append("")

    # ---- Outils utilises ----
    if engagement_state.tools_used:
        lines.append("## Outils Utilises")
        lines.append("")
        for tool in engagement_state.tools_used:
            lines.append(f"- `{tool}`")
        lines.append("")

    # ---- Audit timeline ----
    if audit_logger and audit_logger.count:
        timeline_md = audit_logger.timeline_markdown()
        if timeline_md:
            lines.append("## Timeline des Actions")
            lines.append("")
            lines.append(timeline_md)
            lines.append("")

    # ---- Recommandations ----
    lines.append("## Recommandations")
    lines.append("")
    if vuln_count:
        lines.append("- Corriger les vulnerabilites identifiees par ordre de severite.")
    if cred_count:
        lines.append("- Changer immediatement les credentials compromis.")
    if not vuln_count and not cred_count:
        lines.append("- Aucune vulnerabilite critique detectee a ce stade.")
    lines.append("- Effectuer un re-test apres remediation.")
    lines.append("")

    # Write the report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
