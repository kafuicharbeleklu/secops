"""
Pentest report generation from structured mission state.

This module intentionally has no TUI dependency. It turns a MissionContext into
deterministic Markdown that can be saved, attached as an artifact, or reused by
future UI/reporting commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from secops_agent.core.mission import Evidence, Finding, MissionContext, Service


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

_DEFAULT_REMEDIATIONS = {
    "headers": "Implement the missing security headers and validate them in each exposed response path.",
    "ssl": "Replace or reissue the certificate, then verify the full TLS chain and expiry date.",
    "dir_enum": "Review exposed paths, remove sensitive content, and restrict administrative or backup locations.",
    "sqli": "Use parameterized queries, validate input server-side, and retest the affected parameter.",
    "web_vuln": "Manually validate the finding, patch the affected component, and retest the endpoint.",
    "known_vuln": "Upgrade or patch the affected service version and validate that the vulnerable version is no longer exposed.",
    "suid_binary": "Remove unintended SUID bits, replace risky binaries with least-privilege alternatives, and verify privilege boundaries after remediation.",
    "cve_reference": "Correlate this CVE with confirmed product and version evidence before reporting it as affected.",
    "exploit_reference": "Treat this as reference material until applicability is confirmed against in-scope evidence.",
}


@dataclass(frozen=True)
class PentestReport:
    """Generated report artifact."""

    title: str
    content: str
    format: str = "markdown"


class PentestReportGenerator:
    """Build a structured Markdown pentest report from MissionContext."""

    def generate_markdown(
        self,
        mission: MissionContext,
        *,
        title: str | None = None,
        generated_at: datetime | None = None,
    ) -> str:
        generated_at = generated_at or datetime.now(timezone.utc)
        report_title = title or f"{mission.name or 'SecOps Mission'} Pentest Report"
        findings = _sorted_findings(mission.findings)

        sections = [
            self._title_section(report_title, mission, generated_at),
            self._executive_summary(mission, findings),
            self._scope_section(mission),
            self._methodology_section(mission, findings),
            self._attack_surface_section(mission),
            self._findings_section(findings),
            self._remediation_summary(findings),
            self._appendix_section(mission, findings),
        ]
        return "\n\n".join(section for section in sections if section.strip()).rstrip() + "\n"

    def generate(
        self,
        mission: MissionContext,
        *,
        title: str | None = None,
        generated_at: datetime | None = None,
    ) -> PentestReport:
        report_title = title or f"{mission.name or 'SecOps Mission'} Pentest Report"
        return PentestReport(
            title=report_title,
            content=self.generate_markdown(mission, title=report_title, generated_at=generated_at),
        )

    def _title_section(
        self,
        title: str,
        mission: MissionContext,
        generated_at: datetime,
    ) -> str:
        phase = mission.phase.value if hasattr(mission.phase, "value") else str(mission.phase)
        lines = [
            f"# {_md(title)}",
            "",
            f"- **Mission:** {_md(mission.name or 'Unnamed mission')}",
            f"- **Engagement Type:** {_md(mission.engagement_type)}",
            f"- **Current Phase:** {_md(phase)}",
            f"- **Generated:** {generated_at.astimezone(timezone.utc).isoformat()}",
        ]
        if mission.started_at:
            lines.append(f"- **Started:** {_md(mission.started_at)}")
        if mission.phase_reason:
            lines.append(f"- **Phase Reason:** {_md(mission.phase_reason)}")
        return "\n".join(lines)

    def _executive_summary(self, mission: MissionContext, findings: list[Finding]) -> str:
        counts = _severity_counts(findings)
        actionable = [
            finding
            for finding in findings
            if finding.category not in {"cve_reference", "exploit_reference"}
            and finding.severity != "info"
        ]
        highest = _highest_severity(findings)
        lines = [
            "## Executive Summary",
            "",
            (
                f"SecOps recorded {len(_in_scope_targets(mission))} in-scope target(s), "
                f"{len(mission.hosts)} host(s), {len(_all_services(mission))} service(s), "
                f"and {len(findings)} finding(s)."
            ),
            (
                f"Highest recorded severity: {_SEVERITY_LABELS.get(highest, highest.title())}. "
                f"Actionable non-reference findings: {len(actionable)}."
            ),
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {_SEVERITY_LABELS[severity]} | {counts[severity]} |")
        if mission.blocked_reasons:
            lines.extend(["", "Scope or execution blockers were recorded and are listed in the appendix."])
        return "\n".join(lines)

    def _scope_section(self, mission: MissionContext) -> str:
        lines = [
            "## Scope",
            "",
            "### In Scope",
        ]
        in_scope = _in_scope_targets(mission) or list(mission.scope.in_scope)
        if in_scope:
            lines.extend(f"- `{_md(value)}`" for value in _dedupe(in_scope))
        else:
            lines.append("- Not recorded.")

        lines.extend(["", "### Out Of Scope"])
        if mission.scope.out_of_scope:
            lines.extend(f"- `{_md(value)}`" for value in _dedupe(mission.scope.out_of_scope))
        else:
            lines.append("- Not recorded.")

        if mission.scope.rules:
            lines.extend(["", "### Rules Of Engagement"])
            lines.extend(f"- {_md(rule)}" for rule in mission.scope.rules)
        return "\n".join(lines)

    def _methodology_section(self, mission: MissionContext, findings: list[Finding]) -> str:
        phases = _dedupe(
            transition.to_phase
            for transition in mission.phase_history
            if transition.to_phase
        )
        if not phases:
            phase = mission.phase.value if hasattr(mission.phase, "value") else str(mission.phase)
            phases = [phase] if phase else []

        tools = _dedupe(
            finding.tool_used
            for finding in findings
            if finding.tool_used
        )
        evidence_tools = _dedupe(
            evidence.source_tool
            for finding in findings
            for evidence in finding.evidence_items
            if evidence.source_tool
        )

        lines = [
            "## Methodology",
            "",
            "Testing was reconstructed from structured mission state and recorded tool evidence.",
            "",
            "### Phases Covered",
        ]
        lines.extend(f"- {_md(phase)}" for phase in phases) if phases else lines.append("- Not recorded.")

        lines.extend(["", "### Tools Referenced"])
        all_tools = _dedupe([*tools, *evidence_tools])
        lines.extend(f"- `{_md(tool)}`" for tool in all_tools) if all_tools else lines.append("- Not recorded.")

        if mission.completed_objectives:
            lines.extend(["", "### Completed Objectives"])
            lines.extend(f"- {_md(item)}" for item in mission.completed_objectives)
        return "\n".join(lines)

    def _attack_surface_section(self, mission: MissionContext) -> str:
        services = _all_services(mission)
        lines = [
            "## Attack Surface",
            "",
            f"Hosts discovered: {len(mission.hosts)}",
            f"Services discovered: {len(services)}",
        ]
        if not services:
            return "\n".join(lines + ["", "No services were recorded."])

        lines.extend([
            "",
            "| Host | Port | Protocol | Service | Version | State |",
            "| --- | ---: | --- | --- | --- | --- |",
        ])
        for service in services:
            lines.append(
                "| "
                + " | ".join([
                    _md(service.host or "-"),
                    str(service.port),
                    _md(service.protocol or "-"),
                    _md(service.service or "-"),
                    _md(service.version or "-"),
                    _md(service.state or "-"),
                ])
                + " |"
            )
        return "\n".join(lines)

    def _findings_section(self, findings: list[Finding]) -> str:
        lines = ["## Findings"]
        if not findings:
            return "\n".join(lines + ["", "No findings were recorded."])

        for index, finding in enumerate(findings, start=1):
            severity = _SEVERITY_LABELS.get(finding.severity, finding.severity.title())
            status = "confirmed" if finding.confirmed else "unconfirmed/reference"
            lines.extend([
                "",
                f"### {index}. {_md(finding.title or 'Untitled finding')}",
                "",
                f"- **Severity:** {severity}",
                f"- **Target:** `{_md(finding.target or 'Not recorded')}`",
                f"- **Category:** {_md(finding.category or 'Not recorded')}",
                f"- **Status:** {status}",
                f"- **Source Tool:** `{_md(finding.tool_used or 'Not recorded')}`",
                "",
                "#### Evidence",
            ])
            evidence_items = finding.evidence_items or _legacy_evidence_items(finding)
            if evidence_items:
                for evidence_index, evidence in enumerate(evidence_items[:8], start=1):
                    lines.extend(_format_evidence(evidence, evidence_index))
            else:
                lines.append("- Not recorded.")

            lines.extend([
                "",
                "#### Remediation",
                _md(_remediation_for(finding)),
            ])
        return "\n".join(lines)

    def _remediation_summary(self, findings: list[Finding]) -> str:
        actionable = [
            finding
            for finding in findings
            if finding.category not in {"cve_reference", "exploit_reference"}
            and finding.severity != "info"
        ]
        lines = ["## Remediation Summary"]
        if not actionable:
            return "\n".join(lines + ["", "No actionable remediation items were recorded."])

        for finding in actionable:
            severity = _SEVERITY_LABELS.get(finding.severity, finding.severity.title())
            lines.append(
                f"- **{severity}:** {_md(finding.title or 'Untitled finding')} - {_md(_remediation_for(finding))}"
            )
        return "\n".join(lines)

    def _appendix_section(self, mission: MissionContext, findings: list[Finding]) -> str:
        evidence_count = sum(len(finding.evidence_items) for finding in findings)
        lines = [
            "## Appendix",
            "",
            f"- Findings: {len(findings)}",
            f"- Structured evidence snippets: {evidence_count}",
            f"- Phase transitions: {len(mission.phase_history)}",
        ]
        if mission.blocked_reasons:
            lines.extend(["", "### Blocked Reasons"])
            lines.extend(f"- {_md(reason)}" for reason in mission.blocked_reasons[-20:])
        return "\n".join(lines)


def generate_pentest_report(
    mission: MissionContext,
    *,
    title: str | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Convenience wrapper returning Markdown report content."""
    return PentestReportGenerator().generate_markdown(
        mission,
        title=title,
        generated_at=generated_at,
    )


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER.get(finding.severity, 99),
            finding.target.casefold(),
            finding.title.casefold(),
        ),
    )


def _severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity if finding.severity in counts else "info"] += 1
    return counts


def _highest_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return min(findings, key=lambda finding: _SEVERITY_ORDER.get(finding.severity, 99)).severity


def _in_scope_targets(mission: MissionContext) -> list[str]:
    targets = [target.value for target in mission.targets if target.in_scope and target.value]
    return _dedupe([*targets, *mission.scope.in_scope])


def _all_services(mission: MissionContext) -> list[Service]:
    services: dict[str, Service] = {}
    for service in mission.services:
        services[service.key] = service
    for host in mission.hosts:
        for service in host.services:
            services[service.key] = service
    return sorted(
        services.values(),
        key=lambda service: (service.host, service.port, service.protocol),
    )


def _legacy_evidence_items(finding: Finding) -> list[Evidence]:
    if not finding.evidence:
        return []
    return [
        Evidence(
            title=finding.title,
            source_tool=finding.tool_used,
            target=finding.target,
            snippet=finding.evidence,
        )
    ]


def _format_evidence(evidence: Evidence, index: int) -> list[str]:
    lines = [
        f"{index}. **{_md(evidence.title or 'Evidence')}**",
        f"   - Source: `{_md(evidence.source_tool or 'Not recorded')}`",
        f"   - Target: `{_md(evidence.target or 'Not recorded')}`",
    ]
    if evidence.metadata:
        metadata = ", ".join(
            f"{key}={_metadata_value(value)}"
            for key, value in sorted(evidence.metadata.items())
            if value not in (None, "", [], {})
        )
        if metadata:
            lines.append(f"   - Metadata: {_md(metadata)}")
    lines.extend([
        "   - Snippet:",
        "",
        "```text",
        _code(evidence.snippet or "Not recorded."),
        "```",
    ])
    return lines


def _remediation_for(finding: Finding) -> str:
    if finding.remediation:
        return finding.remediation
    return _DEFAULT_REMEDIATIONS.get(
        finding.category,
        "Validate the issue, document impact, apply the relevant fix, and retest the affected asset.",
    )


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _metadata_value(value: object) -> str:
    if isinstance(value, (list, tuple, set)):
        return "[" + ", ".join(str(item) for item in value) + "]"
    return str(value)


def _md(value: object) -> str:
    return str(value or "").replace("|", "\\|")


def _code(value: object) -> str:
    return str(value or "").replace("```", "` ` `")
