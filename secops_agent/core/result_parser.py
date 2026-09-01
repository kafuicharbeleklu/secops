"""Public façade for tool-output parsing.

The parser implementations live in secops_agent.core.result_parsers.* (split out
of the former monolith, Phase 4.1). This module assembles the tool_name->parser
registry and the ToolResultParser dispatcher, and re-exports the parse_* functions
+ ParsedResult for backward compatibility (call sites and tests import them here).
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from secops_agent.core.mission import MissionContext
from secops_agent.core.result_parsers.base import (
    ParsedResult,
    _missing_tool_findings,
    _overall_severity,
    _timeout_findings,
)
from secops_agent.core.result_parsers.recon import (
    parse_nmap_output,
    parse_dns_output,
    parse_whois_output,
    parse_ssl_output,
)
from secops_agent.core.result_parsers.web import (
    parse_dir_brute_output,
    parse_nikto_output,
    parse_http_headers_output,
    parse_ffuf_output,
    parse_nuclei_output,
    parse_http_request_output,
    parse_fetch_url_output,
)
from secops_agent.core.result_parsers.exploit import (
    parse_sqlmap_output,
    parse_searchsploit_output,
    parse_cve_output,
    parse_webshell_exec_output,
    parse_start_listener_output,
    parse_write_file_output,
)
from secops_agent.core.result_parsers.system import (
    parse_run_shell_output,
    parse_generic_output,
)
from secops_agent.core.result_parsers.observation import (
    parse_ping_output,
    parse_port_check_output,
    parse_subdomain_enum_output,
    parse_tech_detect_output,
    parse_traceroute_output,
    parse_waf_detect_output,
)
from secops_agent.core.result_parsers.local import (
    parse_connect_vpn_config_output,
    parse_disconnect_vpn_output,
    parse_exploit_info_output,
    parse_file_analyze_output,
    parse_find_files_output,
    parse_generate_payload_output,
    parse_hash_generate_output,
    parse_hash_identify_output,
    parse_lab_setup_check_output,
    parse_log_analyze_output,
    parse_password_strength_output,
    parse_sysinfo_output,
    parse_vpn_status_output,
)


_PARSERS: Dict[str, Callable[[str, Dict[str, Any]], ParsedResult]] = {
    "nmap_scan": parse_nmap_output,
    "dns_lookup": parse_dns_output,
    "whois_lookup": parse_whois_output,
    "http_headers": parse_http_headers_output,
    "dir_brute": parse_dir_brute_output,
    "sql_injection_test": parse_sqlmap_output,
    "nikto_scan": parse_nikto_output,
    "ssl_check": parse_ssl_output,
    "ssl_audit": parse_ssl_output,
    "run_shell": parse_run_shell_output,
    "xss_test": parse_generic_output,
    "searchsploit": parse_searchsploit_output,
    "cve_lookup": parse_cve_output,
    "ffuf_scan": parse_ffuf_output,
    "nuclei_scan": parse_nuclei_output,
    # Exploitation tools
    "http_request": parse_http_request_output,
    "write_file": parse_write_file_output,
    "fetch_url": parse_fetch_url_output,
    "webshell_exec": parse_webshell_exec_output,
    "start_listener": parse_start_listener_output,
    # OBSERVE parsers for the six former blind spots (audit R3.3).
    "subdomain_enum": parse_subdomain_enum_output,
    "tech_detect": parse_tech_detect_output,
    "waf_detect": parse_waf_detect_output,
    "port_check": parse_port_check_output,
    "ping_host": parse_ping_output,
    "traceroute": parse_traceroute_output,
    # Local evidence and helper outputs also update the structured mission view.
    "connect_vpn_config": parse_connect_vpn_config_output,
    "disconnect_vpn": parse_disconnect_vpn_output,
    "exploit_info": parse_exploit_info_output,
    "file_analyze": parse_file_analyze_output,
    "find_files": parse_find_files_output,
    "generate_payload": parse_generate_payload_output,
    "hash_generate": parse_hash_generate_output,
    "hash_identify": parse_hash_identify_output,
    "lab_setup_check": parse_lab_setup_check_output,
    "log_analyze": parse_log_analyze_output,
    "password_strength": parse_password_strength_output,
    "sysinfo": parse_sysinfo_output,
    "vpn_status": parse_vpn_status_output,
}


class ToolResultParser:
    """Dispatches tool outputs to specialised parsers.

    Usage::

        parser = ToolResultParser()
        parsed = parser.parse("nmap_scan", raw_output, {"target": "10.10.10.5"})
    """

    def __init__(self, mission: MissionContext | None = None) -> None:
        self.mission = mission

    def parse(
        self,
        tool_name: str,
        raw_output: str,
        arguments: Dict[str, Any] | None = None,
    ) -> ParsedResult:
        """Parse a tool's raw output into a ParsedResult."""
        args = dict(arguments or {})
        args["_tool_name"] = tool_name

        parser_fn = _PARSERS.get(tool_name, parse_generic_output)
        result = parser_fn(raw_output, args)
        result.tool_name = tool_name
        missing_tool_findings = _missing_tool_findings(raw_output, args, tool_name)
        if missing_tool_findings:
            existing_keys = {finding.key for finding in result.findings}
            added_missing_tools: List[str] = []
            for finding in missing_tool_findings:
                if finding.key in existing_keys:
                    continue
                result.findings.append(finding)
                existing_keys.add(finding.key)
                metadata = finding.evidence_items[0].metadata if finding.evidence_items else {}
                added_missing_tools.append(str(metadata.get("missing_tool") or finding.target))
            if added_missing_tools:
                result.severity = _overall_severity(result.findings)
                result.data.setdefault("missing_tools", [])
                result.data["missing_tools"].extend(added_missing_tools)
                for missing_tool in added_missing_tools:
                    result.next_steps.insert(0, f"Install missing local tool: {missing_tool}")
                if result.summary:
                    result.summary += f"\nMissing local tool(s): {', '.join(added_missing_tools)}"
                else:
                    result.summary = f"Missing local tool(s): {', '.join(added_missing_tools)}"

        timeout_findings = _timeout_findings(raw_output, args, tool_name)
        if timeout_findings:
            existing_keys = {finding.key for finding in result.findings}
            for finding in timeout_findings:
                if finding.key in existing_keys:
                    continue
                result.findings.append(finding)
                existing_keys.add(finding.key)
            result.severity = _overall_severity(result.findings)
            result.data["timeout_detected"] = True
            if not any("timeout" in step.casefold() for step in result.next_steps):
                result.next_steps.insert(0, f"Retry {tool_name} with a bounded recovery profile")
            if result.summary:
                result.summary += "\nTool execution timed out before producing a complete result."
            else:
                result.summary = "Tool execution timed out before producing a complete result."

        # Integrate into mission if available
        if self.mission:
            for host in result.hosts_discovered:
                self.mission.add_host(host)
            for svc in result.services_discovered:
                self.mission.add_service(svc)
            for finding in result.findings:
                finding.phase = self.mission.phase.value
                self.mission.upsert_finding(finding)
            self.mission.refresh_phase_from_state()
            # Cache the parsed scan so a same-mission deterministic-preflight
            # follow-up ("how many ports?") can answer without re-running the
            # scan or re-prompting for approval. This is the ONLY write path into
            # the scan cache and is reached only for a genuine, approved execution
            # (agent.py OBSERVE gate), so untrusted lesson/KB/tool-output text has
            # no way to populate it. record_scan_result ignores non-scan tools.
            if hasattr(self.mission, "record_scan_result"):
                self.mission.record_scan_result(tool_name, args, result)

        return result

    @staticmethod
    def has_parser(tool_name: str) -> bool:
        return tool_name in _PARSERS

    @staticmethod
    def supported_tools() -> List[str]:
        return list(_PARSERS.keys())
