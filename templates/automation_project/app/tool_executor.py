import ipaddress
import os
import queue
import re
import shlex
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from app.attack_planner import build_attack_plan, format_plan_prompt, format_plan_display
from app.cve_lookup import CVEEntry, format_cve_results, search_cve
from app.findings import Finding, FindingType
from app.service_router import (
    build_service_plan,
    extract_services_from_findings,
    route_service,
)
from app.tool_plugin import ToolPlugin, ToolSpec
from app.tool_plugins import load_builtin_tool_plugins
from app.tool_policy import ToolPolicy, ToolPolicyError
from app.tool_registry import ToolRegistry


SAFE_DEFAULT_COMMANDS = {
    "cat",
    "date",
    "echo",
    "file",
    "find",
    "head",
    "hostname",
    "id",
    "ip",
    "ls",
    "pwd",
    "rg",
    "sed",
    "tail",
    "uname",
    "wc",
    "whoami",
    "grep",
    "awk",
    "sort",
    "uniq",
    "strings",
    "xxd",
    "base64",
}

ADMIN_COMMANDS = {"apt", "apt-get"}
ADMIN_SUBCOMMAND_ALIASES = {
    "full-upgrade": "dist-upgrade",
}
ADMIN_ALLOWED_SUBCOMMANDS = {
    "update",
    "upgrade",
    "dist-upgrade",
    "autoremove",
}

INSTALLABLE_PACKAGES = {
    "gobuster": "gobuster",
    "nmap": "nmap",
}

# Adaptive timeouts for pentest tools (seconds)
TOOL_TIMEOUTS = {
    "nmap": 120,
    "masscan": 120,
    "gobuster": 120,
    "dirb": 120,
    "nikto": 180,
    "ffuf": 120,
    "hydra": 300,
    "sqlmap": 300,
    "enum4linux": 120,
    "wpscan": 180,
    "john": 600,
    "hashcat": 600,
}

# Registry singleton will be initialized by ToolExecutor
_DEFAULT_REGISTRY = None

ALWAYS_BLOCKED_COMMANDS = {"sudo"}

BLOCKED_TOKENS = ("&&", "||", ";", ">", "<", "$(", "`")
SAFE_PIPE_TARGETS = {"grep", "head", "tail", "sort", "uniq", "wc", "awk", "sed", "cut", "tr"}


TARGET_PLACEHOLDERS = {
    "TARGET_IP",
    "TARGET_URL",
    "<target>",
    "<target_ip>",
    "<target_url>",
    "target_ip",
    "target_url",
}

_SCOPE_TARGET_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"
)
_URL_TARGET_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$"
)

NETWORK_TARGET_COMMANDS = {
    "dig",
    "dirb",
    "dnsenum",
    "enum4linux",
    "ffuf",
    "ftp",
    "gobuster",
    "host",
    "hydra",
    "masscan",
    "nikto",
    "nmap",
    "ping",
    "smbclient",
    "sqlmap",
    "ssh",
    "sshpass",
    "wpscan",
    "curl",
    "wget",
}

COMMAND_NON_TARGET_VALUE_FLAGS = {
    "-H",
    "--header",
    "-a",
    "--user-agent",
    "-c",
    "--cookie",
    "-e",
    "--extensions",
    "--format",
    "-l",
    "-L",
    "--login",
    "-m",
    "--mode",
    "-o",
    "-oA",
    "-oG",
    "-oN",
    "-oX",
    "--output",
    "--output-dir",
    "-p",
    "--password",
    "-P",
    "--passwords",
    "-r",
    "--rate",
    "-t",
    "--threads",
    "--username",
    "-w",
    "--wordlist",
}


class PermissionDenied(RuntimeError):
    pass


class ToolExecutionError(RuntimeError):
    pass


class ScopeViolationError(ToolExecutionError):
    """Raised when a target is outside the authorized scope."""
    pass


class ToolMissingError(ToolExecutionError):
    def __init__(self, executable):
        super().__init__(f"L'outil {executable} est requis mais non installe sur cette machine.")
        self.executable = executable


class ToolsMissingError(ToolExecutionError):
    def __init__(self, executables, *, installed=None):
        self.executables = list(executables)
        self.installed = list(installed or [])
        label = ", ".join(self.executables)
        super().__init__(f"Les outils suivants sont requis mais non installes: {label}.")


class InteractiveAdminRequired(ToolExecutionError):
    def __init__(self, command, manual_command):
        super().__init__(
            f"La commande admin {command} requiert sudo interactif. "
            "Autorisez-vous une nouvelle tentative avec saisie du mot de passe admin ?"
        )
        self.command = command
        self.manual_command = manual_command


class MissingTargetError(ToolExecutionError):
    pass


class ToolExecutor:
    def __init__(
        self,
        *,
        workspace,
        knowledge_root,
        knowledge_store,
        permission_callback=None,
        command_permission_mode="ask",
        allowed_commands=None,
        tool_registry=None,
        findings_store=None,
        authorized_scope=None,
        progress_callback=None,
    ):
        self.workspace = Path(workspace).resolve()
        self.knowledge_root = Path(knowledge_root).resolve()
        self.knowledge_store = knowledge_store
        self.permission_callback = permission_callback
        self.command_permission_mode = command_permission_mode
        self.allowed_commands = set(allowed_commands) if allowed_commands is not None else None
        self._session_allow_commands = set()
        self.tool_registry = tool_registry or ToolRegistry()
        self.findings_store = findings_store
        self.authorized_scope: set[str] = set(authorized_scope or [])
        self.progress_callback = progress_callback
        self._last_command_log_path = None
        self.tool_policy = ToolPolicy(placeholder_tokens=TARGET_PLACEHOLDERS)
        self._tool_plugins = load_builtin_tool_plugins(self)

    @staticmethod
    def _coerce_text(value, default=""):
        """Normalize tool arguments that may arrive as non-string JSON scalars."""
        if value is None:
            return default
        return str(value)

    def _emit_progress(self, event):
        if not self.progress_callback:
            return
        try:
            self.progress_callback(event)
        except Exception:
            return

    def _command_log_path(self, command):
        logs_dir = self.workspace / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        executable = shlex.split(command, posix=True)[0] if command else "command"
        executable = re.sub(r"[^a-zA-Z0-9_.-]+", "_", executable)[:40] or "command"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = logs_dir / f"{timestamp}_{executable}.log"
        suffix = 1
        while path.exists():
            path = logs_dir / f"{timestamp}_{executable}_{suffix}.log"
            suffix += 1
        return path

    def _attach_command_log(self, result):
        if not isinstance(result, dict):
            return result
        command = result.get("command", "")
        if not command:
            return result
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        path = self._command_log_path(command)
        lines = [
            f"command: {command}",
            f"reason: {result.get('reason', '')}",
            f"returncode: {result.get('returncode', '')}",
        ]
        if result.get("error"):
            lines.append(f"error: {result['error']}")
        lines.extend(["", "## stdout", stdout, "", "## stderr", stderr])
        path.write_text("\n".join(lines), encoding="utf-8")
        result["log_path"] = str(path)
        result["stdout_lines"] = len([line for line in stdout.splitlines() if line.strip()])
        result["stderr_lines"] = len([line for line in stderr.splitlines() if line.strip()])
        self._last_command_log_path = str(path)
        return result

    def available_tools(self):
        return tuple(
            plugin.spec
            for plugin in self._tool_plugins.values()
            if plugin.is_enabled()
        )

    def available_tools_for_context(self, *, phase="", prompt="", findings_store=None):
        """Return a compact, phase-aware tool list for the current LLM decision."""
        lowered = (prompt or "").casefold()
        phase = (phase or "").strip()
        findings_store = findings_store or self.findings_store
        include_names = {
            "query_knowledge",
            "list_findings",
            "suggest_pentest_tools",
            "install_pentest_tool",
            "install_pentest_tools",
        }

        if any(term in lowered for term in ("rapport", "report", "export", "preuve", "evidence")):
            include_names.update({"capture_evidence", "plan_attack"})

        if any(term in lowered for term in ("plan", "route", "prochaine", "next", "pivote", "pivot")):
            include_names.update({"plan_attack", "route_services"})

        if any(term in lowered for term in ("commande", "command", "shell", "local", "apt", "sudo")):
            include_names.update({"execute_command", "execute_admin_command"})

        if any(term in lowered for term in ("fichier", "file", "lis ", "read", "write", "ecris")):
            include_names.update({"read_file", "write_file"})

        if any(term in lowered for term in ("cve", "vulnerabil", "vuln", "exploit", "version")):
            include_names.update({"search_cve", "search_exploit", "analyze_service"})

        if any(term in lowered for term in ("web", "http", "apache", "gobuster", "directory", "directories", "repertoire")):
            include_names.update({"enumerate_web", "analyze_service", "search_cve"})

        if any(term in lowered for term in ("dns", "domaine", "domain", "subdomain")):
            include_names.add("enumerate_dns")

        if any(term in lowered for term in ("credential", "identifiant", "mot de passe", "password", "login", "ssh")):
            include_names.add("test_credentials")

        if any(term in lowered for term in ("scan", "nmap", "port", "recon", "cible", "target")):
            include_names.add("scan_target")

        ports = set()
        services = set()
        if findings_store:
            ports = {finding.value for finding in getattr(findings_store, "ports", [])}
            services = {
                finding.value.casefold()
                for finding in getattr(findings_store, "services", [])
            }
        if ports & {"80", "443", "8080", "8443"} or any("http" in service for service in services):
            include_names.update({"enumerate_web", "analyze_service", "search_cve"})
        if "22" in ports or any("ssh" in service for service in services):
            include_names.update({"analyze_service", "test_credentials"})

        selected = []
        fallback = []
        for plugin in self._tool_plugins.values():
            if not plugin.is_enabled():
                continue
            if plugin.spec.name in include_names:
                selected.append(plugin.spec)
                continue
            if plugin.phases and phase in plugin.phases and plugin.risk == "low":
                fallback.append(plugin.spec)

        seen = {spec.name for spec in selected}
        for spec in fallback:
            if spec.name not in seen:
                selected.append(spec)
                seen.add(spec.name)
            if len(selected) >= 12:
                break
        return tuple(selected)

    def dispatch(self, tool_name, arguments):
        plugin = self._tool_plugins.get(tool_name)
        if not plugin or not plugin.is_enabled():
            raise ToolExecutionError(f"Outil inconnu: {tool_name}")
        policy_decision = self.tool_policy.evaluate(plugin, arguments, executor=self)
        if not policy_decision.allowed:
            raise ToolPolicyError(
                policy_decision.reason,
                remediation=policy_decision.remediation,
                code=policy_decision.code,
            )
        return plugin.run(arguments)

    def _trigger_install(self, tool_name):
        tool_name = self.tool_registry.normalize_name(tool_name)
        if not tool_name:
            raise ToolExecutionError("Nom d'outil vide.")
        self.tool_registry.refresh()
        if self.tool_registry.is_installed(tool_name):
            return {"status": "already_installed", "tool": tool_name}
        if not self.tool_registry.is_known(tool_name):
            raise ToolExecutionError(f"Outil inconnu du registre: {tool_name}")
        raise ToolMissingError(tool_name)

    def _coerce_tool_names(self, tool_names):
        if isinstance(tool_names, str):
            raw_names = re.split(r"[\s,]+", tool_names.strip())
        elif isinstance(tool_names, (list, tuple, set)):
            raw_names = []
            for item in tool_names:
                raw_names.extend(re.split(r"[\s,]+", str(item).strip()))
        else:
            raw_names = []

        names = []
        seen = set()
        for name in raw_names:
            normalized = self.tool_registry.normalize_name(name)
            if not normalized or normalized in seen:
                continue
            names.append(normalized)
            seen.add(normalized)
        return names

    def _trigger_install_many(self, tool_names):
        names = self._coerce_tool_names(tool_names)
        if not names:
            raise ToolExecutionError("Liste d'outils vide.")
        self.tool_registry.refresh()
        unknown = [name for name in names if not self.tool_registry.is_known(name)]
        if unknown:
            raise ToolExecutionError(f"Outil(s) inconnu(s) du registre: {', '.join(unknown)}")
        installed = [name for name in names if self.tool_registry.is_installed(name)]
        missing = [name for name in names if not self.tool_registry.is_installed(name)]
        if missing:
            raise ToolsMissingError(missing, installed=installed)
        return {
            "status": "already_installed",
            "tools": installed,
            "installed": installed,
            "missing": [],
        }

    def _scan_target(self, target, mode="quick"):
        """Suggestion #7: High-level scan tool that builds optimal nmap commands."""
        if not target or not target.strip():
            raise MissingTargetError("Cible requise pour le scan. Fournis une IP ou un domaine.")
        target = target.strip()
        self._validate_scope(target)
        # Verify nmap is available
        if not shutil.which("nmap"):
            raise ToolMissingError("nmap")
        mode = (mode or "quick").strip().lower()
        stats_flag = "--stats-every 5s"
        scan_modes = {
            "quick": f"nmap -sC -sV {stats_flag} --top-ports 1000 {target}",
            "full": f"nmap -sC -sV {stats_flag} -p- {target}",
            "stealth": f"nmap -sS -sV {stats_flag} --top-ports 1000 {target}",
        }
        command = scan_modes.get(mode, scan_modes["quick"])
        return self.execute_command(command, f"Scan {mode} de {target}")

    def _search_cve(self, service, version=""):
        """Search NVD for CVEs matching a service and version."""
        service = (service or "").strip()
        version = (version or "").strip()
        if not service:
            raise ToolExecutionError("Nom de service requis pour la recherche CVE.")
        entries = search_cve(service, version, limit=8)
        return {
            "service": service,
            "version": version,
            "count": len(entries),
            "results": format_cve_results(entries),
            "cves": [
                {
                    "id": e.cve_id,
                    "score": e.score,
                    "severity": e.severity,
                    "description": e.description,
                }
                for e in entries
            ],
        }

    def _search_exploit(self, query):
        """Search for public exploits via searchsploit (ExploitDB local)."""
        query = (query or "").strip()
        if not query:
            raise ToolExecutionError("Terme de recherche requis pour searchsploit.")
        if not shutil.which("searchsploit"):
            raise ToolMissingError("searchsploit")
        return self.execute_command(
            f"searchsploit {query}",
            f"Recherche d'exploits pour {query}",
        )

    def _analyze_service(self, service, version="", port=""):
        """Full analysis pipeline: CVE lookup + searchsploit + risk scoring."""
        service = self._coerce_text(service).strip()
        version = self._coerce_text(version).strip()
        port = self._coerce_text(port).strip()
        if not service:
            raise ToolExecutionError("Nom de service requis pour l'analyse.")

        result = {
            "service": service,
            "version": version,
            "port": port,
            "cves": [],
            "exploits": None,
            "risk_score": 0.0,
            "risk_level": "unknown",
            "recommendation": "",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

        # Step 1: CVE lookup via NVD
        cve_entries = search_cve(service, version, limit=8)
        cve_dicts = []
        active_target = getattr(self, "_active_target", None)
        target_ref = active_target.label if active_target else ""
        for e in cve_entries:
            cve_dicts.append({
                "id": e.cve_id,
                "score": e.score,
                "severity": e.severity,
                "description": e.description,
            })
            # Create CVE-typed findings for the findings store
            if self.findings_store:
                self.findings_store.add(Finding(
                    finding_type=FindingType.CVE,
                    value=f"{e.cve_id} (CVSS {e.score:.1f}, {e.severity})",
                    source_tool="analyze_service",
                    confidence=e.severity if e.severity != "unknown" else "medium",
                    raw_output=e.description,
                    severity=e.severity,
                    target_ref=target_ref,
                    attributes={
                        "service": service,
                        "version": version,
                        "port": port,
                        "cve_id": e.cve_id,
                    },
                ))
        result["cves"] = cve_dicts
        result["cve_summary"] = format_cve_results(cve_entries)

        # Step 2: searchsploit (if available)
        if shutil.which("searchsploit"):
            query = f"{service} {version}".strip()
            try:
                exploit_result = self.execute_command(
                    f"searchsploit {query}",
                    f"Recherche d'exploits pour {query}",
                )
                result["exploits"] = exploit_result
            except (ToolExecutionError, OSError):
                result["exploits"] = {"error": "searchsploit echec"}
        else:
            result["exploits"] = {"skipped": "searchsploit non installe"}

        # Step 3: Composite risk scoring
        max_cvss = max((e.score for e in cve_entries), default=0.0)
        exploit_count = 0
        if isinstance(result["exploits"], dict):
            stdout = result["exploits"].get("stdout", "")
            # Count non-header lines containing exploit paths
            exploit_count = sum(
                1 for line in stdout.splitlines()
                if ("exploits/" in line or "shellcodes/" in line)
                and not line.startswith("---")
            )

        # Risk = max CVSS * multiplier based on exploit availability
        multiplier = 1.0
        if exploit_count > 0:
            multiplier = 1.5 if exploit_count <= 3 else 2.0
        risk_score = round(min(max_cvss * multiplier, 10.0), 1)
        result["risk_score"] = risk_score
        result["exploit_count"] = exploit_count

        # Classify risk level
        if risk_score >= 9.0:
            result["risk_level"] = "critical"
        elif risk_score >= 7.0:
            result["risk_level"] = "high"
        elif risk_score >= 4.0:
            result["risk_level"] = "medium"
        elif risk_score > 0:
            result["risk_level"] = "low"
        else:
            result["risk_level"] = "info"

        # Build recommendation
        recommendations = []
        if risk_score >= 7.0:
            recommendations.append(
                f"RISQUE ELEVE ({risk_score}/10). "
                f"Priorite immediate: {len(cve_dicts)} CVE(s), {exploit_count} exploit(s) public(s)."
            )
        if exploit_count > 0:
            recommendations.append(
                "Exploits publics disponibles — tester en priorite via searchsploit -m."
            )
        if max_cvss >= 7.0 and exploit_count == 0:
            recommendations.append(
                "CVSS eleve mais pas d'exploit public connu. Verifier les conditions d'exploitation."
            )
        if not cve_dicts and not exploit_count:
            recommendations.append(
                f"Aucune CVE ni exploit public connu pour {service} {version}. "
                "Verifier manuellement les configurations."
            )
        result["recommendation"] = " ".join(recommendations)

        return result

    def _enumerate_web(self, target, port="80"):
        """High-level web enumeration: chains directory discovery and vuln scanning."""
        if not target or not target.strip():
            raise MissingTargetError("Cible requise pour l'enumeration web.")
        target = target.strip()
        port = self._coerce_text(port, "80").strip() or "80"
        self._validate_scope(target)

        results = []
        url = f"http://{target}:{port}"

        # Step 1: Directory discovery with gobuster
        if shutil.which("gobuster"):
            try:
                results.append(self.execute_command(
                    f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q",
                    f"Enumeration des repertoires web sur {target}:{port}",
                ))
            except (ToolExecutionError, OSError):
                results.append({"tool": "gobuster", "error": "echec"})
        else:
            results.append({"tool": "gobuster", "skipped": "non installe"})

        # Step 2: Vulnerability scanning with nikto
        if shutil.which("nikto"):
            try:
                results.append(self.execute_command(
                    f"nikto -h {url} -Tuning 1",
                    f"Scan de vulnerabilites web sur {target}:{port}",
                ))
            except (ToolExecutionError, OSError):
                results.append({"tool": "nikto", "error": "echec"})
        else:
            results.append({"tool": "nikto", "skipped": "non installe"})

        return {"target": target, "port": port, "scans": results}

    def _test_credentials(self, target, service, username, password):
        """Test credentials on a specific service (SSH, FTP, SMB)."""
        if not target or not target.strip():
            raise MissingTargetError("Cible requise pour le test de credentials.")
        target = target.strip()
        service = (service or "").strip().lower()
        username = (username or "").strip()
        password = (password or "").strip()

        if not service:
            raise ToolExecutionError("Service requis (ssh, ftp, smb, http).")
        if not username:
            raise ToolExecutionError("Nom d'utilisateur requis.")

        self._validate_scope(target)

        if service == "ssh":
            if not shutil.which("sshpass"):
                # Fallback: try hydra single-credential
                if shutil.which("hydra"):
                    return self.execute_command(
                        f"hydra -l {username} -p {password} {target} ssh -t 4",
                        f"Test SSH {username}@{target}",
                    )
                raise ToolMissingError("sshpass")
            return self.execute_command(
                f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@{target} id",
                f"Test SSH {username}@{target}",
            )
        elif service == "ftp":
            # Use curl for FTP login test
            if shutil.which("curl"):
                return self.execute_command(
                    f"curl -s --connect-timeout 5 -u {username}:{password} ftp://{target}/",
                    f"Test FTP {username}@{target}",
                )
            raise ToolMissingError("curl")
        elif service == "smb":
            if shutil.which("smbclient"):
                return self.execute_command(
                    f"smbclient -L //{target} -U {username}%{password} -N",
                    f"Test SMB {username}@{target}",
                )
            raise ToolMissingError("smbclient")
        elif service == "http":
            if shutil.which("curl"):
                return self.execute_command(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 -u {username}:{password} http://{target}/",
                    f"Test HTTP auth {username}@{target}",
                )
            raise ToolMissingError("curl")
        else:
            raise ToolExecutionError(
                f"Service non supporte: {service}. "
                "Utilise ssh, ftp, smb, ou http."
            )

    def _enumerate_dns(self, domain):
        """Enumerate DNS records for a domain using available tools."""
        domain = (domain or "").strip()
        if not domain:
            raise ToolExecutionError("Domaine requis pour l'enumeration DNS.")

        results = []

        # Try dig first (most common)
        if shutil.which("dig"):
            try:
                results.append(self.execute_command(
                    f"dig {domain} ANY +noall +answer",
                    f"Requete DNS ANY pour {domain}",
                ))
            except (ToolExecutionError, OSError):
                results.append({"tool": "dig", "error": "echec"})
        # Fallback to host
        elif shutil.which("host"):
            try:
                results.append(self.execute_command(
                    f"host -a {domain}",
                    f"Requete DNS pour {domain}",
                ))
            except (ToolExecutionError, OSError):
                results.append({"tool": "host", "error": "echec"})
        else:
            results.append({"tool": "dns", "skipped": "ni dig ni host disponible"})

        # Try dnsenum if available for subdomain enumeration
        if shutil.which("dnsenum"):
            try:
                results.append(self.execute_command(
                    f"dnsenum --noreverse {domain}",
                    f"Enumeration DNS complete pour {domain}",
                ))
            except (ToolExecutionError, OSError):
                results.append({"tool": "dnsenum", "error": "echec"})

        return {"domain": domain, "results": results}

    def _capture_evidence(self, title, content, source_tool=""):
        """Save a piece of evidence to workspace/evidence/ with timestamp."""
        title = (title or "").strip()
        content = (content or "").strip()
        if not title:
            raise ToolExecutionError("Titre requis pour la preuve.")
        if not content:
            raise ToolExecutionError("Contenu requis pour la preuve.")

        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize title for filename
        safe_title = re.sub(r"[^a-zA-Z0-9_-]", "_", title)[:50]
        filename = f"{timestamp}_{safe_title}.md"

        evidence_dir = self.workspace / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / filename

        lines = [
            f"# Preuve: {title}",
            "",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        if source_tool:
            lines.append(f"**Source:** {source_tool}")
        lines.extend(["", "## Contenu", "", "```", content, "```", ""])

        evidence_path.write_text("\n".join(lines), encoding="utf-8")
        return {
            "path": str(evidence_path),
            "filename": filename,
            "title": title,
            "written": len(content),
        }

    def query_knowledge(self, query):
        suggestions = self.knowledge_store.suggest(query, limit=3)
        matches = []
        for item in suggestions:
            matches.append(
                {
                    "slug": item.case.slug,
                    "platform": item.case.platform,
                    "summary": item.case.summary,
                    "signals": list(item.matched_signals or item.case.signals[:2]),
                    "actions": list(item.matched_actions or item.case.actions[:2]),
                    "pivots": list(item.matched_pivots or item.case.pivots[:1]),
                }
            )
        return {"query": query, "matches": matches}

    def suggest_pentest_tools(self, phase="", target_type=""):
        """Suggest pentest tools based on phase and target type."""
        phase = phase.strip() or None
        target_type = target_type.strip() or None
        suggested = self.tool_registry.suggest_tools(
            phase=phase,
            target_type=target_type,
            installed_only=False,
        )
        tools = []
        for tool in suggested[:10]:
            tools.append({
                "name": tool.name,
                "category": tool.category.value,
                "description": tool.description,
                "installed": tool.installed,
                "package": tool.package,
            })
        return {"phase": phase, "target_type": target_type, "tools": tools}

    def list_findings(self):
        """Return accumulated findings summary."""
        if not self.findings_store:
            return {"summary": "Pas de store de findings actif.", "count": 0}
        return {
            "summary": self.findings_store.summary(),
            "count": self.findings_store.count,
        }

    def _plan_attack(self):
        """Generate an attack plan from current findings."""
        if not self.findings_store:
            return {"error": "Pas de findings disponibles pour generer un plan."}
        # Import engagement and target from the agent loop if linked
        engagement = getattr(self, "_engagement", None)
        active_target = getattr(self, "_active_target", None)
        if not engagement:
            from app.methodology import EngagementState
            engagement = EngagementState()
        plan = build_attack_plan(self.findings_store, active_target, engagement)
        return {
            "target": plan.target,
            "phase": plan.phase,
            "step_count": len(plan.steps),
            "progress": plan.progress_summary,
            "plan_prompt": format_plan_prompt(plan),
            "steps": [
                {
                    "index": s.index,
                    "name": s.name,
                    "tool": s.tool,
                    "arguments": s.arguments,
                    "priority": s.priority.value,
                    "depends_on": s.depends_on,
                    "status": s.status.value,
                    "rationale": s.rationale,
                }
                for s in plan.steps
            ],
        }

    def _route_services(self):
        """Analyze discovered services and generate targeted playbooks."""
        if not self.findings_store:
            return {"error": "Pas de findings disponibles pour le routage."}

        services = extract_services_from_findings(self.findings_store)
        if not services:
            return {"error": "Aucun service detecte. Lance un scan nmap d'abord."}

        active_target = getattr(self, "_active_target", None)
        target_label = active_target.label if active_target else "cible"
        plan = build_service_plan(services, target_label)

        entries_data = []
        for entry in plan.entries:
            pb = entry["playbook"]
            entries_data.append({
                "port": entry["port"],
                "service": entry["service_name"],
                "version": entry.get("version", ""),
                "label": pb.label,
                "priority": pb.priority,
                "tools": list(pb.tools),
                "checks": list(pb.checks),
            })

        return {
            "target": target_label,
            "service_count": len(entries_data),
            "playbooks": entries_data,
            "prompt_fragment": plan.prompt_fragment,
        }

    def _exploit_workflow(self, query, target=""):
        """Exploit research workflow: searchsploit → copy → analyze."""
        query = (query or "").strip()
        target = (target or "").strip()
        if not query:
            raise ToolExecutionError("Terme de recherche requis (CVE-ID ou nom de service).")

        if target:
            self._validate_scope(target)

        result = {
            "query": query,
            "target": target,
            "exploits_found": [],
            "copied_exploits": [],
            "analysis": "",
        }

        # Step 1: Search for exploits via searchsploit
        if not shutil.which("searchsploit"):
            raise ToolMissingError("searchsploit")

        search_result = self.execute_command(
            f"searchsploit --json {query}",
            f"Recherche d'exploits pour {query}",
        )

        stdout = search_result.get("stdout", "") if isinstance(search_result, dict) else ""

        # Parse JSON output from searchsploit
        exploit_paths = []
        try:
            import json
            data = json.loads(stdout)
            for exploit in data.get("RESULTS_EXPLOIT", []):
                title = exploit.get("Title", "")
                path = exploit.get("Path", "")
                if title and path:
                    result["exploits_found"].append({"title": title, "path": path})
                    exploit_paths.append(path)
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse text output
            for line in stdout.splitlines():
                if "exploits/" in line or "shellcodes/" in line:
                    parts = line.rsplit("|", 1)
                    if len(parts) == 2:
                        title = parts[0].strip()
                        path = parts[1].strip()
                        result["exploits_found"].append({"title": title, "path": path})
                        exploit_paths.append(path)

        if not exploit_paths:
            result["analysis"] = f"Aucun exploit trouve pour '{query}'. Essaie avec des termes differents."
            return result

        # Step 2: Copy the most relevant exploit locally (first result)
        exploits_dir = self.workspace / "exploits"
        exploits_dir.mkdir(parents=True, exist_ok=True)

        # Copy up to 3 most relevant exploits
        for exploit_path in exploit_paths[:3]:
            try:
                copy_result = self.execute_command(
                    f"searchsploit -m {exploit_path}",
                    f"Copie locale de l'exploit {exploit_path}",
                )
                # Find the copied file
                filename = Path(exploit_path).name
                copied_path = self.workspace / filename
                if copied_path.exists():
                    # Move to exploits/ directory
                    dest = exploits_dir / filename
                    copied_path.rename(dest)
                    result["copied_exploits"].append({
                        "path": str(dest),
                        "filename": filename,
                    })
            except (ToolExecutionError, OSError):
                continue

        # Step 3: Read and analyze the first copied exploit
        if result["copied_exploits"]:
            first_exploit = result["copied_exploits"][0]
            try:
                exploit_content = Path(first_exploit["path"]).read_text(
                    encoding="utf-8", errors="replace"
                )[:3000]
                analysis_parts = [
                    f"Exploit: {first_exploit['filename']}",
                    f"Chemin local: {first_exploit['path']}",
                    "",
                    "--- Debut du code exploit (extrait) ---",
                    exploit_content[:2000],
                    "--- Fin de l'extrait ---",
                    "",
                ]
                # Detect common parameters to adapt
                if target:
                    analysis_parts.append(
                        f"Cible a configurer dans l'exploit: {target}"
                    )
                if "RHOST" in exploit_content or "rhost" in exploit_content:
                    analysis_parts.append("Parametre RHOST detecte — a configurer avec l'IP cible.")
                if "LHOST" in exploit_content or "lhost" in exploit_content:
                    analysis_parts.append("Parametre LHOST detecte — a configurer avec l'IP de l'attaquant.")
                if "LPORT" in exploit_content or "lport" in exploit_content:
                    analysis_parts.append("Parametre LPORT detecte — a configurer avec le port d'ecoute.")

                analysis_parts.append(
                    "\nATTENTION: Revue humaine requise avant toute execution d'exploit."
                )
                result["analysis"] = "\n".join(analysis_parts)
            except OSError:
                result["analysis"] = "Impossible de lire l'exploit copie."
        else:
            result["analysis"] = (
                f"{len(result['exploits_found'])} exploit(s) trouve(s) mais impossible de les copier localement."
            )

        return result

    def _execute_parallel(self):
        """Execute independent attack plan steps in parallel."""
        if not self.findings_store:
            return {"error": "Pas de findings disponibles pour l'execution parallele."}

        from app.parallel_executor import ParallelToolExecutor, format_batch_result

        engagement = getattr(self, "_engagement", None)
        active_target = getattr(self, "_active_target", None)
        if not engagement:
            from app.methodology import EngagementState
            engagement = EngagementState()

        plan = build_attack_plan(self.findings_store, active_target, engagement)

        parallel = ParallelToolExecutor(self, max_workers=3)
        independent_steps = parallel.find_independent_steps(plan)

        if not independent_steps:
            return {"error": "Aucune etape independante a executer en parallele."}

        batch_result = parallel.execute_batch(independent_steps)

        # Mark completed steps in the plan
        for r in batch_result.results:
            if r.success:
                plan.mark_done(r.step_index)
            else:
                plan.mark_skipped(r.step_index)

        return {
            "summary": batch_result.summary,
            "success_count": batch_result.success_count,
            "failure_count": batch_result.failure_count,
            "total_duration": batch_result.total_duration_seconds,
            "results": [
                {
                    "step_index": r.step_index,
                    "tool": r.tool_name,
                    "success": r.success,
                    "error": r.error,
                    "duration": r.duration_seconds,
                }
                for r in batch_result.results
            ],
            "display": format_batch_result(batch_result),
        }

    def read_file(self, path):
        file_path = self._resolve_read_path(path)
        if not file_path.exists():
            raise ToolExecutionError(f"Fichier introuvable: {path}")
        return {"path": str(file_path), "content": file_path.read_text(encoding="utf-8")}

    def write_file(self, path, content):
        if not path.strip():
            raise ToolExecutionError("Chemin d'ecriture vide.")
        file_path = (self.workspace / path).resolve()
        if not self._is_within(file_path, self.workspace):
            raise ToolExecutionError("L'ecriture est limitee au workspace.")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        return {"path": str(file_path), "written": len(content)}

    def execute_command(self, command, reason=""):
        if self.command_permission_mode == "deny":
            raise ToolExecutionError("L'execution de commandes est desactivee pour cette session.")

        command = command.strip()
        if not command:
            raise ToolExecutionError("Commande vide.")

        if any(token in command for token in BLOCKED_TOKENS):
            raise ToolExecutionError("Les operateurs shell complexes ne sont pas autorises.")

        # Validate pipe usage — only safe filter commands allowed after |
        if "|" in command:
            self._validate_pipeline(command)

        # Validate scope before execution
        self._validate_scope_in_command(command)

        args = shlex.split(command, posix=True)
        if not args:
            raise ToolExecutionError("Commande vide.")
        if any(argument in TARGET_PLACEHOLDERS for argument in args):
            raise MissingTargetError(
                "J'ai besoin d'une cible concrete (IP ou URL) avant d'executer cette commande."
            )

        executable = args[0]
        if executable in ALWAYS_BLOCKED_COMMANDS:
            raise ToolExecutionError(f"Commande bloquee: {executable}")
        if self.allowed_commands is not None and executable not in self.allowed_commands:
            raise ToolExecutionError(f"Commande non autorisee: {executable}")
        # Allow both safe defaults and registry-known pentest tools
        known_executables = SAFE_DEFAULT_COMMANDS | self.tool_registry.known_executables()
        if self.allowed_commands is None and executable not in known_executables:
            if not shutil.which(executable):
                raise ToolMissingError(executable)
        elif not shutil.which(executable):
            raise ToolMissingError(executable)

        if self.command_permission_mode != "session" and executable not in self._session_allow_commands:
            decision = self._request_permission("execute_command", command, reason)
            if decision == "session":
                self._session_allow_commands.add(executable)
                self.command_permission_mode = "session"
            elif decision is not True:
                raise PermissionDenied(command)

        try:
            executable = args[0]
            timeout = TOOL_TIMEOUTS.get(executable, 30)
            has_pipe = "|" in command
            if self.progress_callback and not has_pipe:
                return self._execute_command_streaming(args, command, reason, timeout)
            completed = subprocess.run(
                command if has_pipe else args,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=has_pipe,
            )
            return self._attach_command_log({
                "command": command,
                "reason": reason,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            })
        except subprocess.TimeoutExpired as exc:
            stdout_partial = exc.stdout.decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr_partial = exc.stderr.decode('utf-8', errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return self._attach_command_log({
                "command": command,
                "reason": reason,
                "stdout": stdout_partial,
                "stderr": stderr_partial,
                "returncode": 124,  # Standard timeout exit code
                "error": f"La commande a expire apres {exc.timeout} secondes."
            })

    def _execute_command_streaming(self, args, command, reason, timeout):
        process = subprocess.Popen(
            args,
            cwd=str(self.workspace),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        output_queue = queue.Queue()
        stdout_chunks = []
        stderr_chunks = []
        reader_threads = []
        tool_name = args[0] if args else "commande"
        heartbeat_interval = 5.0 if tool_name == "nmap" else 10.0
        progress_interval = 5.0 if tool_name == "nmap" else 10.0
        start_time = time.monotonic()
        last_output_time = start_time
        last_heartbeat_time = start_time
        last_progress_time = 0.0
        last_progress_content = ""
        progress_state = {
            "tool": args[0] if args else "commande",
            "phase": "",
            "percent": "",
            "eta": "",
            "elapsed": "",
        }

        self._emit_progress(
            {
                "type": "tool_progress",
                "command": command,
                "stream": "status",
                "content": f"{tool_name} | demarrage | timeout {timeout}s",
                "tool": tool_name,
                "progress_kind": "start",
                "timeout": timeout,
                "ephemeral": True,
            }
        )

        def _elapsed_label(now):
            elapsed = int(now - start_time)
            minutes, seconds = divmod(elapsed, 60)
            if minutes:
                return f"{minutes}m{seconds:02d}"
            return f"{seconds}s"

        def _compact_progress(stream_name, content, now):
            tool_name = progress_state["tool"]
            if tool_name == "nmap":
                stats_match = re.search(r"Stats:\s+([0-9:]+)\s+elapsed;.*undergoing\s+(.+)$", content)
                if stats_match:
                    progress_state["elapsed"] = stats_match.group(1)
                    progress_state["phase"] = stats_match.group(2).strip()
                    phase = progress_state["phase"] or "scan en cours"
                    return {
                        "content": f"nmap | {phase} | ecoule {progress_state['elapsed']}",
                        "progress_kind": "activity",
                        "tool": "nmap",
                        "phase": phase,
                        "elapsed_label": progress_state["elapsed"],
                    }
                timing_match = re.search(
                    r"^(.+?) Timing:\s+About\s+([0-9.]+)% done(?:.*\(([^)]*remaining)\))?",
                    content,
                )
                if timing_match:
                    progress_state["phase"] = timing_match.group(1).strip()
                    progress_state["percent"] = f"{float(timing_match.group(2)):.1f}%"
                    progress_state["eta"] = timing_match.group(3) or ""
                elif re.match(r"^\d+/(tcp|udp)\s+open\s+", content):
                    return {
                        "content": f"nmap | port ouvert detecte: {content}",
                        "progress_kind": "finding",
                        "tool": "nmap",
                        "detail": content,
                    }
                elif content.startswith("Nmap scan report for"):
                    target = content.removeprefix("Nmap scan report for").strip()
                    return {
                        "content": f"nmap | rapport detecte pour {target}",
                        "progress_kind": "activity",
                        "tool": "nmap",
                        "detail": f"rapport detecte pour {target}",
                    }
                else:
                    return None
                parts = ["nmap"]
                if progress_state["phase"]:
                    parts.append(progress_state["phase"])
                if progress_state["percent"]:
                    parts.append(progress_state["percent"])
                parts.append(f"ecoule {_elapsed_label(now)}")
                if progress_state["eta"]:
                    parts.append(progress_state["eta"])
                return {
                    "content": " | ".join(parts),
                    "progress_kind": "activity",
                    "tool": "nmap",
                    "phase": progress_state["phase"],
                    "percent": progress_state["percent"],
                    "elapsed_label": _elapsed_label(now),
                    "eta": progress_state["eta"],
                }

            if tool_name in {"gobuster", "dirb", "ffuf"}:
                progress_match = re.search(
                    r"Progress:\s*\[?\s*([0-9]+)\s*/\s*([0-9]+)\s*\]?\s*(?:\(([0-9.]+)%\))?",
                    content,
                    re.IGNORECASE,
                )
                if progress_match:
                    done = progress_match.group(1)
                    total = progress_match.group(2)
                    percent = progress_match.group(3)
                    if not percent and total != "0":
                        percent = f"{(int(done) / int(total)) * 100:.1f}"
                    percent_label = f"{float(percent):.1f}%" if percent else ""
                    parts = [tool_name]
                    if percent_label:
                        parts.append(percent_label)
                    parts.append(f"{done}/{total}")
                    return {
                        "content": " | ".join(parts),
                        "progress_kind": "activity",
                        "tool": tool_name,
                        "phase": "fuzzing",
                        "percent": percent_label,
                        "detail": f"{done}/{total}",
                        "elapsed_label": _elapsed_label(now),
                    }

                status_match = re.search(r"(\/[^\s]*)\s+\(Status:\s*([0-9]{3})", content)
                if status_match:
                    detail = f"{status_match.group(1)} ({status_match.group(2)})"
                    return {
                        "content": f"{tool_name} | chemin trouve: {detail}",
                        "progress_kind": "finding",
                        "tool": tool_name,
                        "detail": detail,
                    }
                found_match = re.search(r"^Found:\s+(/[^\s]+).*Status:\s*([0-9]{3})", content)
                if found_match:
                    detail = f"{found_match.group(1)} ({found_match.group(2)})"
                    return {
                        "content": f"{tool_name} | chemin trouve: {detail}",
                        "progress_kind": "finding",
                        "tool": tool_name,
                        "detail": detail,
                    }
                dirb_match = re.search(r"^\+\s+https?://[^/]+(/[^\s]+).*\(CODE:([0-9]{3})", content)
                if dirb_match:
                    detail = f"{dirb_match.group(1)} ({dirb_match.group(2)})"
                    return {
                        "content": f"{tool_name} | chemin trouve: {detail}",
                        "progress_kind": "finding",
                        "tool": tool_name,
                        "detail": detail,
                    }
                if content.startswith("/"):
                    return {
                        "content": f"{tool_name} | chemin trouve: {content[:140]}",
                        "progress_kind": "finding",
                        "tool": tool_name,
                        "detail": content[:140],
                    }

            if tool_name == "nikto" and stream_name == "stdout" and content.startswith("+"):
                return {
                    "content": f"nikto | {content[:140]}",
                    "progress_kind": "finding",
                    "tool": "nikto",
                    "detail": content[:140],
                }

            if stream_name == "stderr":
                return {
                    "content": f"{tool_name} | stderr: {content[:140]}",
                    "progress_kind": "warning",
                    "tool": tool_name,
                    "detail": content[:140],
                }
            return None

        def _emit_compact(stream_name, content, *, force=False):
            nonlocal last_progress_time, last_progress_content
            now = time.monotonic()
            payload = _compact_progress(stream_name, content, now)
            if not payload:
                return
            compact = payload["content"]
            milestone = (
                force
                or payload.get("progress_kind") == "finding"
                or " Timing:" in content
                or "Timing:" in content
            )
            if not milestone and compact == last_progress_content:
                return
            if not milestone and now - last_progress_time < progress_interval:
                return
            last_progress_time = now
            last_progress_content = compact
            event = {
                "type": "tool_progress",
                "command": command,
                "stream": "status",
                "ephemeral": True,
            }
            event.update(payload)
            self._emit_progress(event)

        def _reader(stream_name, stream):
            try:
                for chunk in iter(stream.readline, ""):
                    if chunk == "":
                        break
                    output_queue.put((stream_name, chunk))
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        for stream_name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                continue
            thread = threading.Thread(
                target=_reader,
                args=(stream_name, stream),
                daemon=True,
            )
            thread.start()
            reader_threads.append(thread)

        timed_out = False

        while True:
            try:
                stream_name, chunk = output_queue.get(timeout=0.2)
                if stream_name == "stdout":
                    stdout_chunks.append(chunk)
                else:
                    stderr_chunks.append(chunk)
                for raw_line in str(chunk).splitlines():
                    content = raw_line.strip()
                    if not content:
                        continue
                    last_output_time = time.monotonic()
                    last_heartbeat_time = last_output_time
                    _emit_compact(stream_name, content, force=bool(re.match(r"^\d+/(tcp|udp)\s+open\s+", content)))
            except queue.Empty:
                pass

            now = time.monotonic()
            if now - start_time >= timeout:
                timed_out = True
                process.kill()
                break

            if (
                process.poll() is not None
                and output_queue.empty()
                and all(not thread.is_alive() for thread in reader_threads)
            ):
                break

            if now - last_heartbeat_time >= heartbeat_interval and now - last_output_time >= heartbeat_interval:
                elapsed = int(now - start_time)
                self._emit_progress(
                    {
                        "type": "tool_progress",
                        "command": command,
                        "stream": "status",
                        "content": f"commande toujours en cours... {elapsed}s",
                        "tool": tool_name,
                        "progress_kind": "heartbeat",
                        "elapsed": elapsed,
                        "ephemeral": True,
                    }
                )
                last_heartbeat_time = now

        for thread in reader_threads:
            thread.join(timeout=0.2)

        while not output_queue.empty():
            stream_name, chunk = output_queue.get_nowait()
            if stream_name == "stdout":
                stdout_chunks.append(chunk)
            else:
                stderr_chunks.append(chunk)

        stdout_text = "".join(stdout_chunks)
        stderr_text = "".join(stderr_chunks)

        if timed_out:
            self._emit_progress(
                {
                    "type": "tool_progress",
                    "command": command,
                    "stream": "status",
                    "content": f"commande expiree apres {timeout}s",
                    "tool": tool_name,
                    "progress_kind": "timeout",
                    "timeout": timeout,
                    "elapsed": timeout,
                }
            )
            return self._attach_command_log({
                "command": command,
                "reason": reason,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "returncode": 124,
                "duration_seconds": int(time.monotonic() - start_time),
                "error": f"La commande a expire apres {timeout} secondes.",
            })

        process.wait(timeout=1)
        return self._attach_command_log({
            "command": command,
            "reason": reason,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "returncode": process.returncode,
            "duration_seconds": int(time.monotonic() - start_time),
        })

    def execute_admin_command(self, command, reason="", *, interactive=False, skip_permission=False):
        if self.command_permission_mode == "deny":
            raise ToolExecutionError("L'execution de commandes est desactivee pour cette session.")

        command = command.strip()
        if not command:
            raise ToolExecutionError("Commande admin vide.")

        if any(token in command for token in BLOCKED_TOKENS):
            raise ToolExecutionError("Les operateurs shell complexes ne sont pas autorises.")

        raw_args = shlex.split(command, posix=True)
        normalized_args = self._normalize_admin_args(raw_args)
        display_command = " ".join(normalized_args)
        executable = normalized_args[0]

        if not skip_permission:
            if (
                self.command_permission_mode != "session"
                and executable not in self._session_allow_commands
            ):
                decision = self._request_permission("execute_admin_command", display_command, reason)
                if decision == "session":
                    self._session_allow_commands.add(executable)
                    self.command_permission_mode = "session"
                elif decision is not True:
                    raise PermissionDenied(display_command)

        plan = self._build_admin_command_plan(normalized_args, interactive=interactive)
        try:
            if interactive:
                completed = subprocess.run(
                    plan["command_args"],
                    cwd=str(self.workspace),
                    timeout=300,
                    check=False,
                )
            else:
                completed = subprocess.run(
                    plan["command_args"],
                    cwd=str(self.workspace),
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise ToolExecutionError(
                f"La commande admin a expire: {plan['display_command']}"
            ) from exc
        except KeyboardInterrupt as exc:
            raise ToolExecutionError(
                f"La commande admin a ete interrompue: {plan['display_command']}"
            ) from exc

        result = {
            "command": plan["display_command"],
            "reason": reason,
            "stdout": completed.stdout if not interactive else "",
            "stderr": completed.stderr if not interactive else "",
            "returncode": completed.returncode,
        }
        if completed.returncode != 0 and not interactive and self._needs_interactive_sudo(result):
            raise InteractiveAdminRequired(plan["display_command"], plan["manual_command"])
        return result

    def build_install_plan(self, executable, *, interactive=False):
        executable = self.tool_registry.normalize_name(executable)
        # Check both static map and dynamic registry
        package_name = INSTALLABLE_PACKAGES.get(executable)
        if not package_name:
            package_name = self.tool_registry.get_package(executable)
        if not package_name:
            raise ToolExecutionError(
                f"Installation automatique non supportee pour {executable}."
            )

        apt_get = shutil.which("apt-get")
        if not apt_get:
            raise ToolExecutionError(
                "Installation automatique disponible uniquement sur les systemes avec apt-get."
            )

        prefix = []
        manual_prefix = ""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise ToolExecutionError(
                    "Installation automatique impossible sans privileges root ou sudo."
                )
            prefix = [sudo_path]
            if not interactive:
                prefix.append("-n")
            manual_prefix = "sudo "

        apt_options = ["-qq", "-o", "Dpkg::Use-Pty=0"]
        commands = [
            prefix + [apt_get] + apt_options + ["update"],
            prefix + [apt_get] + apt_options + ["install", "-y", package_name],
        ]
        manual_command = (
            f"{manual_prefix}apt-get -qq -o Dpkg::Use-Pty=0 update && "
            f"{manual_prefix}apt-get -qq -o Dpkg::Use-Pty=0 install -y {package_name}"
        )
        return {
            "executable": executable,
            "package": package_name,
            "commands": commands,
            "manual_command": manual_command,
        }

    def build_install_batch_plan(self, executables, *, interactive=False):
        names = self._coerce_tool_names(executables)
        if not names:
            raise ToolExecutionError("Liste d'outils vide.")

        packages = []
        seen_packages = set()
        for executable in names:
            package_name = INSTALLABLE_PACKAGES.get(executable)
            if not package_name:
                package_name = self.tool_registry.get_package(executable)
            if not package_name:
                raise ToolExecutionError(
                    f"Installation automatique non supportee pour {executable}."
                )
            if package_name not in seen_packages:
                packages.append(package_name)
                seen_packages.add(package_name)

        apt_get = shutil.which("apt-get")
        if not apt_get:
            raise ToolExecutionError(
                "Installation automatique disponible uniquement sur les systemes avec apt-get."
            )

        prefix = []
        manual_prefix = ""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise ToolExecutionError(
                    "Installation automatique impossible sans privileges root ou sudo."
                )
            prefix = [sudo_path]
            if not interactive:
                prefix.append("-n")
            manual_prefix = "sudo "

        apt_options = ["-qq", "-o", "Dpkg::Use-Pty=0"]
        commands = [
            prefix + [apt_get] + apt_options + ["update"],
            prefix + [apt_get] + apt_options + ["install", "-y", *packages],
        ]
        manual_command = (
            f"{manual_prefix}apt-get -qq -o Dpkg::Use-Pty=0 update && "
            f"{manual_prefix}apt-get -qq -o Dpkg::Use-Pty=0 install -y {' '.join(packages)}"
        )
        return {
            "executables": names,
            "packages": packages,
            "commands": commands,
            "manual_command": manual_command,
        }

    def _sudo_validation_args(self):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sudo_path = shutil.which("sudo")
            if sudo_path:
                return [sudo_path, "-v"]
        return None

    def _build_admin_command_plan(self, args, *, interactive=False):
        executable = args[0]
        executable_path = shutil.which(executable)
        if not executable_path:
            raise ToolMissingError(executable)

        prefix = []
        manual_prefix = ""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise ToolExecutionError(
                    "Execution admin impossible sans privileges root ou sudo."
                )
            prefix = [sudo_path]
            if not interactive:
                prefix.append("-n")
            manual_prefix = "sudo "

        return {
            "display_command": " ".join(args),
            "manual_command": manual_prefix + " ".join(args),
            "command_args": prefix + [executable_path] + args[1:],
        }

    def install_tool(self, executable, *, interactive=False):
        executable = self.tool_registry.normalize_name(executable)
        plan = self.build_install_plan(executable, interactive=False)
        steps = []

        if interactive:
            validation_args = self._sudo_validation_args()
            if validation_args:
                try:
                    completed = subprocess.run(
                        validation_args,
                        cwd=str(self.workspace),
                        timeout=300,
                        check=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise ToolExecutionError(
                        f"La validation sudo pour {executable} a expire."
                    ) from exc
                except KeyboardInterrupt as exc:
                    raise ToolExecutionError(
                        f"La validation sudo pour {executable} a ete interrompue."
                    ) from exc
                steps.append(
                    {
                        "command": " ".join(validation_args),
                        "stdout": "",
                        "stderr": "",
                        "returncode": completed.returncode,
                    }
                )
                if completed.returncode != 0:
                    self.tool_registry.refresh()
                    return {
                        "executable": executable,
                        "package": plan["package"],
                        "manual_command": plan["manual_command"],
                        "status": "failed",
                        "steps": steps,
                    }

        for args in plan["commands"]:
            try:
                completed = subprocess.run(
                    args,
                    cwd=str(self.workspace),
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ToolExecutionError(
                    f"L'installation de {executable} a expire sur la commande: {' '.join(args)}"
                ) from exc
            except KeyboardInterrupt as exc:
                raise ToolExecutionError(
                    f"L'installation interactive de {executable} a ete interrompue."
                ) from exc

            step = {
                "command": " ".join(args),
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            }
            steps.append(step)

            if completed.returncode != 0:
                break

        self.tool_registry.refresh()

        status = "installed"
        if steps and steps[-1]["returncode"] != 0:
            if not interactive and self._needs_interactive_sudo(steps[-1]):
                status = "manual_required"
            else:
                status = "failed"
        elif not shutil.which(executable):
            status = "failed"

        return {
            "executable": executable,
            "package": plan["package"],
            "manual_command": plan["manual_command"],
            "status": status,
            "steps": steps,
        }

    def install_tools(self, executables, *, interactive=False):
        plan = self.build_install_batch_plan(executables, interactive=False)
        steps = []

        if interactive:
            validation_args = self._sudo_validation_args()
            if validation_args:
                try:
                    completed = subprocess.run(
                        validation_args,
                        cwd=str(self.workspace),
                        timeout=300,
                        check=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise ToolExecutionError("La validation sudo pour l'installation a expire.") from exc
                except KeyboardInterrupt as exc:
                    raise ToolExecutionError("La validation sudo pour l'installation a ete interrompue.") from exc
                steps.append(
                    {
                        "command": " ".join(validation_args),
                        "stdout": "",
                        "stderr": "",
                        "returncode": completed.returncode,
                    }
                )
                if completed.returncode != 0:
                    self.tool_registry.refresh()
                    return {
                        "executables": plan["executables"],
                        "packages": plan["packages"],
                        "manual_command": plan["manual_command"],
                        "status": "failed",
                        "steps": steps,
                        "installed": [],
                        "missing": plan["executables"],
                    }

        for args in plan["commands"]:
            try:
                completed = subprocess.run(
                    args,
                    cwd=str(self.workspace),
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ToolExecutionError(
                    f"L'installation a expire sur la commande: {' '.join(args)}"
                ) from exc
            except KeyboardInterrupt as exc:
                raise ToolExecutionError("L'installation interactive a ete interrompue.") from exc

            step = {
                "command": " ".join(args),
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            }
            steps.append(step)
            if completed.returncode != 0:
                break

        self.tool_registry.refresh()
        installed = [name for name in plan["executables"] if shutil.which(name)]
        missing = [name for name in plan["executables"] if not shutil.which(name)]

        status = "installed"
        if steps and steps[-1]["returncode"] != 0:
            if not interactive and self._needs_interactive_sudo(steps[-1]):
                status = "manual_required"
            else:
                status = "failed"
        elif missing and installed:
            status = "partial"
        elif missing:
            status = "failed"

        return {
            "executables": plan["executables"],
            "packages": plan["packages"],
            "manual_command": plan["manual_command"],
            "status": status,
            "steps": steps,
            "installed": installed,
            "missing": missing,
        }

    def _request_permission(self, tool_name, details, reason):
        if not self.permission_callback:
            return False
        return self.permission_callback(
            tool_name=tool_name,
            details=details,
            reason=reason,
        )

    def _resolve_read_path(self, path):
        raw_path = Path(path)
        if raw_path.is_absolute():
            candidate = raw_path.resolve()
            if self._is_within(candidate, self.workspace) or self._is_within(
                candidate, self.knowledge_root
            ):
                return candidate
            raise ToolExecutionError("Lecture non autorisee hors workspace/ et knowledge/.")

        workspace_candidate = (self.workspace / raw_path).resolve()
        if workspace_candidate.exists() and self._is_within(workspace_candidate, self.workspace):
            return workspace_candidate

        knowledge_candidate = (self.knowledge_root / raw_path).resolve()
        if knowledge_candidate.exists() and self._is_within(
            knowledge_candidate, self.knowledge_root
        ):
            return knowledge_candidate

        return workspace_candidate

    def _is_within(self, path, root):
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def _validate_pipeline(self, command):
        """Validate that a piped command only pipes to safe filter commands."""
        segments = command.split("|")
        for segment in segments[1:]:
            stripped = segment.strip()
            if not stripped:
                raise ToolExecutionError("Pipe vide detecte dans la commande.")
            exe = stripped.split()[0]
            if exe not in SAFE_PIPE_TARGETS:
                raise ToolExecutionError(
                    f"Pipe vers '{exe}' non autorise. "
                    f"Commandes de filtrage autorisees: {', '.join(sorted(SAFE_PIPE_TARGETS))}."
                )

    def set_scope(self, scope_entries):
        """Define the authorized scope. Empty set = no restriction."""
        self.authorized_scope = {
            str(entry).strip()
            for entry in (scope_entries or [])
            if str(entry).strip()
        }

    def _is_in_scope(self, target_str):
        """Check if a target IP/CIDR/domain/URL is within the authorized scope."""
        raw_target = str(target_str or "").strip()
        target_host, target_port = self._normalize_scope_host(target_str)
        target_addr = None
        target_net = None
        parsed_network_target = False
        for candidate in (raw_target, target_host):
            if not candidate:
                continue
            try:
                target_addr = ipaddress.ip_address(candidate)
                parsed_network_target = True
                break
            except ValueError:
                pass
            try:
                target_net = ipaddress.ip_network(candidate, strict=False)
                parsed_network_target = True
                break
            except ValueError:
                pass

        if not parsed_network_target:
            return self._is_domain_in_scope(target_host, target_port)

        for entry in self.authorized_scope:
            try:
                scope_net = ipaddress.ip_network(entry, strict=False)
                if target_addr is not None:
                    if target_addr in scope_net:
                        return True
                else:
                    if target_net.subnet_of(scope_net):
                        return True
            except ValueError:
                entry_host, entry_port = self._normalize_scope_host(entry)
                if raw_target == entry or (
                    entry_host
                    and self._host_matches_scope(target_host, entry_host)
                    and self._port_matches_scope(target_port, entry_port)
                ):
                    return True
        return False

    def _validate_scope(self, target_str):
        """Raise ScopeViolationError if target is outside authorized scope."""
        if not self.authorized_scope:
            return  # No scope defined = no restriction
        if not self._is_in_scope(target_str):
            raise ScopeViolationError(
                f"Cible {target_str} hors scope autorise. "
                f"Scope: {', '.join(sorted(self.authorized_scope))}"
            )

    def _validate_scope_in_command(self, command):
        """Check IPs, domains and URLs in a command string against the scope."""
        if not self.authorized_scope:
            return
        targets_in_cmd = _SCOPE_TARGET_RE.findall(command)
        for target in targets_in_cmd:
            self._validate_scope(target)
        for target in self._extract_domain_targets_from_command(command):
            self._validate_scope(target)

    def _is_domain_in_scope(self, target_host, target_port=None):
        """Validate hostnames only when the scope contains hostname entries."""
        if not target_host:
            return True
        domain_entries = []
        for entry in self.authorized_scope:
            entry_host, entry_port = self._normalize_scope_host(entry)
            if not entry_host:
                continue
            try:
                ipaddress.ip_address(entry_host)
                continue
            except ValueError:
                pass
            try:
                ipaddress.ip_network(entry_host, strict=False)
                continue
            except ValueError:
                pass
            domain_entries.append((entry_host, entry_port))

        if not domain_entries:
            return True  # IP-only scopes keep legacy domain behavior.
        return any(
            self._host_matches_scope(target_host, entry_host)
            and self._port_matches_scope(target_port, entry_port)
            for entry_host, entry_port in domain_entries
        )

    def _normalize_scope_host(self, value):
        raw = str(value or "").strip()
        if not raw:
            return "", None
        raw = raw.strip("[](){}'\"")
        if "://" in raw:
            parsed = urlparse(raw)
        else:
            parsed = urlparse(f"//{raw}")
        host = parsed.hostname
        port = None
        try:
            port = parsed.port
        except ValueError:
            port = None
        if not host:
            host = raw.split("/", 1)[0].split(":", 1)[0]
        host = host.strip().rstrip(".").lower()
        return host, port

    def _host_matches_scope(self, target_host, scope_host):
        target_host = (target_host or "").strip().rstrip(".").lower()
        scope_host = (scope_host or "").strip().rstrip(".").lower()
        if not target_host or not scope_host:
            return False
        if scope_host.startswith("*."):
            suffix = scope_host[2:]
            return target_host.endswith(f".{suffix}")
        return target_host == scope_host

    def _port_matches_scope(self, target_port, scope_port):
        return scope_port is None or target_port == scope_port

    def _extract_domain_targets_from_command(self, command):
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        if not tokens:
            return []

        executable = Path(tokens[0]).name
        if executable not in NETWORK_TARGET_COMMANDS:
            return []

        targets = []
        skip_next = False
        for token in tokens[1:]:
            if skip_next:
                skip_next = False
                continue
            if token in COMMAND_NON_TARGET_VALUE_FLAGS:
                skip_next = True
                continue
            if token.startswith("-"):
                continue

            candidate = self._extract_target_candidate(token)
            if candidate:
                targets.append(candidate)
        return targets

    def _extract_target_candidate(self, token):
        token = str(token or "").strip().strip("'\"")
        if not token:
            return ""
        if token.startswith("//"):
            token = token[2:].split("/", 1)[0]
        if "@" in token and "://" not in token:
            token = token.rsplit("@", 1)[-1]
        match = _URL_TARGET_RE.search(token)
        if match:
            return match.group(0).rstrip(".,;")
        token = token.rstrip(".,;")
        host, _port = self._normalize_scope_host(token)
        if _HOSTNAME_RE.match(host):
            return token
        return ""

    def _needs_interactive_sudo(self, step):
        stderr = (step.get("stderr") or "").casefold()
        stdout = (step.get("stdout") or "").casefold()
        combined = "\n".join([stdout, stderr])
        markers = (
            "a password is required",
            "interactive authentication is required",
            "mot de passe",
            "terminal is required",
            "a terminal is required",
        )
        return any(marker in combined for marker in markers)

    def _normalize_admin_args(self, args):
        if not args:
            raise ToolExecutionError("Commande admin vide.")

        normalized = list(args)
        if normalized[0] == "sudo":
            normalized = normalized[1:]
            while normalized and normalized[0].startswith("-"):
                normalized = normalized[1:]
            if not normalized:
                raise ToolExecutionError("Commande admin vide.")

        executable = normalized[0]
        if executable in ALWAYS_BLOCKED_COMMANDS:
            raise ToolExecutionError(f"Commande admin bloquee: {executable}")

        if executable in ADMIN_COMMANDS:
            normalized[0] = "apt-get"
            if len(normalized) < 2:
                raise ToolExecutionError("Sous-commande apt manquante.")

            subcommand = ADMIN_SUBCOMMAND_ALIASES.get(normalized[1], normalized[1])
            normalized[1] = subcommand
            if subcommand not in ADMIN_ALLOWED_SUBCOMMANDS:
                raise ToolExecutionError(
                    "Sous-commande admin non supportee. "
                    "Utilise apt update, apt upgrade, apt full-upgrade ou apt autoremove."
                )

            if subcommand in {"upgrade", "dist-upgrade", "autoremove"} and "-y" not in normalized[2:]:
                normalized.append("-y")

        return normalized
