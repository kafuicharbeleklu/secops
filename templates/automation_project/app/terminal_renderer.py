import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolFailure:
    cause: str
    impact: str
    next_action: str
    retry: bool
    log_path: str
    severity: str


class TerminalRenderer:
    def render(self, events, *, model_label):
        lines = []
        dim_lines = set()
        line_styles = {}
        tone = "success"
        saw_tool_activity = False
        final_answer = ""
        previous_event = None

        for event in events:
            event_type = event["type"]

            if event_type in {"thinking_start", "thinking_end"}:
                continue
            if event_type == "thought":
                for text_line in self._split_text(event["content"]):
                    idx = len(lines)
                    lines.append(f"• {text_line}")
                    dim_lines.add(idx)
                continue

            if event_type == "reasoning_summary":
                for text_line in self._split_text(event["content"]):
                    idx = len(lines)
                    lines.append(f"→ {text_line}")
                    dim_lines.add(idx)
                previous_event = event
                continue

            if event_type == "tool_start":
                saw_tool_activity = True
                lines.append(self._format_tool_start(event["name"], event.get("args", {})))
                previous_event = event
                continue

            if event_type == "tool_progress":
                saw_tool_activity = True
                lines.append(self._format_tool_progress(event))
                previous_event = event
                continue

            if event_type == "tool_success":
                saw_tool_activity = True
                result_lines = self._format_tool_result(event["name"], event.get("result", {}))
                if previous_event and previous_event["type"] == "tool_start":
                    start_line = self._format_tool_start(
                        previous_event["name"],
                        previous_event.get("args", {}),
                    )
                    if (
                        previous_event["name"] == event["name"]
                        and result_lines
                        and result_lines[0] == start_line
                    ):
                        result_lines = result_lines[1:]
                result_lines.extend(self._format_notification(event))
                lines.extend(result_lines)
                previous_event = event
                continue

            if event_type == "tool_denied":
                failure = self._tool_failure_from_event(event)
                tone = failure.severity
                lines.extend(self._format_tool_failure(event["name"], failure))
                lines.extend(self._format_notification(event))
                previous_event = event
                continue

            if event_type == "tool_error":
                failure = self._tool_failure_from_event(event)
                tone = failure.severity
                lines.extend(self._format_tool_failure(event["name"], failure))
                lines.extend(self._format_notification(event))
                previous_event = event
                continue

            if event_type == "tool_policy_blocked":
                failure = self._tool_failure_from_event(event)
                tone = failure.severity
                lines.extend(self._format_tool_failure(event["name"], failure))
                lines.extend(self._format_notification(event))
                previous_event = event
                continue

            if event_type == "tool_failure":
                failure = self._coerce_tool_failure(event.get("failure", {}), event)
                tone = failure.severity
                lines.extend(self._format_tool_failure(event.get("name", "outil"), failure))
                lines.extend(self._format_notification(event))
                previous_event = event
                continue

            if event_type == "findings":
                preview = event.get("preview", "")
                if preview:
                    lines.append(f"  └ {event['count']} decouverte(s) ({event['tool']}): {preview}")
                else:
                    lines.append(f"  └ {event['count']} decouverte(s) ({event['tool']})")
                previous_event = event
                continue

            if event_type == "phase_advance":
                lines.append(f"• Phase: {event['from']} -> {event['to']}")
                previous_event = event
                continue

            if event_type == "final_answer":
                final_answer = event["content"]
                answer_lines = self._split_text(final_answer)
                # Deduplicate: if all thought lines match the final answer,
                # remove the duplicate thought lines
                thought_indices = sorted(dim_lines)
                if thought_indices:
                    thought_texts = [lines[i].removeprefix("• ") for i in thought_indices]
                    if thought_texts == answer_lines:
                        for i in reversed(thought_indices):
                            lines.pop(i)
                        dim_lines.clear()
                if lines:
                    lines.append("")
                lines.extend(answer_lines)
                previous_event = event
                continue

            previous_event = event

        return {
            "title": "Agent",
            "lines": lines,
            "tone": tone if lines else "muted",
            "answer": "\n".join(self._split_text(final_answer)),
            "dim_lines": dim_lines,
            "line_styles": line_styles,
            "meta": {"tool_activity": saw_tool_activity, "model": model_label},
        }

    def _coerce_tool_failure(self, failure, event):
        if isinstance(failure, ToolFailure):
            return failure
        data = failure if isinstance(failure, dict) else {}
        result = event.get("result", {}) if isinstance(event.get("result", {}), dict) else {}
        cause = (
            data.get("cause")
            or event.get("error")
            or result.get("error")
            or event.get("message")
            or "Erreur outil non detaillee."
        )
        impact = data.get("impact") or self._infer_failure_impact(event, str(cause))
        next_action = (
            data.get("next_action")
            or event.get("remediation")
            or result.get("retry_hint")
            or self._infer_failure_action(event, str(cause))
        )
        retry = data.get("retry")
        if retry is None:
            retry = event.get("type") in {"tool_denied", "tool_error"}
        log_path = data.get("log_path") or result.get("log_path") or event.get("log_path") or ""
        severity = data.get("severity") or self._infer_failure_severity(event, str(cause))
        return ToolFailure(
            cause=str(cause),
            impact=str(impact),
            next_action=str(next_action),
            retry=bool(retry),
            log_path=str(log_path),
            severity=str(severity or "warn"),
        )

    def _tool_failure_from_event(self, event):
        return self._coerce_tool_failure(event.get("failure", {}), event)

    def _format_tool_failure(self, name, failure):
        retry_label = "/retry last" if failure.retry else "non"
        log_label = failure.log_path or "/view last --pager"
        return [
            f"  ✖ ERREUR — {name}",
            f"    Cause      : {failure.cause}",
            f"    Impact     : {failure.impact}",
            f"    Action     : {failure.next_action}",
            f"    Retry      : {retry_label}",
            f"    Log complet: {log_label}",
        ]

    def _format_notification(self, event):
        summary = str(event.get("notification") or "").strip()
        if not summary:
            return []
        return [f"  └ notification: {summary}"]

    def _infer_failure_impact(self, event, cause):
        event_type = event.get("type", "")
        name = event.get("name", "outil")
        lowered = cause.casefold()
        if event_type == "tool_denied":
            return "action outil non executee"
        if event_type == "tool_policy_blocked":
            return "action bloquee par la politique de securite"
        if "timeout" in lowered or "expire" in lowered:
            return "resultat incomplet ou indisponible"
        if "scope" in lowered or "cible" in lowered or "target" in lowered:
            return "operation impossible sans cible ou scope valide"
        if "non installe" in lowered or "introuvable" in lowered:
            return "outil requis indisponible"
        return f"{name} interrompu avant resultat exploitable"

    def _infer_failure_action(self, event, cause):
        event_type = event.get("type", "")
        lowered = cause.casefold()
        if event_type == "tool_denied":
            return "autoriser la relance si l'action est dans le scope"
        if event.get("remediation"):
            return event["remediation"]
        if "timeout" in lowered or "expire" in lowered:
            return "augmenter le timeout ou reduire le perimetre"
        if "scope" in lowered:
            return "verifier le scope autorise avec /scope"
        if "cible" in lowered or "target" in lowered:
            return "definir une cible avec /target"
        if "non installe" in lowered or "introuvable" in lowered:
            return "installer l'outil via /tools install"
        return "verifier les arguments, le scope et relancer si necessaire"

    def _infer_failure_severity(self, event, cause):
        if event.get("type") == "tool_policy_blocked":
            return "warn"
        lowered = cause.casefold()
        if "permission" in lowered or "refusee" in lowered:
            return "warn"
        return "error"

    def _format_tool_start(self, name, args):
        if name == "query_knowledge":
            return f"• Memoire: {args.get('query', '')}"
        if name == "read_file":
            return f"• Lecture: {args.get('path', '')}"
        if name == "write_file":
            return f"• Ecriture: {args.get('path', '')}"
        if name == "execute_command":
            return f"• Commande: {args.get('command', '')}"
        if name == "execute_admin_command":
            return f"• Commande admin: {args.get('command', '')}"
        if name == "install_pentest_tool":
            return f"• Installation: {args.get('tool_name', '?')}"
        if name == "install_pentest_tools":
            tool_names = args.get("tool_names", "")
            if isinstance(tool_names, (list, tuple)):
                tool_names = ", ".join(str(item) for item in tool_names)
            return f"• Installation: {tool_names or '?'}"
        if name == "suggest_pentest_tools":
            return "• Recherche d'outils recommandes"
        if name == "list_findings":
            return "• Consultation des decouvertes"
        if name == "scan_target":
            target = args.get("target", "?")
            mode = args.get("mode", "quick")
            return f"• Scan: {target} ({mode})"
        if name == "enumerate_web":
            return f"• Enumeration web: {args.get('target', '?')}:{args.get('port', '80')}"
        if name == "analyze_service":
            service = args.get("service", "?")
            version = args.get("version", "")
            port = args.get("port", "")
            label = f"{service} {version}".strip()
            return f"• Analyse service: {label}{f' port {port}' if port else ''}"
        return f"• Outil: {name}"

    def _format_tool_progress(self, event):
        structured = self._format_structured_progress(event)
        if structured:
            return structured

        content = event.get("content", "")
        stream = event.get("stream", "status")
        if stream == "stderr":
            return f"  ├ stderr | {content}"
        return f"  ├ {content}"

    def _format_structured_progress(self, event):
        kind = event.get("progress_kind", "")
        if not kind:
            return ""

        tool = event.get("tool") or self._progress_tool_from_content(event.get("content", ""))
        label = tool or "commande"
        if kind == "start":
            timeout = event.get("timeout")
            suffix = f" | timeout {timeout}s" if timeout else ""
            return f"  ├ {label} demarre{suffix}"
        if kind == "heartbeat":
            elapsed = event.get("elapsed")
            suffix = f" | {elapsed}s" if elapsed is not None else ""
            return f"  ├ {label} en cours{suffix}"
        if kind == "activity":
            parts = [label]
            if event.get("phase"):
                parts.append(str(event["phase"]))
            if event.get("percent"):
                parts.append(str(event["percent"]))
            if event.get("elapsed_label"):
                parts.append(f"ecoule {event['elapsed_label']}")
            elif event.get("elapsed"):
                parts.append(f"ecoule {event['elapsed']}s")
            if event.get("eta"):
                parts.append(str(event["eta"]))
            if len(parts) == 1 and event.get("detail"):
                parts.append(str(event["detail"]))
            return f"  ├ {' | '.join(parts)}"
        if kind == "finding":
            detail = event.get("detail") or event.get("content", "")
            return f"  ├ {label} trouve: {detail}"
        if kind == "warning":
            detail = event.get("detail") or event.get("content", "")
            return f"  ├ {label} avertissement: {detail}"
        if kind == "timeout":
            elapsed = event.get("elapsed") or event.get("timeout")
            suffix = f" apres {elapsed}s" if elapsed else ""
            return f"  ├ {label} expire{suffix}"
        return ""

    def _progress_tool_from_content(self, content):
        content = str(content or "")
        if " | " not in content:
            return ""
        return content.split(" | ", 1)[0].strip()

    def _format_tool_result(self, name, result):
        if isinstance(result, dict) and result.get("command") and "returncode" in result:
            return self._format_command_result(result)

        if name == "query_knowledge":
            matches = result.get("matches", [])
            if not matches:
                return ["  └ aucun cas analogue trouve"]
            lines = []
            for match in matches[:3]:
                line = f"  └ {match['slug']} ({match['platform']})"
                if match.get("summary"):
                    line += f" - {match['summary']}"
                lines.append(line)
                for action in match.get("actions", [])[:1]:
                    lines.append(f"    piste: {action}")
            return lines

        if name == "read_file":
            content = result.get("content", "")
            lines = [f"  └ lecture de {result.get('path', '')}"]
            snippet = self._split_text(content)[:20]
            lines.extend([f"    {line}" for line in snippet])
            if len(self._split_text(content)) > len(snippet):
                lines.append("    ... contenu supplementaire omis")
            return lines

        if name == "write_file":
            return [f"  └ ecriture de {result.get('path', '')}"]

        if name in ("execute_command", "execute_admin_command"):
            return self._format_command_result(result)

        if name == "install_pentest_tool":
            status = result.get("status", "unknown")
            tool = result.get("tool", result.get("executable", "?"))
            if status == "already_installed":
                return [f"  └ {tool} est deja installe"]
            if status == "installed":
                return [f"  └ {tool} installe avec succes"]
            if status == "failed":
                return [f"  └ echec de l'installation de {tool}"]
            return [f"  └ {tool}: {status}"]

        if name == "install_pentest_tools":
            status = result.get("status", "unknown")
            installed = result.get("installed") or result.get("tools") or []
            missing = result.get("missing") or []
            if status == "already_installed":
                return [f"  └ deja installe(s): {', '.join(installed)}"]
            lines = [f"  └ installation groupee: {status}"]
            if installed:
                lines.append(f"    installe(s): {', '.join(installed)}")
            if missing:
                lines.append(f"    absent(s): {', '.join(missing)}")
            return lines

        if name == "suggest_pentest_tools":
            tools = result.get("tools", [])
            if not tools:
                return ["  └ aucun outil recommande"]
            lines = []
            for t in tools[:6]:
                installed = "✓" if t.get("installed") else "✗"
                lines.append(f"  └ {installed} {t['name']} ({t.get('category', '')})")
            return lines

        if name == "list_findings":
            count = result.get("count", 0)
            if not count:
                return ["  └ aucune decouverte"]
            return [f"  └ {count} decouverte(s) accumulee(s)"]

        # Generic fallback with result summary
        if isinstance(result, dict):
            summary = ", ".join(f"{k}={v}" for k, v in list(result.items())[:3])
            return [f"  └ {summary[:80]}"]
        return [f"  └ {str(result)[:80]}"]

    def _format_command_result(self, result):
        returncode = result.get("returncode", 0)
        stdout_lines = result.get("stdout_lines")
        stderr_lines = result.get("stderr_lines")
        if stdout_lines is None:
            stdout_lines = len(self._split_text(result.get("stdout", "")))
        if stderr_lines is None:
            stderr_lines = len(self._split_text(result.get("stderr", "")))

        status = "terminee" if returncode == 0 else f"terminee avec code {returncode}"
        parts = [f"commande {status}"]
        if result.get("duration_seconds") is not None:
            parts.append(f"duree: {result['duration_seconds']}s")
        if stdout_lines:
            parts.append(f"stdout: {stdout_lines} ligne(s)")
        if stderr_lines:
            parts.append(f"stderr: {stderr_lines} ligne(s)")
        lines = [f"  └ {' | '.join(parts)}"]
        summary = self._summarize_command_result(result)
        if result.get("log_path"):
            lines.append(f"    top findings: {summary or 'aucun signal prioritaire detecte'}")
            lines.append(f"    log complet: {result['log_path']}")
        elif summary:
            lines.append(f"    resultat: {summary}")
        if result.get("error"):
            lines.append(f"    erreur: {result['error']}")
        return lines

    def _summarize_command_result(self, result):
        command = result.get("command", "")
        executable = self._command_executable(command)
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        text = stdout if stdout else stderr
        if not text:
            return ""

        if executable == "nmap":
            ports = []
            for line in self._split_text(text):
                match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)?", line)
                if not match:
                    continue
                service = match.group(3) or ""
                label = f"{match.group(1)}/{service}" if service else f"{match.group(1)}/{match.group(2)}"
                ports.append(label)
            if ports:
                preview = ", ".join(ports[:6])
                more = f" (+{len(ports) - 6})" if len(ports) > 6 else ""
                return f"{len(ports)} port(s) ouvert(s): {preview}{more}"

        if executable in {"gobuster", "dirb", "ffuf"}:
            paths = []
            for line in self._split_text(text):
                path = self._extract_web_path(line)
                if path and path not in paths:
                    paths.append(path)
            if paths:
                preview = ", ".join(paths[:6])
                more = f" (+{len(paths) - 6})" if len(paths) > 6 else ""
                return f"{len(paths)} chemin(s) trouve(s): {preview}{more}"

        if executable == "nikto":
            findings = [line for line in self._split_text(text) if line.startswith("+")]
            if findings:
                return f"{len(findings)} signalement(s) nikto"

        return ""

    def _command_executable(self, command):
        try:
            head = str(command or "").strip().split()[0]
        except IndexError:
            return ""
        return head.rsplit("/", 1)[-1]

    def _extract_web_path(self, line):
        text = str(line or "").strip()
        patterns = (
            r"^Found:\s+(/[^\s]+)",
            r"^(/\S+)\s+\(Status:\s*\d{3}",
            r"^\+\s+https?://[^/]+(/[^\s]+)",
            r"^(/\S+)\s+\[Status:\s*\d{3}",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return ""

    def _split_text(self, text):
        lines = [line.strip() for line in str(text).splitlines() if line.strip()]
        return lines or ([str(text).strip()] if str(text).strip() else [])
