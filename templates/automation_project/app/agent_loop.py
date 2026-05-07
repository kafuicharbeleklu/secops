import json

from app.audit_logger import AuditLogger

from app.attack_planner import (
    AttackPlan,
    StepStatus,
    build_attack_plan,
    format_plan_prompt,
    reconcile_attack_plan,
)
from app.findings import FindingsStore, FindingType, parse_tool_output
from app.methodology import EngagementState
from app.service_router import build_service_plan, extract_services_from_findings
from app.target_context import build_target_context, merge_findings
from app.tool_executor import (
    InteractiveAdminRequired,
    MissingTargetError,
    PermissionDenied,
    ScopeViolationError,
    ToolExecutionError,
    ToolMissingError,
    ToolsMissingError,
)
from app.tool_policy import ToolPolicyError


class AgentLoop:
    MAX_HISTORY = 30

    CORE_PROMPT = (
        "Tu es SECOPS, un agent expert en tests d'intrusion et securite offensive. "
        "Tu operes sur des labs autorises et des infrastructures reelles selon les directives de l'utilisateur. "
        "Tu raisonnes par boucle observation -> hypothese -> action -> observation. "
        "Tu adaptes ta methodologie selon la phase du pentest (recon, enum, exploit, post-exploit, rapport). "
        "Tu es specialise pentesting: privilegie les hypotheses, outils, services et pivots de securite offensive, "
        "pas les raisonnements generalistes hors sujet. "
        "La memoire locale sert a proposer des pistes transferables, mais jamais a affirmer un fait sur la cible courante sans verification. "
        "Si un bloc MEMOIRE CANDIDATE ou Cas actif est fourni, utilise-le pour orienter la methode puis confirme chaque observation avec un outil. "
        "Quand une action concrete est utile, tu utilises les outils disponibles plutot "
        "que de rester au stade du conseil. "
        "Respecte strictement la portee de la demande utilisateur: pour une question precise, "
        "execute seulement l'action necessaire puis reponds; ne poursuis pas automatiquement "
        "le playbook vers l'enumeration ou l'exploitation sans demande explicite. "
        "Pour un premier scan de cible, utilise scan_target en mode quick sauf demande explicite de scan complet; "
        "n'utilise full que si quick est insuffisant ou si l'utilisateur demande tous les ports. "
        "Si l'utilisateur salue, remercie ou pose une question sociale simple, reponds naturellement sans outil. "
        "N'invente jamais de placeholder de cible comme TARGET_IP. Si la cible manque pour une commande d'attaque ou scan, demande-la. (L'installation d'outils n'exige pas de cible). "
        "Si un outil requis manque, arrete-toi et demande si son installation est autorisee. "
        "N'essaie jamais d'installer toi-meme un outil avec apt, pip ou brew dans execute_command. "
        "Si l'utilisateur demande d'installer un seul outil, utilise 'install_pentest_tool'. "
        "Si l'utilisateur demande d'installer plusieurs outils dans la meme demande, utilise 'install_pentest_tools' avec toute la liste; ne les installe pas un par un. "
        "Si la demande concerne la machine locale (apt, sudo, paquets, systeme actuel), "
        "n'exige pas d'IP cible et utilise execute_admin_command pour les actions privilegiees. "
        "Formate tes reponses finales dans un style Codex: commence par un titre court en ligne avec '• ', "
        "utilise des sections simples terminees par ':' quand utile, des listes avec '- ', "
        "et evite les titres Markdown '##' ou le gras decoratif. "
        "Apres chaque resultat d'outil, analyse les decouvertes et formule une hypothese "
        "avant de lancer l'action suivante. Si un resultat est vide ou inattendu, "
        "propose une approche alternative au lieu de repeter la meme commande."
    )

    # Keep legacy alias for backward compatibility with tests
    SYSTEM_PROMPT = CORE_PROMPT

    def __init__(
        self,
        llm_client,
        tool_executor,
        *,
        max_iterations=15,
        audit_logger=None,
        learning_journal=None,
    ):
        self.llm_client = llm_client
        self.tool_executor = tool_executor
        self.max_iterations = max_iterations
        self.messages = []
        self.pending_external_tool = None
        self.findings_store = FindingsStore()
        self.engagement = EngagementState()
        self.targets = []
        self.active_target = None
        self.current_plan = None
        self._plan_signature = None
        self._failed_commands = set()
        self._tools_this_turn = 0
        self._turn_tool_budget = 1
        self._turn_prompt = ""
        self.audit_logger = audit_logger
        self.learning_journal = learning_journal
        self.active_case_label = ""

    def run(self, user_input, case_context):
        self._turn_prompt = user_input or ""
        self._turn_tool_budget = self._tool_budget_for_prompt(self._turn_prompt)
        self.messages.append({"role": "user", "content": user_input})
        yield from self._run_iterations(case_context)

    def resume_after_external_tool(
        self,
        case_context,
        *,
        result,
        tool_name=None,
        arguments=None,
        thought="",
    ):
        pending = self.pending_external_tool
        if pending:
            tool_name = tool_name or pending.get("tool_name")
            arguments = arguments or pending.get("arguments", {})
            thought = thought or pending.get("thought", "")
            pending_prompt = (
                pending.get("install_prompt", "")
                or pending.get("retry_prompt", "")
                or pending.get("admin_prompt", "")
            )
            if (
                self.messages
                and self.messages[-1].get("role") == "assistant"
                and self.messages[-1].get("content") == pending_prompt
            ):
                self.messages.pop()
        self.pending_external_tool = None

        if not tool_name:
            raise RuntimeError("Aucun outil externe en attente a reprendre.")

        self.refresh_plan(force=False)
        resumed_step = self._match_plan_step(tool_name, arguments or {})
        if resumed_step:
            if self._result_succeeded(result):
                self.current_plan.mark_done(resumed_step.index)
            else:
                self.current_plan.mark_failed(resumed_step.index)
        parser_tool, new_findings = self._collect_findings_from_result(
            tool_name,
            arguments or {},
            result,
        )

        self._append_tool_exchange(
            tool_name,
            arguments or {},
            result,
            thought or f"Appel outil: {tool_name}",
        )
        for event in self._handle_new_findings(parser_tool, new_findings):
            yield event
        yield from self._run_iterations(case_context, tools_already_run=1)

    def _trim_history(self):
        """Keep conversation history within bounds, with summary preservation."""
        if len(self.messages) <= self.MAX_HISTORY:
            return

        # Extract messages that will be trimmed (skip the first user message)
        to_summarize = self.messages[1:-self.MAX_HISTORY]
        if to_summarize:
            summary = self._build_conversation_summary(to_summarize)
            # Keep: first user message + compact summary + recent messages
            self.messages = (
                self.messages[:1]
                + [{"role": "system", "content": f"RESUME DES ECHANGES PRECEDENTS:\n{summary}"}]
                + self.messages[-self.MAX_HISTORY:]
            )
        else:
            self.messages = self.messages[:1] + self.messages[-self.MAX_HISTORY:]

    def export_state(self) -> dict:
        """Export session state for persistence."""
        return {
            "phase": self.engagement.phase.value,
            "tools_used": list(self.engagement.tools_used),
            "targets": [
                {
                    "raw": t.raw,
                    "address": t.address,
                    "target_type": t.target_type.value,
                    "ports": t.ports,
                    "services": dict(t.services),
                    "os_hint": t.os_hint,
                    "tags": list(t.tags),
                }
                for t in self.targets
            ],
            "active_target": self.active_target.label if self.active_target else "",
            "findings_count": self.findings_store.count,
            "conversation_summary": self._build_conversation_summary(
                self.messages[-10:]
            ),
            "attack_plan": self.current_plan.to_dict() if self.current_plan else {},
        }

    def import_state(self, state: dict) -> None:
        """Restore session state from a persisted dict."""
        from app.methodology import PentestPhase
        from app.target_context import Target, TargetType

        # Restore phase
        phase_value = state.get("phase", "recon")
        for p in PentestPhase:
            if p.value == phase_value:
                self.engagement.set_phase(p, "Restauration de session.")
                break

        # Restore tools used
        for tool in state.get("tools_used", []):
            self.engagement.record_tool_use(tool)

        # Restore targets
        self.targets.clear()
        for t_data in state.get("targets", []):
            try:
                target_type = TargetType(t_data.get("target_type", "ip"))
            except ValueError:
                target_type = TargetType.IP
            target = Target(
                raw=t_data.get("raw", ""),
                target_type=target_type,
                address=t_data.get("address", ""),
                ports=t_data.get("ports", []),
                services={int(k): v for k, v in t_data.get("services", {}).items()},
                os_hint=t_data.get("os_hint", ""),
                tags=set(t_data.get("tags", [])),
            )
            self.targets.append(target)

        # Restore active target
        active_label = state.get("active_target", "")
        self.active_target = None
        if active_label and self.targets:
            for t in self.targets:
                if t.label == active_label:
                    self.active_target = t
                    break

        self.current_plan = AttackPlan.from_dict(state.get("attack_plan", {}))
        self._plan_signature = None

    def _plan_context_signature(self):
        active_label = self.active_target.label if self.active_target else ""
        findings_signature = tuple(
            sorted(
                (
                    finding.finding_type.value,
                    finding.value,
                    finding.source_tool,
                    finding.target_ref,
                )
                for finding in self.findings_store.all
            )
        )
        return (
            self.engagement.phase.value,
            active_label,
            tuple(self.engagement.tools_used),
            findings_signature,
        )

    def refresh_plan(self, force=False):
        signature = self._plan_context_signature()
        if not force and self.current_plan and signature == self._plan_signature:
            return self.current_plan
        new_plan = build_attack_plan(self.findings_store, self.active_target, self.engagement)
        self.current_plan = reconcile_attack_plan(self.current_plan, new_plan)
        self._plan_signature = signature
        return self.current_plan

    @staticmethod
    def _result_succeeded(result):
        if not isinstance(result, dict):
            return True
        if result.get("error"):
            return False
        return result.get("returncode", 0) == 0

    def _match_plan_step(self, tool_name, arguments):
        if not self.current_plan:
            return None
        normalized_args = tuple(
            sorted((str(key), str(value)) for key, value in (arguments or {}).items())
        )
        for step in self.current_plan.steps:
            if step.status != StepStatus.PENDING:
                continue
            if step.signature == (tool_name, normalized_args):
                return step
        return None

    def _collect_findings_from_result(self, tool_name, arguments, result):
        if not isinstance(result, dict):
            return "", []
        stdout = result.get("stdout", "")
        if not stdout:
            return "", []

        parser_tool = ""
        if tool_name in ("execute_command", "execute_admin_command"):
            command = (arguments.get("command") or "").strip()
            parser_tool = command.split()[0] if command else ""
        elif tool_name == "scan_target":
            parser_tool = "nmap"

        if not parser_tool:
            return "", []

        self.engagement.record_tool_use(parser_tool)
        return parser_tool, self.findings_store.ingest_tool_output(parser_tool, stdout)

    def _record_learning_attempt(
        self,
        tool_name,
        arguments,
        result,
        *,
        status,
        new_findings=None,
    ):
        if not self.learning_journal:
            return
        if isinstance(result, dict):
            summary = (
                result.get("error")
                or result.get("stdout")
                or result.get("stderr")
                or result.get("recommendation")
                or result.get("status")
                or ""
            )
            retry_hint = result.get("retry_hint", "")
        else:
            summary = str(result)
            retry_hint = ""
        target = self.active_target.label if self.active_target else ""
        findings = [finding.value for finding in (new_findings or [])]
        try:
            self.learning_journal.append_attempt(
                tool_name=tool_name,
                arguments=arguments or {},
                status=status,
                target=target,
                phase=self.engagement.phase.value,
                case_label=self.active_case_label,
                result_summary=summary,
                findings=findings,
                retry_hint=retry_hint,
            )
        except OSError:
            return

    def _learning_decision_context(self):
        if not self.learning_journal:
            return ""
        try:
            return self.learning_journal.decision_context(limit=8)
        except (AttributeError, OSError):
            return ""

    def _tool_budget_for_prompt(self, prompt):
        lowered = (prompt or "").casefold()
        broad_markers = (
            "autonome",
            "chaine",
            "chaîne",
            "continue",
            "continuer",
            "demarche complete",
            "démarche complète",
            "enchaîne",
            "enchaine",
            "exploite",
            "exploitation complete",
            "fais tout",
            "full pentest",
            "jusqu'au flag",
            "poursuis",
            "prends la main",
            "root",
            "trouve le flag",
        )
        if any(marker in lowered for marker in broad_markers):
            return max(1, self.max_iterations - 1)
        return 1

    def _bounded_final_instruction(self):
        return (
            "L'action demandee pour ce tour vient d'etre executee. "
            "Formule maintenant la reponse finale avec les resultats disponibles. "
            "Ne lance aucun nouvel outil et ne poursuis pas le playbook automatiquement."
        )

    def _bounded_result_summary(self):
        ports = sorted(
            {finding.value for finding in self.findings_store.ports},
            key=lambda value: int(value) if str(value).isdigit() else str(value),
        )
        services = [finding.value for finding in self.findings_store.services]
        if ports:
            parts = [
                f"Ports ouverts detectes: {', '.join(ports)}.",
                f"Nombre de ports ouverts: {len(ports)}.",
            ]
            if services:
                parts.append(f"Services identifies: {', '.join(services[:5])}.")
            parts.append("Je n'ai pas lance d'autre outil, car la demande etait bornee a cette action.")
            return " ".join(parts)
        return (
            "Action demandee executee. Je n'ai pas lance d'autre outil, "
            "car la demande etait bornee a cette action."
        )

    def _handle_new_findings(self, source_tool, new_findings):
        events = []
        if not new_findings:
            return events

        if self.active_target:
            merge_findings(self.active_target, new_findings)

        preview_items = [finding.value for finding in new_findings[:3]]
        preview = ", ".join(preview_items) if preview_items else ""
        events.append(
            {
                "type": "findings",
                "count": len(new_findings),
                "tool": source_tool,
                "preview": preview,
            }
        )
        if self.audit_logger:
            self.audit_logger.log_finding(
                source_tool,
                len(new_findings),
                preview,
                target=self.active_target.label if self.active_target else "",
                phase=self.engagement.phase.value,
            )

        if self.engagement.should_suggest_advance(self.findings_store.all):
            next_candidate = self.engagement.next_phase_candidate()
            guard_message = self.engagement.phase_guard_message(
                next_candidate,
                has_scope=bool(getattr(self.tool_executor, "authorized_scope", set())),
                confirmed=False,
            )
            if guard_message:
                events.append({"type": "thought", "content": guard_message})
            else:
                prev_phase = self.engagement.phase
                next_phase = self.engagement.advance_phase(
                    f"Progression auto: {source_tool} a revele {len(new_findings)} decouverte(s)."
                )
                if next_phase:
                    events.append(
                        {
                            "type": "phase_advance",
                            "from": prev_phase.value,
                            "to": next_phase.value,
                        }
                    )
                    if self.audit_logger:
                        self.audit_logger.log_phase_change(
                            prev_phase.value,
                            next_phase.value,
                            f"{source_tool} a revele {len(new_findings)} decouverte(s).",
                            target=self.active_target.label if self.active_target else "",
                        )

        self.refresh_plan(force=True)
        return events

    def _run_iterations(self, case_context, *, tools_already_run=0):
        self._trim_history()
        self._tools_this_turn = tools_already_run
        # Sync engagement and target to executor for plan_attack
        self.tool_executor._engagement = self.engagement
        self.tool_executor._active_target = self.active_target
        if hasattr(self.tool_executor, "available_tools_for_context"):
            tool_specs = self.tool_executor.available_tools_for_context(
                phase=self.engagement.phase.value,
                prompt=self._turn_prompt,
                findings_store=self.findings_store,
            )
        else:
            tool_specs = self.tool_executor.available_tools()
        findings_summary = self.findings_store.summary()
        structured_findings = self.findings_store.structured_summary()
        phase_context = self.engagement.phase_context_prompt(findings_summary)
        target_context = build_target_context(self.targets, self.active_target)
        prompt_parts = [self.CORE_PROMPT, phase_context, target_context, case_context]
        plan = self.refresh_plan(force=False)
        if structured_findings:
            prompt_parts.append(f"FINDINGS ACCUMULES:\n{structured_findings}")
        plan_prompt = format_plan_prompt(plan)
        if plan_prompt:
            prompt_parts.append(plan_prompt)
        learning_context = self._learning_decision_context()
        if learning_context:
            prompt_parts.append(learning_context)
        # Inject service-specific playbooks when services are discovered
        services = extract_services_from_findings(self.findings_store)
        if services:
            target_label = self.active_target.label if self.active_target else "cible"
            service_plan = build_service_plan(services, target_label)
            if service_plan.prompt_fragment:
                prompt_parts.append(service_plan.prompt_fragment)
        if self._failed_commands:
            prompt_parts.append(
                f"COMMANDES DEJA ECHOUEES (ne pas repeter): {', '.join(sorted(self._failed_commands)[-10:])}\n"
                "Utilise une approche differente ou des arguments differents."
            )
        system_prompt = "\n\n".join(prompt_parts)
        if self._tools_this_turn >= self._turn_tool_budget:
            self.messages.append({"role": "user", "content": self._bounded_final_instruction()})

        for _ in range(self.max_iterations):
            yield {"type": "thinking_start"}
            decision = self.llm_client.decide_next_step(
                self.messages,
                system_prompt,
                tool_specs,
            )
            yield {"type": "thinking_end"}

            if decision.thought:
                yield {"type": "thought", "content": decision.thought}

            if decision.final_answer:
                self.messages.append({"role": "assistant", "content": decision.final_answer})
                yield {"type": "final_answer", "content": decision.final_answer}
                return

            if not decision.tool_name:
                fallback = decision.raw_text.strip() or "Aucune reponse exploitable du modele."
                self.messages.append({"role": "assistant", "content": fallback})
                yield {"type": "final_answer", "content": fallback}
                return

            repeated_failed_command = ""
            if decision.tool_name in ("execute_command", "execute_admin_command"):
                repeated_failed_command = (decision.arguments.get("command") or "").strip()
                if repeated_failed_command not in self._failed_commands:
                    repeated_failed_command = ""

            if self._tools_this_turn >= self._turn_tool_budget and not repeated_failed_command:
                final = self._bounded_result_summary()
                self.messages.append({"role": "assistant", "content": final})
                yield {"type": "final_answer", "content": final}
                return

            yield {
                "type": "tool_start",
                "name": decision.tool_name,
                "args": decision.arguments,
            }
            current_step = self._match_plan_step(decision.tool_name, decision.arguments)
            if current_step:
                current_step.status = StepStatus.RUNNING

            try:
                # Anti-loop: check if this exact command already failed
                if repeated_failed_command:
                    result = {
                        "error": (
                            f"Cette commande a deja echoue: {repeated_failed_command}. "
                            "Essaie une approche differente."
                        )
                    }
                    if current_step:
                        self.current_plan.mark_failed(current_step.index)
                    yield {
                        "type": "tool_error",
                        "name": decision.tool_name,
                        "error": result["error"],
                        "result": result,
                    }
                    self._record_learning_attempt(
                        decision.tool_name,
                        decision.arguments,
                        result,
                        status="blocked_repeat",
                    )
                    self._append_tool_exchange(
                        decision.tool_name, decision.arguments, result,
                        decision.thought or f"Appel outil: {decision.tool_name}",
                    )
                    continue

                result = self.tool_executor.dispatch(decision.tool_name, decision.arguments)
                self._tools_this_turn += 1
                if current_step:
                    if self._result_succeeded(result):
                        self.current_plan.mark_done(current_step.index)
                    else:
                        self.current_plan.mark_failed(current_step.index)
                yield {"type": "tool_success", "name": decision.tool_name, "result": result}

                # Audit trail: log successful tool call
                if self.audit_logger:
                    self.audit_logger.log_tool_call(
                        decision.tool_name,
                        decision.arguments,
                        result,
                        target=self.active_target.label if self.active_target else "",
                        phase=self.engagement.phase.value,
                        success=True,
                    )

                # Track failed commands for anti-loop + inject retry hints (#9)
                if decision.tool_name in ("execute_command", "execute_admin_command"):
                    cmd = (decision.arguments.get("command") or "").strip()
                    returncode = result.get("returncode", 0) if isinstance(result, dict) else 0
                    if returncode != 0:
                        self._failed_commands.add(cmd)
                        hint = self._build_retry_hint(cmd, result)
                        if hint and isinstance(result, dict):
                            result["retry_hint"] = hint

                parser_tool, new_findings = self._collect_findings_from_result(
                    decision.tool_name,
                    decision.arguments,
                    result,
                )
                for event in self._handle_new_findings(parser_tool, new_findings):
                    yield event
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    result,
                    status="success" if self._result_succeeded(result) else "failed",
                    new_findings=new_findings,
                )
            except MissingTargetError as exc:
                if current_step:
                    self.current_plan.mark_failed(current_step.index)
                message = str(exc)
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    {"error": message},
                    status="missing_target",
                )
                self.messages.append({"role": "assistant", "content": message})
                yield {"type": "final_answer", "content": message}
                return
            except ToolMissingError as exc:
                if current_step:
                    current_step.status = StepStatus.PENDING
                message = (
                    f"{exc} Autorisez-vous son installation ?"
                )
                self.pending_external_tool = {
                    "tool_name": decision.tool_name,
                    "arguments": dict(decision.arguments),
                    "thought": decision.thought or f"Appel outil: {decision.tool_name}",
                    "install_prompt": message,
                }
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    {"error": message},
                    status="tool_missing",
                )
                self.messages.append({"role": "assistant", "content": message})
                yield {
                    "type": "tool_missing",
                    "name": decision.tool_name,
                    "executable": exc.executable,
                    "arguments": decision.arguments,
                    "thought": decision.thought,
                    "message": message,
                }
                yield {"type": "final_answer", "content": message}
                return
            except ToolsMissingError as exc:
                if current_step:
                    current_step.status = StepStatus.PENDING
                label = ", ".join(exc.executables)
                installed_label = ", ".join(exc.installed)
                message = f"Les outils suivants sont requis mais non installes: {label}. Autorisez-vous leur installation ?"
                if installed_label:
                    message = f"Deja installe(s): {installed_label}. " + message
                self.pending_external_tool = {
                    "tool_name": decision.tool_name,
                    "arguments": dict(decision.arguments),
                    "thought": decision.thought or f"Appel outil: {decision.tool_name}",
                    "install_prompt": message,
                }
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    {"error": message},
                    status="tools_missing",
                )
                self.messages.append({"role": "assistant", "content": message})
                yield {
                    "type": "tool_missing",
                    "name": decision.tool_name,
                    "executable": exc.executables[0] if exc.executables else "",
                    "executables": exc.executables,
                    "installed": exc.installed,
                    "arguments": decision.arguments,
                    "thought": decision.thought,
                    "message": message,
                }
                yield {"type": "final_answer", "content": message}
                return
            except PermissionDenied as exc:
                if current_step:
                    current_step.status = StepStatus.PENDING
                result = {"error": f"Permission refusee: {exc}"}
                message = (
                    f"Permission refusee pour {decision.tool_name}. "
                    "Autorisez-vous une nouvelle tentative ?"
                )
                self.pending_external_tool = {
                    "tool_name": decision.tool_name,
                    "arguments": dict(decision.arguments),
                    "thought": decision.thought or f"Appel outil: {decision.tool_name}",
                    "retry_prompt": message,
                }
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    result,
                    status="permission_denied",
                )
                self.messages.append({"role": "assistant", "content": message})
                yield {
                    "type": "tool_denied",
                    "name": decision.tool_name,
                    "arguments": decision.arguments,
                    "thought": decision.thought,
                    "result": result,
                    "message": message,
                }
                yield {"type": "final_answer", "content": message}
                return
            except InteractiveAdminRequired as exc:
                if current_step:
                    current_step.status = StepStatus.PENDING
                message = str(exc)
                self.pending_external_tool = {
                    "tool_name": decision.tool_name,
                    "arguments": dict(decision.arguments),
                    "thought": decision.thought or f"Appel outil: {decision.tool_name}",
                    "admin_prompt": message,
                }
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    {"error": message},
                    status="admin_required",
                )
                self.messages.append({"role": "assistant", "content": message})
                yield {
                    "type": "tool_admin_required",
                    "name": decision.tool_name,
                    "arguments": decision.arguments,
                    "thought": decision.thought,
                    "command": exc.command,
                    "manual_command": exc.manual_command,
                    "message": message,
                }
                yield {"type": "final_answer", "content": message}
                return
            except ToolPolicyError as exc:
                if current_step:
                    self.current_plan.mark_failed(current_step.index)
                result = {
                    "error": str(exc),
                    "remediation": exc.remediation,
                    "policy_code": exc.code,
                }
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    result,
                    status="policy_blocked",
                )
                yield {
                    "type": "tool_policy_blocked",
                    "name": decision.tool_name,
                    "error": str(exc),
                    "remediation": exc.remediation,
                    "policy_code": exc.code,
                    "result": result,
                }
                if self.audit_logger:
                    self.audit_logger.log_tool_call(
                        decision.tool_name,
                        decision.arguments,
                        result,
                        target=self.active_target.label if self.active_target else "",
                        phase=self.engagement.phase.value,
                        success=False,
                    )
            except (ToolExecutionError, OSError, ValueError) as exc:
                if current_step:
                    self.current_plan.mark_failed(current_step.index)
                result = {"error": str(exc)}
                self._record_learning_attempt(
                    decision.tool_name,
                    decision.arguments,
                    result,
                    status="error",
                )
                yield {
                    "type": "tool_error",
                    "name": decision.tool_name,
                    "error": str(exc),
                    "result": result,
                }
                # Audit trail: log tool error
                if self.audit_logger:
                    self.audit_logger.log_tool_call(
                        decision.tool_name,
                        decision.arguments,
                        result,
                        target=self.active_target.label if self.active_target else "",
                        phase=self.engagement.phase.value,
                        success=False,
                    )

            self._append_tool_exchange(
                decision.tool_name,
                decision.arguments,
                result,
                decision.thought or f"Appel outil: {decision.tool_name}",
            )

            # Suggestion #1 + #10: Multi-step continuation with correlation
            if self._tools_this_turn < self.max_iterations - 1:
                structured = self.findings_store.structured_summary()
                suggestions = self._suggest_next_actions()
                if self._tools_this_turn >= self._turn_tool_budget:
                    continuation = self._bounded_final_instruction()
                else:
                    continuation = (
                        "Analyse le resultat ci-dessus. "
                        "Si d'autres actions sont necessaires pour completer l'objectif de l'utilisateur, "
                        "continue avec le prochain outil. Sinon, formule ta reponse finale."
                    )
                if structured:
                    continuation += f"\nFindings actuels: {structured}"
                if suggestions and self._tools_this_turn < self._turn_tool_budget:
                    continuation += f"\nActions suggerees: {suggestions}"
                self.messages.append({"role": "user", "content": continuation})

        timeout_message = (
            "J'arrete ici: nombre maximal d'iterations atteint avant resolution complete."
        )
        self.messages.append({"role": "assistant", "content": timeout_message})
        yield {"type": "final_answer", "content": timeout_message}

    def _append_tool_exchange(self, tool_name, arguments, result, assistant_content):
        self.messages.append(
            {
                "role": "assistant",
                "content": assistant_content,
            }
        )
        # Suggestion #8: Truncate long outputs to preserve LLM context
        compact_result = self._truncate_result(tool_name, result)
        self.messages.append(
            {
                "role": "tool",
                "content": json.dumps(
                    {
                        "name": tool_name,
                        "arguments": arguments,
                        "result": compact_result,
                    },
                    ensure_ascii=False,
                ),
            }
        )

    def _truncate_result(self, tool_name, result):
        """Truncate long command outputs to save LLM context tokens."""
        if not isinstance(result, dict):
            return result
        stdout = result.get("stdout", "")
        if not stdout or len(stdout) <= 2000:
            return result
        # Keep first 1500 chars + findings summary
        truncated = stdout[:1500]
        total_lines = stdout.count("\n") + 1
        shown_lines = truncated.count("\n") + 1
        omitted = total_lines - shown_lines
        truncated += f"\n\n[... {omitted} lignes restantes sur {total_lines} total]"
        # Append extracted findings if any
        structured = self.findings_store.structured_summary()
        if structured:
            truncated += f"\n[Findings extraits: {structured}]"
        compact = dict(result)
        compact["stdout"] = truncated
        return compact

    def _suggest_next_actions(self):
        """Suggestion #10: Correlate findings to suggest next actions."""
        suggestions = []
        used = set(t.lower() for t in self.engagement.tools_used)
        ports = {f.value for f in self.findings_store.ports}
        services = {f.value.lower() for f in self.findings_store.services}
        paths = {f.value.lower() for f in self.findings_store.by_type(FindingType.PATH)}
        creds = self.findings_store.credentials
        vulns = self.findings_store.vulnerabilities

        # Port-based suggestions
        web_ports = ports & {"80", "443", "8080", "8443"}
        if web_ports and "gobuster" not in used:
            suggestions.append("gobuster sur les ports web")
        if web_ports and "nikto" not in used:
            suggestions.append("nikto pour scanner les vulns web")
        if ("445" in ports or "139" in ports) and "enum4linux" not in used:
            suggestions.append("enum4linux pour enumerer SMB")
        if "21" in ports and "ftp" not in used:
            suggestions.append("tester l'acces FTP anonyme")

        # Path-based suggestions
        wp_paths = [p for p in paths if "/wp-" in p or "wordpress" in p]
        if wp_paths and "wpscan" not in used:
            suggestions.append("wpscan pour auditer WordPress")

        # Credential-based suggestions
        if creds and "ssh" not in used and "22" in ports:
            suggestions.append("tester les credentials en SSH")
        if creds and "hydra" not in used and not creds:
            suggestions.append("hydra pour brute-force les credentials")

        # Vulnerability-based suggestions
        if vulns and "searchsploit" not in used:
            suggestions.append("searchsploit pour chercher des exploits")

        return ", ".join(suggestions[:4]) if suggestions else ""

    def _build_retry_hint(self, command, result):
        """Suggestion #9: Suggest alternative approaches when a command fails."""
        stderr = result.get("stderr", "") if isinstance(result, dict) else ""
        executable = command.split()[0] if command else ""
        hints = {
            "nmap": "Essaie avec moins de ports (--top-ports 100) ou sans scripts (-sV seul).",
            "gobuster": "Essaie une wordlist differente (/usr/share/wordlists/dirb/common.txt) ou un mode different (dir, vhost, dns).",
            "nikto": "Essaie avec -Tuning pour limiter les tests ou verifie que le port web est correct.",
            "hydra": "Reduis le nombre de threads (-t 4) ou essaie une wordlist plus petite.",
            "sqlmap": "Essaie avec --level 1 --risk 1 pour un scan plus rapide, ou verifie l'URL.",
            "enum4linux": "Verifie que le port SMB (445) est bien ouvert et accessible.",
            "ffuf": "Essaie avec -mc 200,301,302 pour filtrer les reponses, ou change la wordlist.",
            "wpscan": "Verifie que le site est bien WordPress. Essaie --enumerate u,p pour lister users et plugins.",
            "john": "Verifie le format du hash. Essaie --format=auto ou specifies le format exact.",
            "searchsploit": "Essaie avec des termes plus generiques ou le nom du service sans version.",
        }
        hint = hints.get(executable, "")
        if not hint and "timeout" in stderr.lower():
            hint = "La commande a expire. Essaie avec un scope plus reduit ou un timeout plus long."
        if not hint and "permission" in stderr.lower():
            hint = "Permission refusee. Essaie avec execute_admin_command pour les commandes privilegiees."
        if not hint and "not found" in stderr.lower():
            hint = f"L'outil {executable} n'est pas installe. Utilise install_pentest_tool pour l'installer."
        return hint

    def _build_conversation_summary(self, messages):
        """Build a compact summary of truncated messages for context preservation."""
        parts = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user":
                parts.append(f"- User: {content[:100]}")
            elif role == "tool":
                # Extract just the tool name and status
                try:
                    data = json.loads(content)
                    tool = data.get("name", "?")
                    parts.append(f"- Tool {tool}: execute")
                except (json.JSONDecodeError, TypeError):
                    pass
            elif role == "assistant" and content:
                parts.append(f"- Agent: {content[:80]}")
            elif role == "system":
                # Skip system messages from previous summaries
                continue
        return "\n".join(parts[-15:])  # Keep the 15 most recent summarized exchanges
