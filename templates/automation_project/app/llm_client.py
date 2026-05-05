import json
import re
from dataclasses import dataclass


FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class AgentDecision:
    thought: str
    tool_name: str | None
    arguments: dict
    final_answer: str | None
    raw_text: str


class ToolCallingLLMClient:
    def __init__(
        self,
        prompt_runner,
        *,
        native_decision_runner=None,
        use_native_tools=False,
        max_prompt_chars=18000,
        max_system_chars=9000,
        max_transcript_messages=8,
        max_message_chars=900,
        max_tool_description_chars=150,
        max_argument_description_chars=70,
    ):
        self._prompt_runner = prompt_runner
        self._native_decision_runner = native_decision_runner
        self.use_native_tools = use_native_tools
        self.max_prompt_chars = max_prompt_chars
        self.max_system_chars = max_system_chars
        self.max_transcript_messages = max_transcript_messages
        self.max_message_chars = max_message_chars
        self.max_tool_description_chars = max_tool_description_chars
        self.max_argument_description_chars = max_argument_description_chars
        self.last_prompt_chars = 0
        self.last_tool_count = 0

    def configure_profile(self, profile):
        self.max_prompt_chars = profile.max_prompt_chars
        self.max_system_chars = profile.max_system_chars
        self.max_transcript_messages = profile.max_transcript_messages
        self.max_message_chars = profile.max_message_chars
        self.max_tool_description_chars = profile.max_tool_description_chars
        self.max_argument_description_chars = profile.max_argument_description_chars
        self.use_native_tools = bool(profile.native_tool_calling)

    def decide_next_step(self, messages, system_prompt, tool_specs):
        self.last_tool_count = len(tool_specs or ())
        if self.use_native_tools and self._native_decision_runner and tool_specs:
            try:
                return self._decide_next_step_native(messages, system_prompt, tool_specs)
            except RuntimeError:
                pass
        prompt = self._build_prompt(messages, system_prompt, tool_specs)
        self.last_prompt_chars = len(prompt)
        response_text = self._prompt_runner(prompt)
        return self._parse_decision(response_text)

    def _decide_next_step_native(self, messages, system_prompt, tool_specs):
        compact_system_prompt = self._compact_system_prompt(system_prompt)
        prompt = self._build_native_prompt(messages)
        self.last_prompt_chars = len(compact_system_prompt) + len(prompt)
        result = self._native_decision_runner(prompt, compact_system_prompt, tool_specs)
        self.last_prompt_chars = max(
            self.last_prompt_chars,
            getattr(result, "prompt_chars", 0) or 0,
        )
        tool_name = getattr(result, "tool_name", None)
        if tool_name:
            arguments = getattr(result, "arguments", {}) or {}
            if not isinstance(arguments, dict):
                arguments = {}
            thought = getattr(result, "thought", "") or f"J'utilise {tool_name}."
            return AgentDecision(
                thought=thought,
                tool_name=tool_name,
                arguments=arguments,
                final_answer=None,
                raw_text=getattr(result, "text", "") or "",
            )
        return self._parse_decision(getattr(result, "text", "") or "")

    def _build_native_prompt(self, messages):
        transcript_lines = []
        for message in messages[-self.max_transcript_messages:]:
            role = message.get("role", "assistant")
            content = message.get("content", "")
            content = self._compact_message_content(role, content)
            transcript_lines.append(f"{role.upper()}: {content}")
        instruction = (
            "Choisis la prochaine action SECOPS. "
            "Si un outil est necessaire, appelle une fonction disponible. "
            "Si aucun outil n'est necessaire, reponds en JSON valide: "
            '{"thought":"raisonnement bref","final":"reponse utilisateur"}. '
            "N'appelle qu'un seul outil."
        )
        return self._fit_prompt_budget(
            "\n\n".join(
                [
                    instruction,
                    "TRANSCRIPT RECENT:\n" + "\n".join(transcript_lines),
                ]
            )
        )

    def _build_prompt(self, messages, system_prompt, tool_specs):
        tool_lines = []
        for spec in tool_specs:
            arg_parts = []
            for key, desc in spec.arguments.items():
                compact_desc = self._truncate_text(
                    desc,
                    self.max_argument_description_chars,
                )
                arg_parts.append(f'"{key}": "{compact_desc}"')
            arg_block = "{" + ", ".join(arg_parts) + "}" if arg_parts else "{}"
            compact_description = self._truncate_text(
                spec.description,
                self.max_tool_description_chars,
            )
            tool_lines.append(
                f"- {spec.name}: {compact_description}\n  arguments: {arg_block}"
            )

        transcript_lines = []
        for message in messages[-self.max_transcript_messages:]:
            role = message.get("role", "assistant")
            content = message.get("content", "")
            content = self._compact_message_content(role, content)
            transcript_lines.append(f"{role.upper()}: {content}")

        instruction = (
            "INSTRUCTIONS DE FORMAT:\n"
            "Reponds TOUJOURS en JSON valide. Un seul objet JSON par reponse.\n"
            "Deux formats possibles:\n\n"
            "1. Appel d'outil:\n"
            '   {"thought":"ton raisonnement", "tool":"nom_outil", "arguments":{"cle":"valeur"}}\n\n'
            "2. Reponse finale (quand tu as assez d'info ou pas besoin d'outil):\n"
            '   {"thought":"ton raisonnement", "final":"ta reponse a l\'utilisateur"}\n\n'
            "EXEMPLES:\n"
            'USER: bonjour\n'
            '{"thought":"L\'utilisateur salue, je reponds naturellement.", "final":"Bonjour ! Comment puis-je vous aider en securite offensive ?"}\n\n'
            'USER: install nmap\n'
            '{"thought":"L\'utilisateur veut installer nmap. J\'utilise install_pentest_tool.", "tool":"install_pentest_tool", "arguments":{"tool_name":"nmap"}}\n\n'
            'USER: install nikto hydra dirb\n'
            '{"thought":"L\'utilisateur demande plusieurs outils. J\'utilise une installation groupee.", "tool":"install_pentest_tools", "arguments":{"tool_names":["nikto","hydra","dirb"]}}\n\n'
            'USER: scan 10.10.10.10\n'
            '{"thought":"L\'utilisateur veut scanner une cible. J\'utilise l\'outil de scan standard.", "tool":"scan_target", "arguments":{"target":"10.10.10.10", "mode":"quick"}}\n\n'
            'USER: quels outils sont disponibles ?\n'
            '{"thought":"L\'utilisateur demande les outils.", "tool":"suggest_pentest_tools", "arguments":{"phase":"", "target_type":""}}\n\n'
            "REGLES:\n"
            "- N'appelle qu'un seul outil par tour.\n"
            "- Mets TOUJOURS un champ 'thought' avec ton raisonnement.\n"
            "- Mets TOUJOURS soit 'tool'+'arguments', soit 'final'. Jamais les deux.\n"
            "- N'ecris RIEN en dehors du JSON. Pas de texte avant ou apres."
        )

        prompt = "\n\n".join(
            [
                self._compact_system_prompt(system_prompt),
                "OUTILS DISPONIBLES:\n" + "\n".join(tool_lines),
                instruction,
                "TRANSCRIPT RECENT:\n" + "\n".join(transcript_lines),
            ]
        )
        return self._fit_prompt_budget(prompt)

    @staticmethod
    def _truncate_text(value, limit):
        text = str(value or "").strip()
        if limit <= 0 or len(text) <= limit:
            return text
        return text[: max(0, limit - 18)].rstrip() + " ...[tronque]"

    def _compact_message_content(self, role, content):
        limit = self.max_message_chars
        if role == "tool":
            limit = min(limit, 700)
        return self._truncate_text(content, limit)

    def _compact_system_prompt(self, system_prompt):
        text = str(system_prompt or "").strip()
        if len(text) <= self.max_system_chars:
            return text
        head_limit = max(0, int(self.max_system_chars * 0.65))
        tail_limit = max(0, self.max_system_chars - head_limit - 80)
        return (
            text[:head_limit].rstrip()
            + "\n\n[... contexte systeme intermediaire tronque pour economiser les tokens ...]\n\n"
            + text[-tail_limit:].lstrip()
        )

    def _fit_prompt_budget(self, prompt):
        if len(prompt) <= self.max_prompt_chars:
            return prompt
        head_limit = max(0, int(self.max_prompt_chars * 0.55))
        tail_limit = max(0, self.max_prompt_chars - head_limit - 70)
        return (
            prompt[:head_limit].rstrip()
            + "\n\n[... prompt tronque pour economiser les tokens ...]\n\n"
            + prompt[-tail_limit:].lstrip()
        )

    def _parse_decision(self, response_text):
        payload = self._extract_payload(response_text)
        if not payload:
            return AgentDecision(
                thought="",
                tool_name=None,
                arguments={},
                final_answer=response_text.strip(),
                raw_text=response_text,
            )

        thought = str(payload.get("thought", "")).strip()
        tool_name = payload.get("tool")
        if tool_name is None and isinstance(payload.get("name"), str):
            tool_name = payload.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            tool_name = None

        arguments = payload.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        # Accept multiple aliases for the final answer key
        final_answer = None
        for key in ("final", "answer", "response", "reply"):
            candidate = payload.get(key)
            if isinstance(candidate, str) and candidate.strip():
                final_answer = candidate.strip()
                break

        if not tool_name and not final_answer:
            final_answer = thought if thought else response_text.strip()

        return AgentDecision(
            thought=thought,
            tool_name=tool_name,
            arguments=arguments,
            final_answer=final_answer,
            raw_text=response_text,
        )

    def _extract_payload(self, response_text):
        candidates = []

        # 1. Fenced JSON blocks (```json ... ```)
        fenced = FENCED_JSON_RE.search(response_text)
        if fenced:
            candidates.append(fenced.group(1).strip())

        stripped = response_text.strip()

        # 2. Entire response is JSON
        if stripped.startswith("{") and stripped.endswith("}"):
            candidates.append(stripped)

        # 3. Extract JSON using bracket counting (handles nested braces)
        depth = 0
        json_start = None
        for i, char in enumerate(stripped):
            if char == "{":
                if depth == 0:
                    json_start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0 and json_start is not None:
                    candidates.append(stripped[json_start : i + 1])
                    break

        # 4. Fallback: first { to last }
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end != -1 and end > start:
            fallback = stripped[start : end + 1]
            if fallback not in candidates:
                candidates.append(fallback)

        # Parse all candidates and prefer ones with 'thought' or 'tool' or 'final'
        parsed = []
        for candidate in candidates:
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                parsed.append(payload)

        if not parsed:
            return None

        # Score candidates: prefer structured ones with expected keys
        def _score(payload):
            score = 0
            if "thought" in payload:
                score += 3
            if "tool" in payload or "name" in payload:
                score += 2
            if "final" in payload or "answer" in payload or "response" in payload:
                score += 2
            return score

        parsed.sort(key=_score, reverse=True)
        return parsed[0]
