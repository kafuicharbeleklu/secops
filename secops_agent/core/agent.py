"""
Main Agent orchestrator for the SecOps Agent.
Handles the agentic loop with streaming events, tool execution,
dangerous tool approval, token tracking, and retry logic.
"""

from __future__ import annotations

import uuid
import asyncio
import datetime
import logging
import platform
import re
import shlex
import socket
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, List, Dict, Any, Union, Optional

logger = logging.getLogger(__name__)

_DEFAULT_TOOL_IDLE_PROGRESS_INTERVAL = 3.0

from secops_agent.core.llm import LLMProvider, Message, StreamChunk, ToolCallChunk
from secops_agent.core.tools import ToolProgress, ToolRegistry, ToolResult, ToolRiskClass
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.experience import build_lesson_from_tool_result, build_suggestion_signal
from secops_agent.core.hooks import HookManager
from secops_agent.core.observability import StructuredTracer, TraceSink, trace_sink_from_settings
from secops_agent.core.mission import ActionTraceEntry
from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
from secops_agent.core.planner import MissionPlanner, NextAction
from secops_agent.core.request_context import (
    RequestDecision,
    TechnicalGoal,
    ToolSchemaSelector,
    UserIntent,
    classify_request,
)
from secops_agent.core.sandbox import validate_shell_command
from secops_agent.core.sudo import (
    SudoAuthenticationDecision,
    can_prompt_for_sudo,
    command_uses_sudo,
    sudo_noninteractive_status,
)
from secops_agent.core.permissions import (
    ApprovalDecision,
    ApprovalScope,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.scope_guard import ScopeGuard
from secops_agent.core.preflight import PreflightRouter

# Optional imports for Phase 2 features (structured memory & parsing)
try:
    from secops_agent.core.structured_memory import StructuredMemory
    from secops_agent.core.result_parser import ToolResultParser
except ImportError:  # pragma: no cover – graceful degradation
    StructuredMemory = None  # type: ignore[assignment,misc]
    ToolResultParser = None  # type: ignore[assignment,misc]


# ── Agent Events ──────────────────────────────────────────────────────

class AgentRetryException(Exception):
    """Raised when model generation needs to be retried."""
    pass


class ForcedExecutionException(Exception):
    """Raised when an archived tool call needs to be forced to execute."""
    def __init__(self, tool_name: str, arguments: dict):
        super().__init__(f"Force execute {tool_name}")
        self.tool_name = tool_name
        self.arguments = arguments


@dataclass
class ArchivedToolCallEvent:
    tool_name: str
    arguments: dict
    raw_text: str


@dataclass
class APIErrorEvent:
    status_code: str
    error_message: str
    attempt: int
    max_attempts: int
    delay: float
    is_quota: bool
    choice_future: asyncio.Future[str]


@dataclass
class ThinkingEvent:
    content: str


@dataclass
class TextEvent:
    content: str
    done: bool = False


@dataclass
class ToolCallEvent:
    name: str
    arguments: dict
    id: str
    dangerous: bool = False
    permission: str = ""


@dataclass
class ToolResultEvent:
    name: str
    result: ToolResult
    id: str


@dataclass
class SuggestedActionsEvent:
    actions: list[NextAction]


@dataclass
class ToolStartEvent:
    name: str
    arguments: dict
    id: str


@dataclass
class ToolProgressEvent:
    name: str
    id: str
    phase: str
    detail: str = ""
    percent: Optional[float] = None


@dataclass
class ErrorEvent:
    error: str


@dataclass
class StatusEvent:
    message: str


@dataclass
class ApprovalRequestEvent:
    """Emitted when a tool, command, or resource needs user approval."""
    tool_name: str
    arguments: dict
    resource: PermissionResource
    approval_future: asyncio.Future


@dataclass
class SudoAuthenticationRequestEvent:
    """Emitted when a sudo command needs local interactive authentication."""
    command: str
    reason: str
    authentication_future: asyncio.Future


@dataclass
class TokenUsageEvent:
    """Emitted after receiving a complete LLM response."""
    input_tokens: int
    output_tokens: int


AgentEvent = Union[
    ThinkingEvent,
    TextEvent,
    ToolCallEvent,
    ToolStartEvent,
    ToolProgressEvent,
    ToolResultEvent,
    SuggestedActionsEvent,
    ErrorEvent,
    StatusEvent,
    ApprovalRequestEvent,
    SudoAuthenticationRequestEvent,
    TokenUsageEvent,
]


# Intents broad enough to warrant LLM-driven multi-step chaining (RC2). A
# specific single-tool request (RUN_SINGLE_TOOL) or a plan request
# (PROPOSE_PLAN) is answered in one step and then offers suggestions; focused
# questions and greetings never reach here (they suppress follow-ups).
_CHAINING_INTENTS = frozenset({UserIntent.UNKNOWN, UserIntent.APPROVED_BATCH})

# RC-α: the generic parser collapses long output to "<lead>  (+N more line(s))"
# (core/result_parsers/system.py). That trailer is a display hint for the Ctrl+O
# collapsed view — it must never surface in the user-facing answer channel.
_COLLAPSE_TRAILER_RE = re.compile(r"\s*\(\+\d+\s+more line\(s\)\)\s*$")


def _strip_collapse_trailer(text: Any) -> str:
    """Drop the parser's collapsed-preview trailer from an answer string."""
    return _COLLAPSE_TRAILER_RE.sub("", str(text or "")).strip()


# ── Agent ─────────────────────────────────────────────────────────────

class SecOpsAgent:
    def __init__(
        self,
        llm: LLMProvider,
        registry: ToolRegistry,
        memory: ConversationMemory,
        permissions: PermissionEngine | None = None,
        hooks: HookManager | None = None,
        max_iterations: int = 14,
        structured_memory: Any | None = None,
        result_parser: Any | None = None,
        planner: MissionPlanner | None = None,
        experience_store: Any | None = None,
        max_chained_actions_per_turn: int = 0,
        allow_automatic_planner_execution: bool = False,
        autonomy: AutonomyPolicy | None = None,
        approval_timeout: float = 600.0,
        tool_idle_progress_interval: float = _DEFAULT_TOOL_IDLE_PROGRESS_INTERVAL,
        trace_sink: TraceSink | None = None,
        llm_max_attempts: int = 3,
        llm_retry_base_seconds: float = 2.0,
        llm_retry_max_seconds: float = 8.0,
    ):
        self.llm = llm
        self.registry = registry
        self.memory = memory
        self.permissions = permissions or PermissionEngine()
        self.hooks = hooks or HookManager()
        self.max_iterations = max_iterations
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self._turn_count = 0
        # Phase 2: structured memory and result parser (optional)
        self.structured_memory = structured_memory  # StructuredMemory instance
        self.result_parser = result_parser  # ToolResultParser instance
        self.planner = planner or MissionPlanner()
        self.experience_store = experience_store
        self.max_chained_actions_per_turn = max(0, max_chained_actions_per_turn)
        self.allow_automatic_planner_execution = bool(allow_automatic_planner_execution)
        # Semi-autonomous-by-risk by default (see docs/ARCHITECTURE.md §7).
        # When no policy is injected, autonomy adapts per turn to the detected
        # environment (trusted lab/CTF -> supervised); an explicit policy is
        # respected as-is.
        self.autonomy = autonomy or AutonomyPolicy()
        self._autonomy_explicit = autonomy is not None
        self.approval_timeout = approval_timeout
        self.tracer = StructuredTracer(trace_sink or trace_sink_from_settings())
        self.llm_max_attempts = max(1, int(llm_max_attempts or 1))
        self.llm_retry_base_seconds = max(0.0, float(llm_retry_base_seconds))
        self.llm_retry_max_seconds = max(0.0, float(llm_retry_max_seconds))
        try:
            self.tool_idle_progress_interval = max(0.01, float(tool_idle_progress_interval))
        except (TypeError, ValueError):
            self.tool_idle_progress_interval = _DEFAULT_TOOL_IDLE_PROGRESS_INTERVAL
        self._attempted_action_keys: set[str] = set()
        self._last_suggested_actions: list[NextAction] = []
        self._last_suggestion_batch_id = ""
        self._suggestion_actions_by_call_id: dict[str, tuple[NextAction, int, str]] = {}
        self._tool_call_sources: dict[str, str] = {}
        self._active_guided_task_text = ""
        self.tool_schema_selector = ToolSchemaSelector()
        self._preflight = PreflightRouter(
            registry=self.registry,
            structured_memory=self.structured_memory,
            last_suggested_actions=self._last_suggested_actions,
            suggestion_actions_by_call_id=self._suggestion_actions_by_call_id,
            attempted_action_keys=self._attempted_action_keys,
            last_suggestion_batch_id=self._last_suggestion_batch_id,
            record_suggestion_selection_fn=self._record_suggestion_selection,
            single_download_vpn_config_fn=lambda: self._single_download_vpn_config(),
        )

    @staticmethod
    def _plain_text(text: str) -> str:
        normalized = unicodedata.normalize("NFKD", text or "")
        return "".join(ch for ch in normalized if not unicodedata.combining(ch)).casefold()

    # First-person "about to act now" cues (FR/EN), accent-stripped/casefolded.
    _ACTION_ANNOUNCEMENT_CUES = (
        "je vais ",
        "je lance",
        "je commence par",
        "je procede",
        "laisse-moi",
        "laissez-moi",
        "on va lancer",
        "let me ",
        "i'll ",
        "i will ",
        "i am going to",
        "i'm going to",
        "going to run",
    )

    @staticmethod
    def _announces_unexecuted_action(text: str) -> bool:
        """Heuristic: text announces a tool action but no tool call was made.

        Conservative — used only to grant one corrective iteration when tools
        were available, so a rare false positive costs at most one extra pass.
        """
        plain = SecOpsAgent._plain_text(text).replace("’", "'")
        if not plain:
            return False
        return any(cue in plain for cue in SecOpsAgent._ACTION_ANNOUNCEMENT_CUES)

    # Directory names that signal an attack surface vs. static noise, used to
    # prioritise gobuster candidates like an analyst instead of just listing them.
    _DIR_HIGH_VALUE = (
        "admin", "panel", "upload", "dashboard", "login", "manage", "cms",
        "dev", "backup", "config", "phpmyadmin", "wp-admin", "api", "secret",
        "private", "portal", "console", "internal", "test",
    )
    _DIR_NOISE = (
        "css", "js", "javascript", "image", "img", "font", "asset",
        "static", "icon", "style", "vendor", "node_modules",
    )

    @staticmethod
    def _dir_candidate_score(path: str) -> int:
        """Rank a discovered web path: 2 = likely attack surface, 0 = static noise."""
        p = str(path or "").strip().strip("/").casefold()
        if any(marker in p for marker in SecOpsAgent._DIR_HIGH_VALUE):
            return 2
        if any(marker in p for marker in SecOpsAgent._DIR_NOISE):
            return 0
        return 1

    @staticmethod
    def _strip_mission_state_sections(text: str) -> str:
        """Remove noisy mission summaries from focused answer turns."""
        lines = str(text or "").splitlines()
        kept: list[str] = []
        for line in lines:
            normalized = SecOpsAgent._plain_text(line).strip(" #:")
            if normalized == "mission state":
                break
            kept.append(line)
        return "\n".join(kept).rstrip()

    @staticmethod
    def _strip_archived_tool_markers(text: str) -> tuple[str, bool]:
        """Remove prior-history tool markers before they reach the transcript."""
        raw = str(text or "")
        pattern = re.compile(r"\[Archived tool (?:call|result):[^\]]+\]")
        cleaned, count = pattern.subn("", raw)
        cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned, count > 0

    @property
    def turn_count(self) -> int:
        return self._turn_count

    def _trace(self, event_type: str, **fields: Any) -> None:
        self.tracer.emit(event_type, **fields)

    def _llm_backoff_delay(self, attempt: int) -> float:
        delay = self.llm_retry_base_seconds * (2 ** max(0, attempt - 1))
        if self.llm_retry_max_seconds:
            delay = min(delay, self.llm_retry_max_seconds)
        return delay

    @staticmethod
    def _is_retriable_llm_error(error: Exception | str) -> bool:
        text = " ".join(str(error or "").split()).casefold()
        if not text:
            return True
        non_retriable = (
            "invalid_argument",
            "api key",
            "authentication",
            "permission denied",
            "quota reached",
            "individual quota",
            "not found",
        )
        if any(marker in text for marker in non_retriable):
            return False
        retriable = (
            "429",
            "500",
            "502",
            "503",
            "504",
            "capacity",
            "deadline",
            "high traffic",
            "internal",  # Gemini "500 INTERNAL" is transient — retry with backoff
            "rate limit",
            "resource_exhausted",
            "temporarily unavailable",
            "temporary failure",
            "timeout",
            "timed out",
            "unavailable",
        )
        return any(marker in text for marker in retriable)

    async def _sleep_before_llm_retry(self, delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(delay)

    async def _stream_llm_with_retries(
        self,
        *,
        tools_schema: list[dict[str, Any]],
        turn_id: str,
    ) -> AsyncIterator[StreamChunk | StatusEvent | ErrorEvent]:
        messages = self.memory.get_messages()
        for attempt in range(1, self.llm_max_attempts + 1):
            should_retry = False
            self._trace(
                "llm_request_started",
                turn_id=turn_id,
                attempt=attempt,
                max_attempts=self.llm_max_attempts,
                model=getattr(self.llm, "model_name", ""),
                messages=len(messages),
                tools=len(tools_schema),
            )
            try:
                async for chunk in self.llm.stream_chat(
                    messages=messages,
                    tools_schema=tools_schema,
                ):
                    if chunk.error:
                        retriable = self._is_retriable_llm_error(chunk.error)
                        self._trace(
                            "llm_request_error",
                            turn_id=turn_id,
                            attempt=attempt,
                            retriable=retriable,
                            error=chunk.error,
                        )
                        if retriable and attempt < self.llm_max_attempts:
                            delay = self._llm_backoff_delay(attempt)
                            self._trace(
                                "llm_retry_scheduled",
                                turn_id=turn_id,
                                attempt=attempt,
                                next_attempt=attempt + 1,
                                delay_seconds=delay,
                            )
                            yield StatusEvent(
                                f"LLM error, retrying in {delay:g}s... ({chunk.error[:80]})"
                            )
                            await self._sleep_before_llm_retry(delay)
                            should_retry = True
                            break
                        yield ErrorEvent(chunk.error)
                        return
                    yield chunk
                if should_retry:
                    continue
                self._trace("llm_request_completed", turn_id=turn_id, attempt=attempt)
                return
            except Exception as exc:
                retriable = self._is_retriable_llm_error(exc)
                self._trace(
                    "llm_request_exception",
                    turn_id=turn_id,
                    attempt=attempt,
                    retriable=retriable,
                    error=str(exc),
                )
                if retriable and attempt < self.llm_max_attempts:
                    delay = self._llm_backoff_delay(attempt)
                    self._trace(
                        "llm_retry_scheduled",
                        turn_id=turn_id,
                        attempt=attempt,
                        next_attempt=attempt + 1,
                        delay_seconds=delay,
                    )
                    yield StatusEvent(f"LLM error, retrying in {delay:g}s... ({str(exc)[:80]})")
                    await self._sleep_before_llm_retry(delay)
                    continue
                yield ErrorEvent(f"LLM failed after {attempt} attempt(s): {str(exc)}")
                return

    @staticmethod
    def _coerce_approval(value: ApprovalDecision | bool) -> ApprovalDecision:
        if isinstance(value, bool):
            return ApprovalDecision(allowed=value)
        return value

    def _remember_approval(self, resource: PermissionResource, approval: ApprovalDecision) -> None:
        decision = PermissionDecision.ALLOW if approval.allowed else PermissionDecision.DENY
        if approval.scope == ApprovalScope.SESSION:
            self.permissions.remember(resource, decision)
        elif approval.scope == ApprovalScope.PERSISTENT:
            self.permissions.remember_persistent(resource, decision)

    @staticmethod
    def _approval_denied_error(resource: PermissionResource, approval: ApprovalDecision) -> str:
        if approval.interrupted:
            return "Interrupted · What should SecOps CLI do instead?"
        if resource.kind in {"command_exact", "command_prefix"}:
            return f"Permission denied by user: command({resource.name})"
        return f"Permission denied by user: {resource.value}"

    def _update_recorded_tool_arguments(self, tool_call_id: str, arguments: dict) -> None:
        for message in reversed(self.memory.messages):
            if message.role != "model":
                continue
            for tool_call in message.tool_calls:
                if tool_call.get("id") == tool_call_id:
                    tool_call["arguments"] = dict(arguments)
                    return

    def _record_tool_call(self, tool_call: ToolCallChunk) -> None:
        serialized = {
            "name": tool_call.name,
            "arguments": dict(tool_call.arguments),
            "id": tool_call.id,
        }
        for message in reversed(self.memory.messages):
            if message.role == "model":
                message.tool_calls.append(serialized)
                return
        self.memory.add_assistant_message("", tool_calls=[serialized])

    @staticmethod
    def _tool_action_key(tool_name: str, arguments: dict[str, Any]) -> str:
        return NextAction(
            title=tool_name,
            rationale="tool call",
            tool_name=tool_name,
            arguments=dict(arguments),
        ).key

    def _remember_attempted_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> None:
        self._attempted_action_keys.add(self._tool_action_key(tool_name, arguments))

    def _record_experience_lesson(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult,
        parsed: Any | None = None,
    ) -> None:
        if self.experience_store is None:
            return
        mission = (
            getattr(self.structured_memory, "mission", None)
            if self.structured_memory
            else None
        )
        lesson = build_lesson_from_tool_result(
            tool_name,
            arguments,
            result,
            mission=mission,
            parsed=parsed,
            session_name=str(getattr(mission, "id", "") or ""),
        )
        if lesson is None:
            return
        try:
            if hasattr(self.experience_store, "append_unique"):
                self.experience_store.append_unique(lesson)
            else:
                self.experience_store.append(lesson)
            if hasattr(self.planner, "lessons"):
                self.planner.lessons.append(lesson)
        except OSError:
            return

    def _mission_session_name(self) -> str:
        mission = (
            getattr(self.structured_memory, "mission", None)
            if self.structured_memory
            else None
        )
        return str(getattr(mission, "id", "") or "")

    def _mission(self) -> Any | None:
        return (
            getattr(self.structured_memory, "mission", None)
            if self.structured_memory
            else None
        )

    def _start_action_trace(
        self,
        *,
        turn_id: str,
        user_input: str,
        tool_call: ToolCallChunk,
        tool_def: Any | None,
    ) -> ActionTraceEntry | None:
        mission = self._mission()
        if not mission or not hasattr(mission, "add_action_trace"):
            return None
        phase = getattr(mission, "phase", "")
        phase_value = phase.value if hasattr(phase, "value") else str(phase or "")
        risk_class = getattr(tool_def, "risk_class", "")
        entry = ActionTraceEntry(
            turn_id=turn_id,
            source=self._tool_call_sources.pop(tool_call.id, "llm"),
            phase=phase_value,
            tool_name=tool_call.name,
            arguments=dict(tool_call.arguments or {}),
            risk_class=str(getattr(risk_class, "value", "") or risk_class or ""),
            user_intent=str(user_input or "")[:500],
        )
        mission.add_action_trace(entry)
        return entry

    @staticmethod
    def _finish_action_trace(
        entry: ActionTraceEntry | None,
        *,
        status: str,
        result: ToolResult | None = None,
        parsed_result: Any | None = None,
        state_changes: list[str] | None = None,
        suggested_actions: list[NextAction] | None = None,
        error: str = "",
    ) -> None:
        if entry is None:
            return
        entry.status = status
        entry.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if result is not None:
            entry.execution_time = float(getattr(result, "execution_time", 0.0) or 0.0)
            if result.error:
                entry.error = str(result.error)[:1000]
        if error:
            entry.error = str(error)[:1000]

        summary = str(getattr(parsed_result, "summary", "") or "").strip()
        if summary:
            entry.result_summary = summary[:1000]
        elif result is not None and result.success:
            entry.result_summary = (
                f"Tool completed successfully ({len(result.output or '')} output chars)."
            )
        elif entry.error and not entry.result_summary:
            entry.result_summary = "Tool did not complete successfully."

        if state_changes:
            entry.state_changes = [str(change)[:500] for change in state_changes[:20]]
        if suggested_actions:
            entry.suggested_actions = [
                action.to_dict()
                for action in suggested_actions[:10]
            ]

    def _record_suggestion_signal(
        self,
        action: NextAction,
        *,
        outcome: str,
        rank: int = 0,
        reason: str = "",
        batch_id: str = "",
    ) -> None:
        if self.experience_store is None or not hasattr(self.experience_store, "append_signal"):
            return
        signal = build_suggestion_signal(
            action,
            outcome=outcome,
            session_name=self._mission_session_name(),
            batch_id=batch_id or self._last_suggestion_batch_id,
            rank=rank,
            reason=reason,
            **self._suggestion_audit_context(action),
        )
        try:
            self.experience_store.append_signal(signal)
            if hasattr(self.planner, "suggestion_signals"):
                self.planner.suggestion_signals.append(signal)
        except OSError:
            return

    def _suggestion_audit_context(self, action: NextAction) -> dict[str, Any]:
        if not self.planner or not hasattr(self.planner, "learning_audit"):
            return {}
        try:
            audit = self.planner.learning_audit()
        except Exception:
            return {}
        matches = [
            entry for entry in audit
            if entry.get("action_key") == action.key
        ]
        if not matches:
            return {}
        preferred = next(
            (
                entry for entry in matches
                if entry.get("source_type") == "playbook"
                or entry.get("status") == "rejected"
            ),
            matches[0],
        )
        return {
            "audit_status": str(preferred.get("status") or ""),
            "audit_reasons": list(preferred.get("reasons") or []),
        }

    def _record_suggestion_batch(self, actions: list[NextAction]) -> None:
        if not actions:
            return
        self._last_suggestion_batch_id = uuid.uuid4().hex[:12]
        for rank, action in enumerate(actions, start=1):
            self._record_suggestion_signal(
                action,
                outcome="suggested",
                rank=rank,
                batch_id=self._last_suggestion_batch_id,
            )

    def _record_suggestion_selection(self, selected_indices: set[int]) -> None:
        if not selected_indices or not self._last_suggested_actions:
            return
        for index, action in enumerate(self._last_suggested_actions):
            outcome = "selected" if index in selected_indices else "ignored"
            reason = "user selected suggestion" if outcome == "selected" else "not selected in this batch"
            self._record_suggestion_signal(
                action,
                outcome=outcome,
                rank=index + 1,
                reason=reason,
                batch_id=self._last_suggestion_batch_id,
            )

    def _record_suggestion_execution_outcome(self, call_id: str, result: ToolResult) -> None:
        tracked = self._suggestion_actions_by_call_id.pop(str(call_id or ""), None)
        if not tracked:
            return
        action, rank, batch_id = tracked
        self._record_suggestion_signal(
            action,
            outcome="succeeded" if result.success else "failed",
            rank=rank,
            reason=result.error or "",
            batch_id=batch_id,
        )

    def _request_decision(self, user_input: str) -> RequestDecision:
        mission = (
            getattr(self.structured_memory, "mission", None)
            if self.structured_memory
            else None
        )
        return classify_request(user_input, mission=mission)

    # Risk classes safe to expose as a baseline floor under every goal. The
    # genuinely dangerous primitives — privileged local actions (run_shell, vpn
    # connect/disconnect) and offensive payload/exploit assistance — are
    # deliberately excluded and remain behind the AutonomyPolicy gate +
    # PermissionEngine approval.
    _SAFE_BASELINE_RISK_CLASSES = frozenset(
        {
            ToolRiskClass.PURE_LOCAL_COMPUTATION,
            ToolRiskClass.LOCAL_OBSERVATION,
            ToolRiskClass.NETWORK_OBSERVATION,
            ToolRiskClass.ACTIVE_ENUMERATION,
            ToolRiskClass.LOCAL_FILE_ACCESS,
        }
    )

    def _safe_baseline_tool_names(self) -> list[str]:
        """Broad set of safe tools exposed under every goal (RC1).

        Derived from the live registry by risk class so newly registered safe
        tools are picked up automatically. Lets the classifier *rank* rather
        than *gate*: the model always sees a usable toolset and chooses; the
        PermissionEngine remains the execution gate.
        """
        cached = getattr(self, "_safe_baseline_cache", None)
        if cached is None:
            cached = [
                t.name
                for t in self.registry.list_tools()
                if getattr(t, "risk_class", None) in self._SAFE_BASELINE_RISK_CLASSES
            ]
            self._safe_baseline_cache = cached
        return cached

    def _autonomy_for_turn(self, decision: RequestDecision) -> AutonomyPolicy:
        """Effective policy for this turn.

        An explicitly injected policy is used as-is; otherwise autonomy adapts
        to the detected environment so a trusted lab/CTF escalates to supervised
        (low-risk runs freely; exploitation pauses until approved, then chains).
        """
        if self._autonomy_explicit:
            return self.autonomy
        return AutonomyPolicy.for_environment(decision.environment_hint)

    def set_autonomy_for_permission_mode(self, mode: str) -> None:
        """Align autonomy with the active permission mode.

        Free-execution modes (``always-proceed`` / ``proceed-in-sandbox``) imply
        an authorised target, so escalate to SANDBOX autonomy — which exposes
        high-risk tool *schemas* to the model. Execution stays gated by the
        PermissionEngine. Other modes restore adaptive, environment-based
        autonomy so a trusted lab/CTF still escalates on its own.
        """
        if mode in {"always-proceed", "proceed-in-sandbox"}:
            self.autonomy = AutonomyPolicy(level=AutonomyLevel.SANDBOX)
            self._autonomy_explicit = True
        else:
            self.autonomy = AutonomyPolicy()
            self._autonomy_explicit = False

    def _relevant_lessons_briefing(self, mission: Any) -> str:
        """Prime the model with relevant prior lessons (memory briefing, §5).

        Silent mission-context injection (not a user-facing block), gated to
        lessons that actually match the current mission so it adds nothing when
        none apply. The set of matches naturally enriches as the mission accrues
        evidence across turns.
        """
        store = self.experience_store
        if mission is None or store is None or not hasattr(store, "retrieve"):
            return ""
        try:
            scored = store.retrieve(mission, limit=3)
        except Exception:
            logger.debug("Lesson retrieval for briefing failed", exc_info=True)
            return ""
        if not scored:
            return ""
        lines = ["## Relevant Prior Lessons (hints from past authorized engagements)"]
        for lesson, _score in scored:
            tool = str(getattr(lesson, "action_tool_name", "") or "").strip()
            suffix = f" [{tool}]" if tool else ""
            lines.append(f"- {lesson.reason()}{suffix}")
        lines.append("Treat these as hints only; verify against current evidence.")
        return "\n".join(lines)

    def _tools_schema_for_decision(self, decision: RequestDecision) -> list[dict[str, Any]]:
        # AutonomyPolicy (§7): withhold exploitation/destructive tool schemas
        # until the user has approved a plan. The PermissionEngine still gates
        # any exposed tool at execution time.
        if not self._autonomy_for_turn(decision).exposes_tool_schemas(decision):
            # §7 withholds the high-risk schemas until a plan is approved, but we
            # must never blind the model: expose the safe baseline floor so it can
            # keep working (recon/enum) instead of receiving an empty toolset —
            # which previously let Google Search grounding hijack the turn and made
            # the agent report it "only has google:search".
            return self.registry.get_tools_schema(self._safe_baseline_tool_names())
        selection = self.tool_schema_selector.select(decision)
        # Goal-specific tools rank first, then the safe baseline as a floor so a
        # vague request ("scan", "check this host") still exposes a usable
        # toolset instead of an empty schema.
        names: list[str] = list(selection.tool_names)
        seen = set(names)
        for name in self._safe_baseline_tool_names():
            if name not in seen:
                names.append(name)
                seen.add(name)
        return self.registry.get_tools_schema(names)

    @staticmethod
    def _prefers_french(user_input: str) -> bool:
        text = SecOpsAgent._plain_text(user_input)
        return any(
            marker in text
            for marker in (
                "quelle",
                "quel ",
                "quels ",
                "quelles ",
                "mon systeme",
                "mon système",
                "adresse ip",
                "c'est quoi",
                "explique",
            )
        )

    @staticmethod
    def _transient_llm_notice(user_input: str) -> str:
        """Clean user-facing message when a transient LLM error leaves a turn
        with no tool result to present (RC-γ / D5). The turn must never end
        empty; degrade to a clear, actionable notice instead."""
        if SecOpsAgent._prefers_french(user_input):
            return (
                "Le service de modèle est momentanément indisponible "
                "(erreur transitoire). Merci de réessayer dans un instant."
            )
        return (
            "The model service is momentarily unavailable (transient error). "
            "Please try again in a moment."
        )

    @staticmethod
    def _os_release_pretty_name() -> str:
        path = Path("/etc/os-release")
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return platform.platform()

    @staticmethod
    def _local_ip_addresses() -> list[str]:
        addresses: list[str] = []
        try:
            completed = subprocess.run(
                ["hostname", "-I"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            for item in completed.stdout.split():
                if item and item not in addresses:
                    addresses.append(item)
        except (OSError, subprocess.SubprocessError):
            pass

        if not addresses:
            try:
                hostname = socket.gethostname()
                for item in socket.gethostbyname_ex(hostname)[2]:
                    if item and not item.startswith("127.") and item not in addresses:
                        addresses.append(item)
            except OSError:
                pass
        return addresses

    def _local_preflight_answer(self, user_input: str, decision: RequestDecision) -> str:
        """Return an instant text answer for LOCAL_SYSTEM queries, or empty string."""
        return self._preflight.local_answer(user_input, decision)

    def _guided_lab_restraint_turn(self, user_input: str) -> bool:
        """Detect narrow answer turns that should not add follow-up proposals."""
        return self._request_decision(user_input).should_suppress_followups

    @staticmethod
    def _looks_like_guided_multistep_task(user_input: str) -> bool:
        text = SecOpsAgent._plain_text(user_input)
        if "answer the questions below" in text:
            return True
        if any(marker in text for marker in ("user.txt", "root.txt")):
            return True
        question_markers = (
            "how many ports",
            "what version",
            "what service",
            "hidden directory",
            "find directories",
            "reverse shell",
            "suid",
        )
        return sum(1 for marker in question_markers if marker in text) >= 3

    @staticmethod
    def _guided_continue_intent(user_input: str) -> bool:
        text = SecOpsAgent._plain_text(user_input).strip(" ?!.")
        if re.fullmatch(r"(?:et\s+)?(?:la\s+)?suite", text):
            return True
        if re.fullmatch(r"(?:continue|continuer|poursuis|poursuivre|vas y|go on|proceed|next)", text):
            return True
        return (
            "tant que" in text
            and any(marker in text for marker in ("question", "repondu", "répondu", "fini", "termine", "terminé"))
        )

    def _guided_task_preflight_tool_calls(self, user_input: str) -> list[ToolCallChunk]:
        if not self._active_guided_task_text or not self._guided_continue_intent(user_input):
            return []

        task_text = self._plain_text(self._active_guided_task_text)
        wants_dir_enum = any(
            marker in task_text
            for marker in ("gobuster", "go buster", "hidden directory", "find directories", "directory")
        )
        if not wants_dir_enum or not self.registry.get_tool("dir_brute"):
            return []

        self._preflight._structured_memory = self.structured_memory
        url = self._preflight._known_web_url(self._active_guided_task_text)
        if not url:
            return []

        arguments = {"url": url}
        if self._tool_action_key("dir_brute", arguments) in self._attempted_action_keys:
            return []

        return [
            ToolCallChunk(
                name="dir_brute",
                arguments=arguments,
                id=f"dir_brute_{uuid.uuid4().hex[:8]}",
            )
        ]

    def _format_tool_answer_summary(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        parsed_result: Any | None,
    ) -> str:
        if parsed_result is None:
            return ""

        if tool_name == "vpn_status":
            raw = str(getattr(parsed_result, "raw_output", "") or "")
            status = ""
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("vpn status:"):
                    status = stripped.split(":", 1)[1].strip().lower()
                    break
            detail = {
                "connected": "tunnel TUN actif et utilisable",
                "down/stale": "interface TUN présente mais DOWN/NO-CARRIER, "
                "un processus OpenVPN subsiste",
                "disconnected": "aucune interface tun active ni processus OpenVPN",
                "starting/stale": "OpenVPN démarre, pas encore d'interface TUN active",
            }.get(status)
            if status == "connected":
                head = "Oui, un VPN est actif"
            elif status:
                head = "Non, aucun VPN actif"
            else:
                return _strip_collapse_trailer(getattr(parsed_result, "summary", ""))
            return f"{head} ({detail})." if detail else f"{head}."

        if tool_name == "lab_setup_check":
            raw = str(getattr(parsed_result, "raw_output", "") or "")
            present: list[str] = []
            missing: list[str] = []
            in_tools = False
            for line in raw.splitlines():
                if line.strip() == "Tools:":
                    in_tools = True
                    continue
                if not in_tools:
                    continue
                if not line.startswith("  "):  # blank line / next section ends the block
                    break
                name, sep, state = line.strip().partition(":")
                if not sep or name.strip() == "sudo":
                    continue
                bucket = missing if state.strip() == "not installed" else present
                bucket.append(name.strip())
            if present or missing:
                parts = ["Outils installés : " + (", ".join(present) or "aucun")]
                if missing:
                    parts.append("manquants : " + ", ".join(missing))
                return " ; ".join(parts) + "."
            return _strip_collapse_trailer(getattr(parsed_result, "summary", ""))

        if tool_name == "nmap_scan":
            services = [
                service
                for service in getattr(parsed_result, "services_discovered", []) or []
                if str(getattr(service, "state", "") or "").casefold() == "open"
            ]
            if not services:
                return _strip_collapse_trailer(getattr(parsed_result, "summary", ""))

            target = str(arguments.get("target") or "").strip() or "target"
            ports = ", ".join(f"{svc.port}/{svc.protocol}" for svc in services)
            lines = [
                f"Résultat Nmap pour `{target}`:",
                f"1. Ports ouverts: {len(services)} ({ports}).",
            ]

            web_service = next(
                (
                    svc for svc in services
                    if svc.port in {80, 443, 8080, 8443}
                    or "http" in f"{svc.service} {svc.version}".casefold()
                    or "apache" in f"{svc.service} {svc.version}".casefold()
                ),
                None,
            )
            if web_service:
                web_label = " ".join(
                    part
                    for part in (web_service.service, web_service.version)
                    if str(part or "").strip()
                ).strip()
                if web_label:
                    lines.append(f"2. Serveur web/Apache: {web_label}.")

            ssh_service = next((svc for svc in services if svc.port == 22), None)
            if ssh_service:
                ssh_label = " ".join(
                    part
                    for part in (ssh_service.service, ssh_service.version)
                    if str(part or "").strip()
                ).strip() or "ssh"
                lines.append(f"3. Service sur le port 22: {ssh_label}.")

            if self._active_guided_task_text and any(
                marker in self._plain_text(self._active_guided_task_text)
                for marker in ("gobuster", "hidden directory", "find directories")
            ):
                url = self._preflight._known_web_url(self._active_guided_task_text)
                if url:
                    lines.append(
                        f"Question restante: trouver le hidden directory avec GoBuster sur `{url}`."
                    )
            return "\n".join(lines)

        if tool_name == "dir_brute":
            paths = list((getattr(parsed_result, "data", {}) or {}).get("paths", []) or [])
            url = str(arguments.get("url") or arguments.get("target") or "").strip() or "target"
            lines = [f"Résultat GoBuster pour `{url}`:"]
            if not paths:
                summary = _strip_collapse_trailer(getattr(parsed_result, "summary", ""))
                if summary:
                    lines.append(summary)
                lines.append("Aucun chemin exploitable n'a été identifié dans ce passage.")
                return "\n".join(lines)

            rendered_paths = ", ".join(
                f"{item.get('path', '?')} ({item.get('status', '?')})"
                for item in paths[:8]
            )
            if len(paths) > 8:
                rendered_paths += f", +{len(paths) - 8} autre(s)"
            lines.append(f"1. Chemins trouvés: {rendered_paths}.")

            interesting_paths = []
            for finding in getattr(parsed_result, "findings", []) or []:
                if getattr(finding, "category", "") != "dir_enum":
                    continue
                for evidence in getattr(finding, "evidence_items", []) or []:
                    metadata = getattr(evidence, "metadata", {}) or {}
                    path = str(metadata.get("path") or "").strip()
                    if path and path not in interesting_paths:
                        interesting_paths.append(path)
            if interesting_paths:
                ranked = sorted(
                    interesting_paths[:8], key=self._dir_candidate_score, reverse=True
                )
                lines.append(
                    "2. Candidat(s) hidden directory: "
                    + ", ".join(f"`{path}`" for path in ranked[:5])
                    + "."
                )
                best = ranked[0]
                if self._dir_candidate_score(best) >= 2:
                    lines.append(
                        f"   → Priorité: `{best}` — nom évocateur d'une interface "
                        "(admin/upload/login), vecteur d'exploitation le plus probable. "
                        "Ressources statiques (css/js) et endpoints en 403 à écarter."
                    )
            else:
                lines.append("2. Aucun candidat hidden directory évident dans les résultats parsés.")

            if self._active_guided_task_text and any(
                marker in self._plain_text(self._active_guided_task_text)
                for marker in ("upload", "reverse shell", "user.txt")
            ):
                lines.append("Question restante: identifier le formulaire d'upload puis récupérer `user.txt`.")
            return "\n".join(lines)

        return _strip_collapse_trailer(getattr(parsed_result, "summary", ""))

    def _normalize_tool_arguments(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(arguments or {})
        if tool_name != "nmap_scan":
            return normalized
        target = str(normalized.get("target") or "").strip()

        extra_args = str(normalized.get("extra_args") or "").strip()
        target_needs_split = bool(target and (target.startswith("-") or re.search(r"\s", target)))
        if target and not target_needs_split:
            return normalized

        scan_text = " ".join(part for part in (target, extra_args) if part).strip()
        if not scan_text:
            return normalized
        try:
            tokens = shlex.split(scan_text)
        except ValueError:
            tokens = scan_text.split()
        if tokens and tokens[0].rsplit("/", 1)[-1].casefold() == "nmap":
            tokens = tokens[1:]

        value_options = {
            "-p",
            "--top-ports",
            "--exclude",
            "--excludefile",
            "-iL",
            "-oA",
            "-oG",
            "-oN",
            "-oX",
            "--script",
        }
        skip_next = False
        selected_index: int | None = None
        for index, token in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if token in value_options:
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            selected_index = index
            break

        if selected_index is None:
            return normalized

        normalized["target"] = tokens[selected_index]
        remaining = tokens[:selected_index] + tokens[selected_index + 1:]
        if remaining:
            normalized["extra_args"] = " ".join(shlex.quote(token) for token in remaining)
        else:
            normalized.pop("extra_args", None)
        return normalized

    @staticmethod
    def _canonical_tool_name(tool_name: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(tool_name or "").casefold()).strip("_")
        aliases = {
            "bash": "run_shell",
            "execute_bash": "run_shell",
            "execute_command": "run_shell",
            "run_command": "run_shell",
            "shell_execute": "run_shell",
            "shell_exec": "run_shell",
            "terminal": "run_shell",
            "http_get": "run_shell",
            "http_fetch": "run_shell",
            "fetch_url": "run_shell",
            "http_request": "run_shell",
            "http_post": "run_shell",
            "post_url": "run_shell",
            "nmap": "nmap_scan",
            "nmapscan": "nmap_scan",
            "gobuster": "dir_brute",
            "dirb": "dir_brute",
            "dir_brute_force": "dir_brute",
            "vpnstatus": "vpn_status",
        }
        return aliases.get(normalized, str(tool_name or "").strip())

    @staticmethod
    def _first_string_argument(arguments: dict[str, Any]) -> str:
        for value in (arguments or {}).values():
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    @staticmethod
    def _normalized_tool_label(tool_name: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", str(tool_name or "").casefold()).strip("_")

    @classmethod
    def _http_alias_command(cls, original_name: str, arguments: dict[str, Any]) -> str:
        args = dict(arguments or {})
        original = cls._normalized_tool_label(original_name)
        if original not in {"http_get", "http_fetch", "fetch_url", "http_request", "http_post", "post_url"}:
            return ""
        url = str(args.get("url") or args.get("uri") or args.get("target") or cls._first_string_argument(args)).strip()
        if not url:
            return ""
        if original in {"http_post", "post_url"}:
            parts = ["curl", "-sL", "--max-time", "30", "-X", "POST"]
            data = args.get("data")
            if isinstance(data, dict):
                for key, value in data.items():
                    parts.extend(["-F", f"{key}={value}"])
            files = args.get("files")
            if isinstance(files, dict):
                for field, spec in files.items():
                    if isinstance(spec, dict):
                        filename = str(spec.get("filename") or field).strip() or field
                        content = str(spec.get("content") or "")
                        parts.extend(["-F", f"{field}={content};filename={filename}"])
                    elif isinstance(spec, str) and spec.strip():
                        parts.extend(["-F", f"{field}=@{spec.strip()}"])
            parts.append(url)
        else:
            parts = ["curl", "-sL", "--max-time", "20", url]
        return " ".join(shlex.quote(part) for part in parts)

    def _coerce_alias_arguments(
        self,
        tool_name: str,
        original_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        args = dict(arguments or {})
        if tool_name == "run_shell":
            http_command = self._http_alias_command(original_name, args)
            if http_command:
                return {"command": http_command}
            command = ""
            for key in ("command", "cmd", "shell", "bash", "input", "query"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    command = value.strip()
                    break
            if not command:
                command = self._first_string_argument(args)
            return {"command": command} if command else args

        if tool_name == "nmap_scan":
            if "target" not in args:
                for key in ("host", "ip", "address", "target_host"):
                    value = args.get(key)
                    if isinstance(value, str) and value.strip():
                        args["target"] = value.strip()
                        break
            if "target" not in args:
                command = ""
                for key in ("command", "cmd", "args", "arguments", "query"):
                    value = args.get(key)
                    if isinstance(value, str) and value.strip():
                        command = value.strip()
                        break
                if not command and original_name and self._canonical_tool_name(original_name) == "nmap_scan":
                    command = self._first_string_argument(args)
                if command:
                    args["extra_args"] = command
            return args

        if tool_name == "dir_brute" and "url" not in args:
            for key in ("target", "host", "domain"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    candidate = value.strip()
                    args["url"] = candidate if candidate.startswith(("http://", "https://")) else f"http://{candidate}"
                    break
        return args

    @staticmethod
    def _prompt_web_url(user_input: str) -> str:
        url_match = re.search(r"\bhttps?://[^\s\"'<>]+", user_input or "", re.IGNORECASE)
        if url_match:
            return url_match.group(0).rstrip(".,;)")

        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_input or "")
        if ip_match:
            return f"http://{ip_match.group(0)}"
        return ""

    @staticmethod
    def _url_from_service(service: Any) -> str:
        host = str(getattr(service, "host", "") or "").strip()
        if not host:
            return ""
        try:
            port = int(getattr(service, "port", 0) or 0)
        except (TypeError, ValueError):
            port = 0

        descriptor = " ".join(
            str(getattr(service, attr, "") or "")
            for attr in ("service", "version", "banner")
        ).casefold()
        is_https = port in {443, 8443} or "https" in descriptor or "ssl/http" in descriptor
        is_http = is_https or port in {80, 8000, 8008, 8080, 8081, 8888} or "http" in descriptor
        if not is_http:
            return ""

        scheme = "https" if is_https else "http"
        if (scheme == "http" and port in {0, 80}) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _known_web_url(self, user_input: str = "") -> str:
        prompt_url = self._prompt_web_url(user_input)
        if prompt_url:
            return prompt_url

        mission = getattr(self.structured_memory, "mission", None) if self.structured_memory else None
        if not mission:
            return ""

        for target in getattr(mission, "targets", []) or []:
            value = str(getattr(target, "value", "") or "").strip()
            if value.startswith(("http://", "https://")):
                return value

        for value in getattr(getattr(mission, "scope", None), "in_scope", []) or []:
            scoped = str(value or "").strip()
            if scoped.startswith(("http://", "https://")):
                return scoped

        for service in getattr(mission, "services", []) or []:
            url = self._url_from_service(service)
            if url:
                return url

        for host in getattr(mission, "hosts", []) or []:
            for service in getattr(host, "services", []) or []:
                url = self._url_from_service(service)
                if url:
                    return url

        return ""

    def _web_directory_preflight_tool_calls(self, user_input: str) -> list[ToolCallChunk]:
        """Delegate to PreflightRouter for web directory discovery."""
        self._preflight._structured_memory = self.structured_memory
        return self._preflight._web_directory_preflight(user_input)

    @staticmethod
    def _lab_provider_from_prompt(user_input: str) -> str:
        text = SecOpsAgent._plain_text(user_input)
        provider_markers = (
            ("tryhackme", ("tryhackme", "try hack me", "thm")),
            ("hackthebox", ("hackthebox", "hack the box", "htb")),
            ("rootme", ("rootme", "root-me")),
            ("portswigger", ("portswigger", "port swigger", "web security academy")),
            ("picoctf", ("picoctf", "pico ctf")),
            ("overthewire", ("overthewire", "over the wire")),
            ("vulnhub", ("vulnhub",)),
            ("ctf", ("ctf", "capture the flag", "challenge")),
        )
        for provider, markers in provider_markers:
            if any(marker in text for marker in markers):
                return provider
        return "lab"

    @staticmethod
    def _prompt_target_value(user_input: str) -> str:
        url_match = re.search(r"\bhttps?://[^\s\"'<>]+", user_input or "", re.IGNORECASE)
        if url_match:
            return url_match.group(0).rstrip(".,;)")
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_input or "")
        if ip_match:
            return ip_match.group(0)
        return ""

    def _suggested_action_preflight_tool_calls(self, user_input: str) -> list[ToolCallChunk]:
        """Delegate to PreflightRouter for suggestion selection."""
        # Sync mutable state that may have changed since __init__
        self._preflight._last_suggested_actions = self._last_suggested_actions
        self._preflight._last_suggestion_batch_id = self._last_suggestion_batch_id
        self._preflight._attempted_action_keys = self._attempted_action_keys
        return self._preflight._suggestion_preflight(user_input)

    def _local_preflight_tool_calls(self, user_input: str) -> list[ToolCallChunk]:
        """Route obvious local lab setup requests without waiting on the LLM."""
        # Sync mutable state that may have changed since __init__
        self._preflight._last_suggested_actions = self._last_suggested_actions
        self._preflight._last_suggestion_batch_id = self._last_suggestion_batch_id
        self._preflight._attempted_action_keys = self._attempted_action_keys
        self._preflight._structured_memory = self.structured_memory
        self._preflight._single_download_vpn_config_fn = self._single_download_vpn_config
        guided_calls = self._guided_task_preflight_tool_calls(user_input)
        if guided_calls:
            return guided_calls
        decision = self._request_decision(user_input)
        return self._preflight.route(user_input, decision)

    @staticmethod
    def _single_download_vpn_config() -> str:
        root = Path("~/Downloads").expanduser()
        try:
            if not root.exists() or not root.is_dir():
                return ""
            configs = sorted(
                path
                for path in root.iterdir()
                if path.is_file() and path.suffix.lower() in {".ovpn", ".conf"}
            )
        except OSError:
            return ""
        return str(configs[0]) if len(configs) == 1 else ""

    def _scope_gate_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult | None:
        mission = (
            getattr(self.structured_memory, "mission", None)
            if self.structured_memory
            else None
        )
        if not mission:
            return None

        check = ScopeGuard(mission).check_tool_call(tool_name, arguments)
        if check.allowed:
            return None

        reason = check.reason or "Out-of-scope target blocked."
        if hasattr(mission, "blocked_reasons") and reason not in mission.blocked_reasons[-10:]:
            mission.blocked_reasons.append(reason)
        return ToolResult(success=False, output="", error=reason)

    def _build_chained_tool_calls(
        self,
        remaining_budget: int,
    ) -> list[ToolCallChunk]:
        if remaining_budget <= 0 or not self.structured_memory or not self.planner:
            return []
        mission = getattr(self.structured_memory, "mission", None)
        if not mission:
            return []

        chained: list[ToolCallChunk] = []
        for action in self.planner.plan(mission):
            if len(chained) >= remaining_budget:
                break
            if (
                self._is_proposal_only_action(action)
                or not action.tool_name
                or action.key in self._attempted_action_keys
            ):
                continue
            tool_def = self.registry.get_tool(action.tool_name)
            if not tool_def:
                if hasattr(self.planner, "record_registry_decision"):
                    self.planner.record_registry_decision(action, False)
                continue
            if hasattr(self.planner, "record_registry_decision"):
                self.planner.record_registry_decision(action, True)
            permission = self.permissions.evaluate_tool(action.tool_name, tool_def.dangerous)
            if permission == PermissionDecision.DENY:
                continue
            unique_id = f"{action.tool_name}_{uuid.uuid4().hex[:8]}"
            call = ToolCallChunk(
                name=action.tool_name,
                arguments=dict(action.arguments),
                id=unique_id,
            )
            self._attempted_action_keys.add(action.key)
            chained.append(call)
        return chained

    @staticmethod
    def _is_proposal_only_action(action: NextAction) -> bool:
        if str(getattr(action, "phase", "") or "") == "proposal":
            return True
        for detail in getattr(action, "experience_details", []) or []:
            if isinstance(detail, dict) and detail.get("effect") == "playbook-proposal":
                return True
        return False

    def _suggested_next_actions(self, max_actions: int = 5) -> list[NextAction]:
        if not self.structured_memory or not self.planner:
            return []
        mission = getattr(self.structured_memory, "mission", None)
        if not mission:
            return []

        suggestions: list[NextAction] = []
        for action in self.planner.plan(mission):
            if action.key in self._attempted_action_keys:
                continue
            if action.tool_name:
                tool_available = self.registry.get_tool(action.tool_name) is not None
                if hasattr(self.planner, "record_registry_decision"):
                    self.planner.record_registry_decision(action, tool_available)
                if not tool_available:
                    continue
            suggestions.append(action)
            if len(suggestions) >= max_actions:
                break
        return suggestions

    async def stream_response(
        self,
        user_input: str,
        *,
        attachments: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[AgentEvent]:
        """
        Main agent loop: sends user input to LLM, handles tool calls,
        streams events to the UI, and manages dangerous tool approvals.
        """
        self.memory.add_user_message(user_input, attachments=attachments or [])
        self._turn_count += 1
        turn_id = uuid.uuid4().hex
        chained_actions_this_turn = 0
        request_decision = self._request_decision(user_input)
        if self._looks_like_guided_multistep_task(user_input):
            self._active_guided_task_text = user_input
        guided_lab_restraint_turn = request_decision.should_suppress_followups
        # RC2 (multi-step): for broader low-risk work, let the model chain tool
        # calls across iterations within a single turn (recon -> enumerate ->
        # ...). We pause for a text-only summary only when the turn is a focused
        # answer/social turn (answer once, stop) or the autonomy policy requires
        # approval for this risk level (exploitation/destructive). The exposed
        # toolset already excludes offensive/privileged primitives for low-risk
        # turns, so the chain stays within safe tools; max_iterations bounds it.
        allow_llm_chaining = (
            not self.allow_automatic_planner_execution
            and not guided_lab_restraint_turn
            and request_decision.user_intent in _CHAINING_INTENTS
            and not self._autonomy_for_turn(request_decision).pauses_for(request_decision.risk)
        )
        self._trace(
            "turn_started",
            turn_id=turn_id,
            turn_number=self._turn_count,
            prompt_chars=len(user_input or ""),
            attachments=len(attachments or []),
            technical_goal=getattr(request_decision.technical_goal, "value", str(request_decision.technical_goal)),
            should_suppress_followups=request_decision.should_suppress_followups,
            llm_chaining=allow_llm_chaining,
        )

        local_answer = self._local_preflight_answer(user_input, request_decision)
        if local_answer:
            yield ThinkingEvent("Thinking...")
            yield TextEvent(content=local_answer)
            yield TextEvent(content="", done=True)
            self.memory.add_assistant_message(local_answer)
            return

        # Build mission-aware context for the LLM
        llm_context: dict[str, Any] = dict(request_decision.to_context())
        if guided_lab_restraint_turn:
            # Compatibility key for existing model-routing tests and prompts.
            llm_context["guided_lab_restraint"] = True
        if self.structured_memory:
            sm = self.structured_memory
            mission = getattr(sm, "mission", None)
            if mission:
                llm_context["phase"] = mission.phase.value if hasattr(mission.phase, "value") else str(mission.phase)
                llm_context["phase_reason"] = getattr(mission, "phase_reason", "")
                llm_context["findings_count"] = len(mission.findings)
                llm_context["blocked_reason"] = "; ".join(mission.blocked_reasons[-3:]) if mission.blocked_reasons else ""
            # Inject structured context into system prompt, primed with any
            # relevant prior lessons (memory briefing).
            ctx_str = sm.build_context_for_llm(include_conversation=False)
            briefing = self._relevant_lessons_briefing(mission)
            if briefing:
                ctx_str = f"{ctx_str}\n\n{briefing}" if ctx_str else briefing
            if ctx_str and hasattr(self.llm, "set_mission_context"):
                self.llm.set_mission_context(ctx_str)

        if hasattr(self.llm, "prepare_for_prompt"):
            self.llm.prepare_for_prompt(user_input, context=llm_context or None)

        async for _event in self._run_mission_loop(
            user_input=user_input,
            request_decision=request_decision,
            turn_id=turn_id,
            guided_lab_restraint_turn=guided_lab_restraint_turn,
            allow_llm_chaining=allow_llm_chaining,
            chained_actions_this_turn=chained_actions_this_turn,
        ):
            yield _event

    async def _run_mission_loop(
        self,
        *,
        user_input: str,
        request_decision: Any,
        turn_id: str,
        guided_lab_restraint_turn: bool,
        allow_llm_chaining: bool,
        chained_actions_this_turn: int,
    ) -> AsyncIterator[AgentEvent]:
        """The ReAct mission loop (plan->act->observe->reflect), extracted from
        stream_response (chantier 3 / ARCHITECTURE §3). Bounded by max_iterations;
        preserves both convergence guardrails and the AutonomyPolicy pause behaviour.
        """
        iteration = 0
        local_preflight_calls = self._local_preflight_tool_calls(user_input)
        text_only_followup_after_tools = False
        announced_action_retry_used = False
        # A5: best available summary of a tool result obtained this turn, used as
        # a fallback answer if the follow-up synthesis LLM call fails transiently
        # so the turn is never left empty and the result is not discarded.
        pending_tool_summary = ""
        previous_iter_signatures: tuple[str, ...] = ()
        repeated_iteration_streak = 0
        while iteration < self.max_iterations:
            iteration += 1
            tools_were_offered = False

            current_response_text = ""
            tool_calls_to_run = []
            archived_tool_marker_seen = False
            local_preflight_turn = iteration == 1 and bool(local_preflight_calls)
            defer_text_stream = guided_lab_restraint_turn and not local_preflight_turn

            # Thinking indicator
            yield ThinkingEvent("Thinking...")

            if local_preflight_turn:
                current_response_text = ""
                tool_calls_to_run = list(local_preflight_calls)
                for tc in tool_calls_to_run:
                    self._tool_call_sources[tc.id] = "local_preflight"
                    self._remember_attempted_tool_call(tc.name, tc.arguments)
                    tool_def = self.registry.get_tool(tc.name)
                    is_dangerous = tool_def.dangerous if tool_def else False
                    permission = self.permissions.evaluate_tool(tc.name, is_dangerous)
                    yield ToolCallEvent(
                        name=tc.name,
                        arguments=tc.arguments,
                        id=tc.id,
                        dangerous=permission != PermissionDecision.ALLOW,
                        permission=permission.value,
                    )
            else:
                # Get tools schema
                tools_schema = (
                    []
                    if text_only_followup_after_tools and not self.allow_automatic_planner_execution
                    else self._tools_schema_for_decision(request_decision)
                )
                tools_were_offered = bool(tools_schema)

                async for llm_item in self._stream_llm_with_retries(
                    tools_schema=tools_schema,
                    turn_id=turn_id,
                ):
                    if isinstance(llm_item, StatusEvent):
                        yield llm_item
                        continue
                    if isinstance(llm_item, ErrorEvent):
                        # A5: a transient failure of the synthesis call must not
                        # discard a tool result already obtained this turn.
                        # Present the extracted summary so the turn is not empty
                        # and the correct data still reaches the user.
                        if pending_tool_summary and not current_response_text.strip():
                            yield TextEvent(content=pending_tool_summary)
                            self.memory.add_assistant_message(pending_tool_summary)
                            pending_tool_summary = ""
                        elif (
                            not current_response_text.strip()
                            and self._is_retriable_llm_error(llm_item.error)
                        ):
                            # RC-γ / D5: a transient error on the first (tool-
                            # selection) call leaves no tool result to fall back
                            # on. Never end empty — surface a clean notice.
                            notice = self._transient_llm_notice(user_input)
                            yield TextEvent(content=notice)
                            self.memory.add_assistant_message(notice)
                        yield llm_item
                        return
                    chunk = llm_item

                    # Text token
                    if chunk.content:
                        cleaned_content, saw_archived_marker = self._strip_archived_tool_markers(chunk.content)
                        archived_tool_marker_seen = archived_tool_marker_seen or saw_archived_marker
                        if cleaned_content:
                            current_response_text += cleaned_content
                            if not defer_text_stream:
                                yield TextEvent(content=cleaned_content)

                    # Tool call requested
                    if chunk.tool_call:
                        if text_only_followup_after_tools and not self.allow_automatic_planner_execution:
                            logger.debug(
                                "Ignoring tool call %s during text-only follow-up after tool execution",
                                chunk.tool_call.name,
                            )
                            continue
                        # Generate unique ID
                        tc = chunk.tool_call
                        tool_name = self._canonical_tool_name(tc.name)
                        arguments = self._coerce_alias_arguments(
                            tool_name,
                            tc.name,
                            tc.arguments,
                        )
                        arguments = self._normalize_tool_arguments(tool_name, arguments)
                        tool_def = self.registry.get_tool(tool_name)
                        if not tool_def:
                            notice = (
                                f"\nTool `{tc.name}` is not registered locally. "
                                "I will not execute that call; use `/tools` to list available tools."
                            )
                            current_response_text += notice
                            if not defer_text_stream:
                                yield TextEvent(content=notice)
                            continue

                        unique_id = f"{tool_name}_{uuid.uuid4().hex[:8]}"
                        tc_with_id = type(tc)(
                            name=tool_name,
                            arguments=arguments,
                            id=unique_id,
                        )
                        tool_calls_to_run.append(tc_with_id)
                        self._tool_call_sources[unique_id] = "llm"
                        self._remember_attempted_tool_call(tool_name, arguments)

                        is_dangerous = tool_def.dangerous
                        permission = self.permissions.evaluate_tool(tool_name, is_dangerous)

                        yield ToolCallEvent(
                            name=tool_name,
                            arguments=arguments,
                            id=unique_id,
                            dangerous=permission != PermissionDecision.ALLOW,
                            permission=permission.value,
                        )

            if defer_text_stream and current_response_text:
                filtered_response_text = self._strip_mission_state_sections(current_response_text)
                if filtered_response_text:
                    yield TextEvent(content=filtered_response_text)
                    current_response_text = filtered_response_text
                else:
                    current_response_text = ""

            if archived_tool_marker_seen and not current_response_text.strip():
                current_response_text = (
                    "I did not run a tool in this turn. The model referenced an archived tool call "
                    "from history, which is not executable now."
                )
                if not defer_text_stream:
                    yield TextEvent(content=current_response_text)

            # Loop guardrails for an iteration that produced no tool calls.
            no_tools_this_iter = not tool_calls_to_run
            if no_tools_this_iter:
                # Guard: the model narrated an action ("Je vais scanner...")
                # while tools were available but called nothing. Give it one
                # corrective iteration to actually act before ending the turn.
                if (
                    tools_were_offered
                    and not announced_action_retry_used
                    and self._announces_unexecuted_action(current_response_text)
                ):
                    announced_action_retry_used = True
                    if not local_preflight_turn:
                        yield TextEvent(content="", done=True)
                    self.memory.add_assistant_message(current_response_text)
                    self.memory.add_user_message(
                        "(System reminder: you described an action but did not call "
                        "the tool. If you intend to run it, call the tool now via a "
                        "function call; otherwise give the direct answer.)"
                    )
                    continue

                # Guard: never end a turn on a blank assistant message.
                if not current_response_text.strip():
                    current_response_text = (
                        "I don't have anything to run for that. Could you clarify "
                        "what you'd like me to do, or give a target to work with?"
                    )
                    if not defer_text_stream:
                        yield TextEvent(content=current_response_text)

            # Close streamed LLM text before executing model-requested tools.
            # Local preflight turns generate their user-facing summary after
            # the deterministic tool result, so close them at the end instead.
            if not local_preflight_turn:
                yield TextEvent(content="", done=True)

            if no_tools_this_iter:
                self.memory.add_assistant_message(current_response_text)
                break

            # Convergence guard: if the model re-issues the identical tool calls
            # iteration after iteration, it is looping without progress. Allow one
            # repeat, then stop with an explanation instead of silently burning
            # through max_iterations on a circular call.
            current_iter_signatures = tuple(sorted(
                f"{tc.name}:{sorted(tc.arguments.items())!r}" for tc in tool_calls_to_run
            ))
            if current_iter_signatures and current_iter_signatures == previous_iter_signatures:
                repeated_iteration_streak += 1
            else:
                repeated_iteration_streak = 0
            previous_iter_signatures = current_iter_signatures

            if repeated_iteration_streak >= 2:
                stall_msg = (
                    "I repeated the same tool call without making progress, so I "
                    "stopped to avoid a loop. The last action did not change the "
                    "result — a different approach or input is needed."
                )
                if current_response_text.strip():
                    self.memory.add_assistant_message(current_response_text)
                self.memory.add_assistant_message(stall_msg)
                yield TextEvent(content=stall_msg)
                break

            # Store assistant message with tool calls
            serialized_tool_calls = [
                {"name": tc.name, "arguments": tc.arguments, "id": tc.id}
                for tc in tool_calls_to_run
            ]
            self.memory.add_assistant_message(
                current_response_text, tool_calls=serialized_tool_calls
            )

            # Execute tool calls
            for tc in tool_calls_to_run:
                tool_def = self.registry.get_tool(tc.name)
                action_trace = self._start_action_trace(
                    turn_id=turn_id,
                    user_input=user_input,
                    tool_call=tc,
                    tool_def=tool_def,
                )

                if not tool_def:
                    res = ToolResult(
                        success=False,
                        output="",
                        error=f"Error: Tool '{tc.name}' is not registered.",
                    )
                else:
                    scope_gate_result = self._scope_gate_tool_call(tc.name, tc.arguments)
                    if scope_gate_result is not None:
                        self._finish_action_trace(
                            action_trace,
                            status="blocked",
                            result=scope_gate_result,
                            error=scope_gate_result.error or "",
                        )
                        self.memory.add_tool_result(
                            tc.name, scope_gate_result.error or ""
                        )
                        yield ToolResultEvent(name=tc.name, result=scope_gate_result, id=tc.id)
                        continue

                    sudo_command_candidate = ""
                    if tc.name == "connect_vpn_config" and str(
                        (tc.arguments or {}).get("config_path") or ""
                    ).strip():
                        sudo_command_candidate = self._sudo_command_candidate_for_tool_call(
                            tool_def,
                            tc.arguments,
                        )
                    if sudo_command_candidate:
                        sandbox_check = validate_shell_command(sudo_command_candidate)
                        if not sandbox_check.allowed:
                            res = ToolResult(
                                success=False,
                                output="",
                                error=f"Sandbox blocked command: {sandbox_check.reason}",
                            )
                            self._finish_action_trace(
                                action_trace,
                                status="blocked",
                                result=res,
                                error=res.error or "",
                            )
                            self.memory.add_tool_result(tc.name, res.error or "")
                            yield ToolResultEvent(name=tc.name, result=res, id=tc.id)
                            continue
                        resource = self.permissions.command_approval_resource(sudo_command_candidate)
                        permission = self.permissions.check_command_permission(
                            [self._command_word(sudo_command_candidate)],
                            command_text=sudo_command_candidate,
                        )
                    else:
                        permission = self.permissions.evaluate_tool(tc.name, tool_def.dangerous)
                        resource = self.permissions.tool_resource(tc.name)
                    if action_trace is not None:
                        action_trace.permission = permission.value

                    if permission == PermissionDecision.DENY:
                        res = ToolResult(
                            success=False,
                            output="",
                            error=f"Permission denied by policy: {resource.value}",
                        )
                        self._finish_action_trace(
                            action_trace,
                            status="denied",
                            result=res,
                            error=res.error or "",
                        )
                        self.memory.add_tool_result(
                            tc.name, f"Permission denied by policy: {resource.value}"
                        )
                        yield ToolResultEvent(name=tc.name, result=res, id=tc.id)
                        continue

                    if permission == PermissionDecision.ASK:
                        if action_trace is not None:
                            action_trace.status = "approval_requested"
                        while True:
                            loop = asyncio.get_running_loop()
                            approval_future = loop.create_future()

                            yield ApprovalRequestEvent(
                                tool_name=tc.name,
                                arguments=tc.arguments,
                                resource=resource,
                                approval_future=approval_future,
                            )

                            # Wait for user approval
                            try:
                                approval = await asyncio.wait_for(
                                    approval_future, timeout=self.approval_timeout
                                )
                            except asyncio.TimeoutError:
                                approval = ApprovalDecision(allowed=False)

                            approval = self._coerce_approval(approval)
                            if approval.amended_arguments:
                                tc.arguments = approval.amended_arguments
                                self._update_recorded_tool_arguments(tc.id, tc.arguments)
                                if action_trace is not None:
                                    action_trace.arguments = dict(tc.arguments)
                                continue

                            self._remember_approval(resource, approval)
                            break

                        if not approval.allowed:
                            error = self._approval_denied_error(resource, approval)
                            res = ToolResult(
                                success=False,
                                output="",
                                error=error,
                            )
                            self._finish_action_trace(
                                action_trace,
                                status="denied",
                                result=res,
                                error=error,
                            )
                            self.memory.add_tool_result(tc.name, error)
                            yield ToolResultEvent(name=tc.name, result=res, id=tc.id)
                            continue
                        if action_trace is not None:
                            action_trace.status = "approved"

                    argument_gate_result: ToolResult | None = None
                    while True:
                        argument_permission, argument_resource = (
                            self.permissions.evaluate_tool_argument_resource(
                                tc.name,
                                tc.arguments,
                            )
                        )
                        if not argument_resource or argument_permission == PermissionDecision.ALLOW:
                            break

                        if argument_permission == PermissionDecision.DENY:
                            argument_gate_result = ToolResult(
                                success=False,
                                output="",
                                error=f"Permission denied by policy: {argument_resource.value}",
                            )
                            break

                        loop = asyncio.get_running_loop()
                        approval_future = loop.create_future()

                        yield ApprovalRequestEvent(
                            tool_name=tc.name,
                            arguments=tc.arguments,
                            resource=argument_resource,
                            approval_future=approval_future,
                        )

                        try:
                            approval = await asyncio.wait_for(
                                approval_future, timeout=self.approval_timeout
                            )
                        except asyncio.TimeoutError:
                            approval = ApprovalDecision(allowed=False)

                        approval = self._coerce_approval(approval)
                        if approval.amended_arguments:
                            tc.arguments = approval.amended_arguments
                            self._update_recorded_tool_arguments(tc.id, tc.arguments)
                            if action_trace is not None:
                                action_trace.arguments = dict(tc.arguments)
                            continue

                        self._remember_approval(argument_resource, approval)
                        if not approval.allowed:
                            argument_gate_result = ToolResult(
                                success=False,
                                output="",
                                error=self._approval_denied_error(argument_resource, approval),
                            )
                        break

                    if argument_gate_result is not None:
                        self._finish_action_trace(
                            action_trace,
                            status="denied",
                            result=argument_gate_result,
                            error=argument_gate_result.error or "",
                        )
                        self.memory.add_tool_result(
                            tc.name, argument_gate_result.error or ""
                        )
                        yield ToolResultEvent(name=tc.name, result=argument_gate_result, id=tc.id)
                        continue

                    command_gate_result: ToolResult | None = None
                    restart_command_gate = True
                    approved_command_resources: set[str] = set()
                    while restart_command_gate:
                        restart_command_gate = False
                        full_command = str(tc.arguments.get("command") or "").strip()
                        approval_resource = self.permissions.command_approval_resource(full_command)
                        for command_resource in self._command_resources_for_tool_call(tc.name, tc.arguments):
                            if not command_resource.name:
                                command_gate_result = ToolResult(
                                    success=False,
                                    output="",
                                    error="Permission denied by policy: command(empty)",
                                )
                                break

                            if approval_resource.value in approved_command_resources:
                                command_permission = PermissionDecision.ALLOW
                            else:
                                command_permission = self.permissions.check_command_permission(
                                    [command_resource.name],
                                    command_text=full_command,
                                )
                            if command_permission == PermissionDecision.DENY:
                                command_gate_result = ToolResult(
                                    success=False,
                                    output="",
                                    error=f"Permission denied by policy: {command_resource.value}",
                                )
                                break

                            if command_permission == PermissionDecision.ASK:
                                loop = asyncio.get_running_loop()
                                approval_future = loop.create_future()

                                yield ApprovalRequestEvent(
                                    tool_name=tc.name,
                                    arguments=tc.arguments,
                                    resource=approval_resource,
                                    approval_future=approval_future,
                                )

                                try:
                                    approval = await asyncio.wait_for(
                                        approval_future, timeout=self.approval_timeout
                                    )
                                except asyncio.TimeoutError:
                                    approval = ApprovalDecision(allowed=False)

                                approval = self._coerce_approval(approval)
                                if approval.amended_arguments:
                                    tc.arguments = approval.amended_arguments
                                    self._update_recorded_tool_arguments(tc.id, tc.arguments)
                                    if action_trace is not None:
                                        action_trace.arguments = dict(tc.arguments)
                                    approved_command_resources.clear()
                                    restart_command_gate = True
                                    break

                                self._remember_approval(approval_resource, approval)

                                if not approval.allowed:
                                    error = self._approval_denied_error(approval_resource, approval)
                                    command_gate_result = ToolResult(
                                        success=False,
                                        output="",
                                        error=error,
                                    )
                                    break
                                approved_command_resources.add(approval_resource.value)

                    if command_gate_result is not None:
                        self._finish_action_trace(
                            action_trace,
                            status="denied",
                            result=command_gate_result,
                            error=command_gate_result.error or "",
                        )
                        self.memory.add_tool_result(
                            tc.name, command_gate_result.error or ""
                        )
                        yield ToolResultEvent(name=tc.name, result=command_gate_result, id=tc.id)
                        continue

                    scope_gate_result = self._scope_gate_tool_call(tc.name, tc.arguments)
                    if scope_gate_result is not None:
                        self._finish_action_trace(
                            action_trace,
                            status="blocked",
                            result=scope_gate_result,
                            error=scope_gate_result.error or "",
                        )
                        self.memory.add_tool_result(
                            tc.name, scope_gate_result.error or ""
                        )
                        yield ToolResultEvent(name=tc.name, result=scope_gate_result, id=tc.id)
                        continue

                    sudo_command = self._sudo_command_for_tool_call(tool_def, tc.arguments)
                    if sudo_command:
                        sudo_ok, sudo_reason = await sudo_noninteractive_status()
                        if not sudo_ok and can_prompt_for_sudo():
                            loop = asyncio.get_running_loop()
                            authentication_future = loop.create_future()
                            yield SudoAuthenticationRequestEvent(
                                command=sudo_command,
                                reason=sudo_reason,
                                authentication_future=authentication_future,
                            )
                            try:
                                sudo_auth = await asyncio.wait_for(
                                    authentication_future,
                                    timeout=max(self.approval_timeout, 30),
                                )
                            except asyncio.TimeoutError:
                                sudo_auth = SudoAuthenticationDecision(
                                    success=False,
                                    reason="sudo authentication timed out",
                                )
                            if not isinstance(sudo_auth, SudoAuthenticationDecision):
                                sudo_auth = SudoAuthenticationDecision(
                                    success=bool(getattr(sudo_auth, "success", False)),
                                    reason=str(getattr(sudo_auth, "reason", "") or ""),
                                )
                            if not sudo_auth.success:
                                error = (
                                    "Sudo authentication was not completed, so the "
                                    "command was not executed."
                                )
                                if sudo_auth.reason:
                                    error += f"\nReason: {sudo_auth.reason}"
                                res = ToolResult(success=False, output="", error=error)
                                self._finish_action_trace(
                                    action_trace,
                                    status="denied",
                                    result=res,
                                    error=error,
                                )
                                self.memory.add_tool_result(tc.name, error)
                                yield ToolResultEvent(name=tc.name, result=res, id=tc.id)
                                continue

                    # Execute the tool
                    if action_trace is not None:
                        action_trace.status = "running"
                    self._trace(
                        "tool_started",
                        turn_id=turn_id,
                        tool_call_id=tc.id,
                        tool_name=tc.name,
                        arguments=tc.arguments,
                    )
                    yield ToolStartEvent(name=tc.name, arguments=tc.arguments, id=tc.id)
                    before_hooks = self.hooks.hooks_for("before_tool", tc.name)
                    if before_hooks:
                        yield ToolProgressEvent(
                            name=tc.name,
                            id=tc.id,
                            phase="running before_tool hooks",
                            detail=f"{len(before_hooks)} hook(s)",
                        )
                        await self.hooks.run("before_tool", tc.name, tc.arguments)

                    progress_queue: asyncio.Queue[ToolProgress] = asyncio.Queue()

                    async def publish_progress(progress: ToolProgress):
                        await progress_queue.put(progress)

                    execution_task = asyncio.create_task(
                        self.registry.execute(
                            tc.name,
                            tc.arguments,
                            progress=publish_progress,
                        )
                    )
                    progress_task: asyncio.Task | None = asyncio.create_task(progress_queue.get())
                    loop = asyncio.get_running_loop()
                    tool_started_at = loop.time()

                    try:
                        while True:
                            wait_for = {execution_task}
                            if progress_task:
                                wait_for.add(progress_task)

                            done, _ = await asyncio.wait(
                                wait_for,
                                return_when=asyncio.FIRST_COMPLETED,
                                timeout=self.tool_idle_progress_interval,
                            )

                            if not done:
                                elapsed = max(0.0, loop.time() - tool_started_at)
                                if elapsed < 60:
                                    elapsed_label = f"{elapsed:.1f}s"
                                else:
                                    minutes = int(elapsed // 60)
                                    seconds = int(elapsed % 60)
                                    elapsed_label = f"{minutes}m {seconds}s"
                                yield ToolProgressEvent(
                                    name=tc.name,
                                    id=tc.id,
                                    phase="still running",
                                    detail=f"{elapsed_label} elapsed · waiting for tool output",
                                )
                                continue

                            if progress_task and progress_task in done:
                                progress = progress_task.result()
                                yield ToolProgressEvent(
                                    name=tc.name,
                                    id=tc.id,
                                    phase=progress.phase,
                                    detail=progress.detail,
                                    percent=progress.percent,
                                )
                                progress_task = (
                                    asyncio.create_task(progress_queue.get())
                                    if not execution_task.done()
                                    else None
                                )

                            if execution_task in done:
                                if progress_task and not progress_task.done():
                                    progress_task.cancel()
                                while not progress_queue.empty():
                                    progress = progress_queue.get_nowait()
                                    yield ToolProgressEvent(
                                        name=tc.name,
                                        id=tc.id,
                                        phase=progress.phase,
                                        detail=progress.detail,
                                        percent=progress.percent,
                                    )
                                res = execution_task.result()
                                break
                    except asyncio.CancelledError:
                        if not execution_task.done():
                            execution_task.cancel()
                            try:
                                await execution_task
                            except asyncio.CancelledError:
                                pass
                            except Exception:
                                pass
                        raise
                    finally:
                        if progress_task and not progress_task.done():
                            progress_task.cancel()

                    hook_event = "after_tool" if res.success else "on_error"
                    matching_hooks = self.hooks.hooks_for(hook_event, tc.name)
                    if matching_hooks:
                        yield ToolProgressEvent(
                            name=tc.name,
                            id=tc.id,
                            phase=f"running {hook_event} hooks",
                            detail=f"{len(matching_hooks)} hook(s)",
                        )
                        await self.hooks.run(
                            hook_event,
                            tc.name,
                            tc.arguments,
                            result=res,
                            error=res.error or "",
                        )

                # Add to memory
                self.memory.add_tool_result(
                    tc.name, res.output or res.error or ""
                )
                self._trace(
                    "tool_completed",
                    turn_id=turn_id,
                    tool_call_id=tc.id,
                    tool_name=tc.name,
                    success=res.success,
                    execution_time=getattr(res, "execution_time", 0),
                    output_chars=len(res.output or ""),
                    error_chars=len(res.error or ""),
                )
                self._record_suggestion_execution_outcome(tc.id, res)

                pending_suggestions: list[NextAction] = []
                parsed_result: Any | None = None
                state_changes: list[str] = []
                experience_recorded = False
                action_trace_finished = False
                # Phase 2: parse tool results into structured data
                if self.result_parser and res.success and res.output:
                    try:
                        parsed = self.result_parser.parse(
                            tc.name, res.output, tc.arguments
                        )
                        parsed_result = parsed
                        # Integrate into knowledge base
                        if self.structured_memory and hasattr(self.structured_memory, "knowledge"):
                            changes = self.structured_memory.knowledge.integrate(parsed)
                            state_changes = list(changes)
                            if hasattr(self.structured_memory, "sync_to_mission"):
                                self.structured_memory.sync_to_mission()
                            # Auto-advance mission phase based on new evidence
                            _sm_mission = getattr(self.structured_memory, "mission", None)
                            if _sm_mission and hasattr(_sm_mission, "refresh_phase_from_state"):
                                _sm_mission.refresh_phase_from_state()
                            self._record_experience_lesson(
                                tc.name,
                                tc.arguments,
                                res,
                                parsed_result,
                            )
                            experience_recorded = True
                            # Update mission context in LLM for next iteration
                            if changes and not guided_lab_restraint_turn:
                                pending_suggestions = self._suggested_next_actions()
                                self._last_suggested_actions = list(pending_suggestions)
                                self._record_suggestion_batch(pending_suggestions)

                                remaining_chain_budget = (
                                    self.max_chained_actions_per_turn
                                    - chained_actions_this_turn
                                    if self.allow_automatic_planner_execution
                                    else 0
                                )
                                chained_calls = self._build_chained_tool_calls(
                                    remaining_chain_budget
                                )
                                for chained_call in chained_calls:
                                    tool_calls_to_run.append(chained_call)
                                    self._tool_call_sources[chained_call.id] = "planner"
                                    self._record_tool_call(chained_call)
                                    chained_actions_this_turn += 1
                                    chained_tool_def = self.registry.get_tool(chained_call.name)
                                    is_dangerous = (
                                        chained_tool_def.dangerous
                                        if chained_tool_def
                                        else False
                                    )
                                    permission = self.permissions.evaluate_tool(
                                        chained_call.name,
                                        is_dangerous,
                                    )
                                    yield ToolCallEvent(
                                        name=chained_call.name,
                                        arguments=chained_call.arguments,
                                        id=chained_call.id,
                                        dangerous=permission != PermissionDecision.ALLOW,
                                        permission=permission.value,
                                    )
                                self._finish_action_trace(
                                    action_trace,
                                    status="succeeded" if res.success else "failed",
                                    result=res,
                                    parsed_result=parsed_result,
                                    state_changes=state_changes,
                                    suggested_actions=pending_suggestions,
                                )
                                action_trace_finished = True
                                ctx_str = self.structured_memory.build_context_for_llm(
                                    include_conversation=False
                                )
                                if hasattr(self.llm, "set_mission_context"):
                                    self.llm.set_mission_context(ctx_str)
                    except Exception as exc:
                        logger.debug(
                            "Result integration failed for tool %s: %s",
                            tc.name, exc, exc_info=True,
                        )
                if not experience_recorded:
                    self._record_experience_lesson(tc.name, tc.arguments, res, parsed_result)

                if not action_trace_finished:
                    self._finish_action_trace(
                        action_trace,
                        status="succeeded" if res.success else "failed",
                        result=res,
                        parsed_result=parsed_result,
                        state_changes=state_changes,
                        suggested_actions=pending_suggestions,
                    )
                # P3: carry the parsed structured summary to the renderer so the
                # collapsed (Ctrl+O) view leads with the key fact ("3 services on
                # 10.10.10.5") instead of the raw output head.
                parsed_summary = str(getattr(parsed_result, "summary", "") or "").strip()
                if parsed_summary and isinstance(getattr(res, "metadata", None), dict):
                    res.metadata.setdefault("parsed_summary", parsed_summary)
                # A5: remember the best user-facing summary of this successful tool
                # result so it can be presented if the synthesis call later fails.
                if res.success:
                    tool_answer = (
                        self._format_tool_answer_summary(tc.name, tc.arguments, parsed_result)
                        or _strip_collapse_trailer(parsed_summary)
                    )
                    if tool_answer:
                        pending_tool_summary = tool_answer
                yield ToolResultEvent(name=tc.name, result=res, id=tc.id)
                if local_preflight_turn and res.success:
                    answer_summary = self._format_tool_answer_summary(
                        tc.name,
                        tc.arguments,
                        parsed_result,
                    )
                    if answer_summary:
                        yield TextEvent(content=answer_summary)
                        self.memory.add_assistant_message(answer_summary)
                # Suggestions are a single-step affordance: when the model is
                # chaining multi-step it drives its own next action, so emitting
                # "suggested next actions" mid-chain would be noise.
                if pending_suggestions and not allow_llm_chaining:
                    yield SuggestedActionsEvent(actions=pending_suggestions)

            if local_preflight_turn:
                yield TextEvent(content="", done=True)
                break

            # After a tool batch, either let the model keep chaining (RC2
            # multi-step) or fall back to one natural-language summary pass with
            # tools withheld. Focused-answer/social turns and high-risk turns do
            # not chain.
            if (
                tool_calls_to_run
                and not self.allow_automatic_planner_execution
                and not allow_llm_chaining
            ):
                text_only_followup_after_tools = True
        else:
            yield ErrorEvent(
                f"Max iterations ({self.max_iterations}) reached. "
                "Stopping to prevent infinite loop."
            )

    def _command_resources_for_tool_call(
        self,
        tool_name: str,
        arguments: dict,
    ) -> list[PermissionResource]:
        if tool_name != "run_shell":
            return []
        command = str(arguments.get("command") or "")
        if not command.strip():
            return [PermissionResource(kind="command", name="")]
        return self.permissions.shell_command_resources(command)

    @staticmethod
    def _command_word(command: str) -> str:
        try:
            tokens = shlex.split(str(command or ""))
        except ValueError:
            tokens = str(command or "").split()
        return tokens[0].rsplit("/", 1)[-1] if tokens else ""

    @staticmethod
    def _sudo_command_candidate_for_tool_call(tool_def: Any | None, arguments: dict[str, Any]) -> str:
        if tool_def is None:
            return ""

        tool_name = str(getattr(tool_def, "name", "") or "")
        func = getattr(tool_def, "func", None)
        module = str(getattr(func, "__module__", ""))
        command = ""
        if tool_name == "run_shell" and module == "secops_agent.tools.forensics":
            command = str((arguments or {}).get("command") or "").strip()
        elif tool_name == "connect_vpn_config":
            config_path = str((arguments or {}).get("config_path") or "").strip()
            display_path = config_path or "selected VPN config"
            command = f"sudo openvpn --config {shlex.quote(display_path)}"
        elif tool_name == "disconnect_vpn":
            command = "sudo kill openvpn"

        if not command or not command_uses_sudo(command):
            return ""
        return command

    @staticmethod
    def _sudo_command_for_tool_call(tool_def: Any | None, arguments: dict[str, Any]) -> str:
        command = SecOpsAgent._sudo_command_candidate_for_tool_call(tool_def, arguments)
        if not command:
            return ""
        if not validate_shell_command(command).allowed:
            return ""
        return command
