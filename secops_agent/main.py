"""
Main entry point for the SecOps Agent CLI.
Clean Antigravity-style chat loop with slash commands.
"""

from __future__ import annotations

import os
import sys
import json
import asyncio
from collections import deque
import signal
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import typer
from rich.text import Text

from secops_agent import __version__
from secops_agent.cli.attachments import parse_attach_argument
from secops_agent.cli.cancel import parse_cancel_argument
from secops_agent.cli.lessons import (
    format_end_of_mission_review,
    format_lessons_for_review,
    parse_lessons_command,
)
from secops_agent.cli.permissions import (
    PERMISSIONS_RULE_USAGE,
    normalize_permission_mode,
    plan_permission_command,
)
from secops_agent.cli.sandbox import parse_sandbox_argument
from secops_agent.cli.sessions import (
    build_session_summary,
    build_session_metadata,
    format_session_description,
    parse_export_argument,
    parse_load_argument,
    parse_save_argument,
    resolve_resume_target,
    resolve_session_model,
    should_autosave_session,
)
from secops_agent.cli.slash import parse_slash_command
from secops_agent.cli.surfaces import should_use_interactive_surface
from secops_agent.cli.tasks import parse_task_argument
from secops_agent.cli.tools import parse_tool_argument
from secops_agent.cli.workspace import parse_add_dir_argument
from secops_agent.config import settings
from secops_agent.core.extensions import build_skills_prompt, load_skills
from secops_agent.core.experience import ExperienceStore
from secops_agent.core.hooks import load_hooks
from secops_agent.core.llm import GeminiProvider
from secops_agent.core.mcp import load_mcp_config
from secops_agent.core.model_catalog import get_model_profile, selectable_models
from secops_agent.core.llm import Message
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext
from secops_agent.core.permissions import ApprovalDecision, PermissionDecision, PermissionResource
from secops_agent.core.planner import MissionPlanner
from secops_agent.core.preferences import load_model_preference, save_model_preference
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.sandbox import set_sandbox_enabled
from secops_agent.core.structured_memory import KnowledgeBase, StructuredMemory
from secops_agent.core.sudo import SudoAuthenticationDecision
from secops_agent.core.tools import registry
from secops_agent.core.agent import (
    ApprovalRequestEvent,
    ErrorEvent,
    SecOpsAgent,
    StatusEvent,
    SuggestedActionsEvent,
    SudoAuthenticationRequestEvent,
    TextEvent,
    ThinkingEvent,
    TokenUsageEvent,
    ToolCallEvent,
    ToolProgressEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.ui.renderer import Renderer
from secops_agent.ui.input_handler import InputHandler
from secops_agent.ui.animations import StartupAnimation
from secops_agent.ui.spool_display import spool_reference, supervised_detail_text
from secops_agent.ui.tool_display import format_tool_call_text, _looks_like_tool_failure
from secops_agent.ui.attachments import (
    AttachmentError,
    attach_file,
    build_attachment_model_parts,
    build_attachment_prompt_context,
)
from secops_agent.ui.runtime import RuntimeState, RuntimeTask
from secops_agent.utils.logger import logger

# Import tools to trigger registration
from secops_agent.tools import network, recon, web, exploit, crypto, forensics, exploitation

from secops_agent.ui.theme import friendly_model_name, get_header_banner
from secops_agent.ui.menu import switch_model_menu
from secops_agent.ui.overlay import OverlayChoice, choose_overlay
from secops_agent.ui.permissions_menu import switch_permissions_menu
from secops_agent.ui.commands import get_command

app = typer.Typer(
    help="SecOps Agent — AI-Powered Security Operations CLI",
    invoke_without_command=True,
    no_args_is_help=False,
)

def _list_saved_sessions() -> list[str]:
    d = settings.sessions_dir
    return sorted(f.name for f in d.iterdir() if f.is_file() and f.suffix == ".json") if d.exists() else []


def _session_path(name: str) -> Path:
    filename = f"{name}.json" if not name.endswith(".json") else name
    return settings.sessions_dir / filename


def _read_session_payload(name: str) -> object | None:
    path = _session_path(name)
    try:
        import json
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _session_summary(name: str) -> dict[str, object]:
    payload = _read_session_payload(name)
    path = _session_path(name)
    try:
        modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        modified_at = ""
    return build_session_summary(name, payload, modified_at=modified_at)


def _format_session_description(summary: dict[str, object]) -> str:
    return format_session_description(summary)


def _latest_saved_session() -> str | None:
    d = settings.sessions_dir
    if not d.exists():
        return None
    sessions = [f for f in d.iterdir() if f.is_file() and f.suffix == ".json"]
    if not sessions:
        return None
    return max(sessions, key=lambda f: f.stat().st_mtime).name


def _choose_saved_session(
    sessions: list[str],
    *,
    status_right: str = "",
    prompt_frame: bool = False,
) -> str | None:
    if not sessions:
        return None
    latest = _latest_saved_session()
    summaries = [_session_summary(session) for session in sessions]
    choices = [
        OverlayChoice(
            value=str(summary["name"]),
            label=str(summary["label"]),
            description=_format_session_description(summary),
            current=summary["name"] == latest,
        )
        for summary in summaries
    ]

    def on_delete(value: str) -> bool:
        path = _session_path(value)
        try:
            if path.exists():
                path.unlink()
                return True
        except OSError:
            pass
        return False

    return choose_overlay(
        "Resume Session",
        choices,
        status_right=status_right,
        prompt_frame=prompt_frame,
        show_descriptions=True,
        footer="Keyboard: ↑/↓ Navigate  enter Select  ctrl+delete Delete",
        on_delete=on_delete,
    )


def _new_auto_session_name() -> str:
    base = f"secops-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    candidate = base
    counter = 2
    while (settings.sessions_dir / f"{candidate}.json").exists():
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def _resolve_workspace_dirs(paths: list[Path] | None) -> list[Path]:
    resolved: list[Path] = []
    for raw_path in paths or []:
        path = raw_path.expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Workspace directory not found: {path}")
        final = path.resolve()
        if final not in resolved:
            resolved.append(final)
    return resolved


def _copy_memory(memory: ConversationMemory) -> ConversationMemory:
    copied = ConversationMemory()
    copied.messages = [Message.from_dict(message.to_dict()) for message in memory.messages]
    return copied


def _rewind_last_turn(memory: ConversationMemory) -> int:
    for index in range(len(memory.messages) - 1, -1, -1):
        if memory.messages[index].role == "user":
            removed = len(memory.messages) - index
            del memory.messages[index:]
            return removed
    removed = len(memory.messages)
    memory.clear()
    return removed


def _rebuild_artifacts_from_memory(runtime: RuntimeState, memory: ConversationMemory) -> None:
    runtime.artifacts.clear()
    runtime._next_artifact_id = 1
    for msg in memory.messages:
        if msg.role != "tool":
            continue
        for result in msg.tool_results:
            name = result.get("name", "tool")
            content = result.get("content", "")
            runtime.add_artifact(
                f"{name} result",
                "tool-result",
                str(content),
                source=name,
            )


def _sync_agent_structured_state(agent: SecOpsAgent) -> None:
    structured_memory = getattr(agent, "structured_memory", None)
    if structured_memory is not None:
        structured_memory.conversation = agent.memory
    result_parser = getattr(agent, "result_parser", None)
    if result_parser is not None and structured_memory is not None:
        result_parser.mission = structured_memory.mission


def _reset_agent_structured_state(agent: SecOpsAgent, name: str = "SecOps CLI session") -> None:
    mission = MissionContext(name=name)
    structured_memory = getattr(agent, "structured_memory", None)
    if structured_memory is None:
        agent.structured_memory = StructuredMemory(conversation=agent.memory, mission=mission)
    else:
        structured_memory.conversation = agent.memory
        structured_memory.mission = mission
        structured_memory.knowledge = KnowledgeBase()
    _sync_agent_structured_state(agent)


def _save_agent_session(
    agent: SecOpsAgent,
    name: str,
    *,
    metadata: dict[str, object] | None = None,
    runtime: RuntimeState | None = None,
) -> Path:
    metadata = metadata or _build_session_metadata(agent, name)
    return agent.memory.save_session(
        name,
        structured_memory=getattr(agent, "structured_memory", None),
        metadata=metadata,
        runtime_state=runtime,
    )


def _restore_model_from_session(agent: SecOpsAgent, name: str) -> None:
    llm = getattr(agent, "llm", None)
    if llm is None or not hasattr(llm, "set_model"):
        return
    payload = _read_session_payload(name)
    if not isinstance(payload, dict):
        return
    metadata = payload.get("metadata", {})
    selection = resolve_session_model(metadata)
    if not selection.raw_model:
        return
    try:
        llm.set_model(selection.raw_model, thinking_level=selection.thinking_level)
    except ValueError:
        logger.exception("Ignoring invalid session model metadata")


def _load_agent_session(
    agent: SecOpsAgent,
    name: str,
    *,
    runtime: RuntimeState | None = None,
    restore_model: bool = True,
) -> bool:
    loaded = agent.memory.load_session(
        name,
        structured_memory=getattr(agent, "structured_memory", None),
        runtime_state=runtime,
    )
    if loaded:
        _sync_agent_structured_state(agent)
        if restore_model:
            _restore_model_from_session(agent, name)
    return loaded


def _load_runtime_from_session(runtime: RuntimeState, name: str) -> None:
    payload = _read_session_payload(name)
    if isinstance(payload, dict):
        runtime_data = payload.get("runtime")
        if isinstance(runtime_data, dict):
            runtime.load_session_dict(runtime_data)


def _restore_runtime_artifacts_after_load(runtime: RuntimeState, memory: ConversationMemory) -> None:
    if not runtime.artifacts:
        _rebuild_artifacts_from_memory(runtime, memory)


def _should_capture_response_artifact(text: str) -> bool:
    clean = text.strip()
    if len(clean) >= 300:
        return True
    return "```" in clean or "\n#" in clean or "| ---" in clean


def _prompt_with_attachments(user_input: str, runtime: RuntimeState) -> str:
    attachment_context = build_attachment_prompt_context(runtime)
    if not attachment_context:
        return user_input
    return (
        f"{user_input}\n\n"
        "[SecOps attached evidence]\n"
        f"{attachment_context}"
    )


def _tool_result_spool_path(result: object) -> Path | None:
    metadata = getattr(result, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    raw_path = metadata.get("spool_path")
    if not raw_path:
        return None
    try:
        path = Path(str(raw_path)).expanduser()
    except (TypeError, ValueError):
        return None
    return path if path.exists() and path.is_file() else None


async def _track_agent_artifacts(
    runtime: RuntimeState,
    event_stream: AsyncIterator[object],
) -> AsyncIterator[object]:
    response_parts: list[str] = []
    tool_calls: dict[str, tuple[str, dict]] = {}

    async for event in event_stream:
        if isinstance(event, TextEvent) and event.content:
            response_parts.append(event.content)
        elif isinstance(event, ToolCallEvent):
            tool_calls[event.id] = (event.name, dict(event.arguments or {}))
        elif isinstance(event, ToolResultEvent):
            content = event.result.output or event.result.error or ""
            if str(content).strip():
                text_failure = event.result.success and _looks_like_tool_failure(str(content))
                status = "result" if event.result.success and not text_failure else "error"
                call_name, call_args = tool_calls.get(event.id, (event.name, {}))
                runtime.add_artifact(
                    f"{format_tool_call_text(call_name, call_args)} {status}",
                    "tool-result",
                    str(content),
                    source=event.name,
                    path=_tool_result_spool_path(event.result),
                    metadata=getattr(event.result, "metadata", {}) or {},
                )
        yield event

    response = "".join(response_parts).strip()
    if _should_capture_response_artifact(response):
        runtime.add_artifact(
            "Assistant response",
            "response",
            response,
            source="assistant",
        )


def _permission_label(agent: SecOpsAgent, runtime: RuntimeState | None = None) -> str:
    if runtime and runtime.permission_mode != "request-review":
        return runtime.permission_mode
    summary = agent.permissions.summary()
    counts = {name: len(rules) for name, rules in summary.items()}
    total = sum(counts.values())
    if total == 0:
        return "perm default"
    parts = []
    if counts["allow"]:
        parts.append(f"A{counts['allow']}")
    if counts["ask"]:
        parts.append(f"K{counts['ask']}")
    if counts["deny"]:
        parts.append(f"D{counts['deny']}")
    return "perm " + "/".join(parts)


def _statusline_payload(agent: SecOpsAgent, runtime: RuntimeState) -> dict[str, object]:
    stats = agent.memory.get_stats()
    return {
        "cwd": os.getcwd().replace(os.path.expanduser("~"), "~"),
        "tokens": stats["estimated_tokens"],
        "tools": len(registry.list_tools()),
        "tasks": len(runtime.running_tasks()),
        "dirs": len(runtime.workspace_dirs),
        "profile": "fast" if runtime.fast_mode else "standard",
        "sandbox": runtime.sandbox_enabled,
        "permissions": _permission_label(agent, runtime),
        "autonomy": agent.autonomy_posture(),
        "phase": agent.current_phase(),
        "state": runtime.agent_state,
    }


def _apply_permission_mode(mode: str, agent: SecOpsAgent, runtime: RuntimeState) -> None:
    agent.permissions.reset_session()
    runtime.permission_mode = mode
    # Keep autonomy in step with the permission mode: free-execution modes imply
    # an authorised target and must expose high-risk tool schemas to the model.
    agent.set_autonomy_for_permission_mode(mode)

    if mode == "request-review":
        runtime.sandbox_enabled = False
    elif mode == "proceed-in-sandbox":
        runtime.sandbox_enabled = True
        agent.permissions.remember(PermissionResource("command", "*"), PermissionDecision.ALLOW)
        agent.permissions.remember(PermissionResource("tool", "run_shell"), PermissionDecision.ALLOW)
    elif mode == "always-proceed":
        runtime.sandbox_enabled = False
        agent.permissions.remember(PermissionResource("command", "*"), PermissionDecision.ALLOW)
        agent.permissions.remember(PermissionResource("tool", "*"), PermissionDecision.ALLOW)
    elif mode == "strict":
        runtime.sandbox_enabled = False
        agent.permissions.remember(PermissionResource("command", "*"), PermissionDecision.ASK)
        agent.permissions.remember(PermissionResource("tool", "*"), PermissionDecision.ASK)

    set_sandbox_enabled(runtime.sandbox_enabled)


def _set_response_profile(agent: SecOpsAgent, runtime: RuntimeState, fast_mode: bool) -> str:
    runtime.fast_mode = fast_mode
    if runtime.fast_mode:
        settings.MODEL_TEMPERATURE = 0.2
        agent.max_iterations = 4
        return "Response Profile set to fast"
    settings.MODEL_TEMPERATURE = runtime.original_temperature
    agent.max_iterations = runtime.original_max_iterations
    return "Response Profile set to standard"


def _persist_model_selection(agent: SecOpsAgent, raw_model: str) -> None:
    profile = get_model_profile(agent.llm.model_name)
    thinking_level = (
        getattr(agent.llm, "current_thinking_level", "")
        if profile.supports_thinking
        else ""
    )
    try:
        save_model_preference(
            raw_model,
            resolved_model=agent.llm.model_name,
            thinking_level=thinking_level,
            auto_routing=getattr(agent.llm, "model_auto_routing", False),
        )
    except OSError:
        logger.exception("Unable to persist model preference")


def _set_model_selection(
    agent: SecOpsAgent,
    model: str,
    thinking: str | None = None,
    *,
    persist: bool = False,
) -> str:
    _, profile = agent.llm.set_model(model, thinking_level=thinking)
    route = "auto routing" if getattr(agent.llm, "model_auto_routing", False) else "manual"
    current_thinking = getattr(agent.llm, "current_thinking_level", "")
    if profile.supports_thinking:
        thinking_label = "High" if current_thinking == "high" else "Off"
    else:
        thinking_label = "Default"
    if persist:
        _persist_model_selection(agent, model)
    return f"Model set to {profile.label} ({thinking_label}) - {route}"


def _startup_model_selection(cli_model: str | None) -> tuple[str | None, str | None]:
    if cli_model:
        return cli_model, None
    preference = load_model_preference()
    raw_model = str(preference.get("raw_model") or "").strip()
    thinking = str(preference.get("thinking_level") or "").strip()
    return raw_model or None, thinking or None


def _has_autosave_activity(agent: SecOpsAgent, runtime: RuntimeState) -> bool:
    structured_memory = getattr(agent, "structured_memory", None)
    mission = getattr(structured_memory, "mission", None)
    return should_autosave_session(
        message_count=len(agent.memory.get_all_messages()),
        artifact_count=len(runtime.artifacts),
        mission=mission,
    )


def _build_session_metadata(
    agent: SecOpsAgent,
    session_name: str,
    *,
    auto_saved: bool = False,
    reason: str = "manual",
) -> dict[str, object]:
    llm = getattr(agent, "llm", None)
    return build_session_metadata(
        session_name,
        auto_saved=auto_saved,
        reason=reason,
        model_name=getattr(llm, "model_name", ""),
        thinking_level=getattr(llm, "current_thinking_level", ""),
        model_auto_routing=getattr(llm, "model_auto_routing", False),
        cwd=os.getcwd(),
    )


def _autosave_agent_session(
    agent: SecOpsAgent,
    runtime: RuntimeState,
    session_name: str,
    *,
    reason: str = "exit",
) -> Path | None:
    if not _has_autosave_activity(agent, runtime):
        return None
    metadata = _build_session_metadata(
        agent,
        session_name,
        auto_saved=True,
        reason=reason,
    )
    return _save_agent_session(agent, session_name, metadata=metadata, runtime=runtime)


def _safe_autosave_agent_session(
    agent: SecOpsAgent,
    runtime: RuntimeState,
    session_name: str,
    *,
    reason: str = "exit",
) -> Path | None:
    try:
        return _autosave_agent_session(agent, runtime, session_name, reason=reason)
    except OSError:
        logger.exception("Unable to autosave session")
        return None


def _model_from_display_name(display_name: str) -> str | None:
    for model in selectable_models():
        if friendly_model_name(model) == display_name:
            return model
    return None


def _new_runtime(
    agent: SecOpsAgent,
    *,
    permission_mode: str = "request-review",
    sandbox_enabled: bool = False,
    workspace_dirs: list[Path] | None = None,
) -> RuntimeState:
    runtime = RuntimeState(
        original_temperature=settings.MODEL_TEMPERATURE,
        original_max_iterations=agent.max_iterations,
        allow_automatic_planner_execution=agent.allow_automatic_planner_execution,
    )
    for path in workspace_dirs or []:
        runtime.add_workspace_dir(path)
    _apply_permission_mode(permission_mode, agent, runtime)
    if sandbox_enabled:
        runtime.sandbox_enabled = True
        set_sandbox_enabled(True)
    return runtime


def _apply_loaded_runtime_controls(agent: SecOpsAgent, runtime: RuntimeState) -> None:
    try:
        mode = normalize_permission_mode(runtime.permission_mode)
    except ValueError:
        mode = "request-review"
    restored_sandbox = runtime.sandbox_enabled
    _apply_permission_mode(mode, agent, runtime)
    if restored_sandbox:
        runtime.sandbox_enabled = True
        set_sandbox_enabled(True)
    agent.allow_automatic_planner_execution = runtime.allow_automatic_planner_execution


def _render_header_banner(renderer: Renderer, model_name: str) -> None:
    renderer.console.print(Text.from_ansi(get_header_banner(model_name)))


def _export_conversation(memory: ConversationMemory, name: str) -> Path:
    import json
    export_dir = Path.home() / ".secops_agent" / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{name}.md" if not name.endswith(".md") else name
    filepath = export_dir / filename

    lines = [
        f"# SecOps Agent — Session Export",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Messages:** {len(memory.messages)}", "", "---", "",
    ]
    for msg in memory.messages:
        if msg.role == "user":
            lines += [f"## User", "", msg.content, ""]
        elif msg.role == "model":
            lines += [f"## SecOps Agent", "", msg.content, ""]
            for tc in msg.tool_calls:
                lines += [f"**Tool:** `{tc['name']}`", f"```json", json.dumps(tc.get("arguments", {}), indent=2), "```", ""]
        elif msg.role == "tool":
            for tr in msg.tool_results:
                content = tr.get("content", "")[:3000]
                lines += [f"### Tool: `{tr['name']}`", "```", content, "```", ""]
        lines.append("---\n")

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath


def _refresh_skills(runtime: RuntimeState, agent: SecOpsAgent) -> int:
    runtime.skills = load_skills()
    context = build_skills_prompt(runtime.skills)
    if hasattr(agent.llm, "set_extension_context"):
        agent.llm.set_extension_context(context)
    return len(runtime.skills)


def _refresh_hooks(runtime: RuntimeState, agent: SecOpsAgent) -> int:
    runtime.hooks = load_hooks()
    agent.hooks = runtime.hooks
    return len(runtime.hooks.enabled_hooks)


def _refresh_mcp(runtime: RuntimeState) -> int:
    runtime.mcp = load_mcp_config()
    return len(runtime.mcp.enabled_servers)


def _load_runtime_extensions(runtime: RuntimeState, agent: SecOpsAgent) -> None:
    _refresh_skills(runtime, agent)
    _refresh_hooks(runtime, agent)
    _refresh_mcp(runtime)


async def _start_mcp(runtime: RuntimeState) -> int:
    return await runtime.mcp_runtime.start(runtime.mcp, registry)


async def _stop_mcp(runtime: RuntimeState) -> int:
    return await runtime.mcp_runtime.stop(registry)


def _task_transcript(task: RuntimeTask) -> str:
    sections = [
        f"Task: {task.id} {task.name}",
        f"Status: {task.status}",
        f"Elapsed: {task.elapsed:.2f}s",
    ]
    if task.query:
        sections.extend(["", "Query:", task.query])
    if task.detail:
        sections.extend(["", "Detail:", task.detail])
    log_path = spool_reference(getattr(task, "metadata", None))
    if log_path:
        sections.extend(["", "Log file:", log_path])
    if task.error:
        sections.extend(["", "Error:", task.error])
    if task.output:
        sections.extend(["", "Output:", supervised_detail_text(getattr(task, "metadata", None), task.output)])
    if task.log:
        sections.extend(["", "Log:", *task.log])
    return "\n".join(sections)


async def _run_side_question(task: RuntimeTask, side_agent: SecOpsAgent, query: str):
    """Run a side agent without writing to the interactive terminal."""
    text_parts: list[str] = []
    tool_outputs: list[str] = []

    try:
        task.detail = "thinking"
        async for event in side_agent.stream_response(query):
            if isinstance(event, ThinkingEvent):
                task.detail = "thinking"
            elif isinstance(event, TextEvent):
                if event.content:
                    text_parts.append(event.content)
                    task.detail = "answering"
            elif isinstance(event, ToolCallEvent):
                task.detail = f"requested {event.name}"
                task.append_log(f"tool requested: {event.name} {event.arguments}")
            elif isinstance(event, ApprovalRequestEvent):
                task.detail = f"denied permission for {event.tool_name}"
                task.append_log(
                    f"permission denied in background: {event.resource.value}"
                )
                if event.approval_future and not event.approval_future.done():
                    event.approval_future.set_result(ApprovalDecision(allowed=False))
            elif isinstance(event, SudoAuthenticationRequestEvent):
                task.detail = "sudo authentication denied in background"
                task.append_log("sudo authentication denied in background task")
                if event.authentication_future and not event.authentication_future.done():
                    event.authentication_future.set_result(
                        SudoAuthenticationDecision(
                            False,
                            "sudo authentication is not available in background tasks",
                        )
                    )
            elif isinstance(event, ToolStartEvent):
                task.detail = f"running {event.name}"
            elif isinstance(event, ToolProgressEvent):
                progress = event.phase
                if event.detail:
                    progress += f" · {event.detail}"
                task.detail = f"{event.name}: {progress}"
            elif isinstance(event, ToolResultEvent):
                content = event.result.output or event.result.error or ""
                tool_outputs.append(f"### {event.name}\n{content}")
                if event.result.success:
                    task.detail = f"{event.name} done"
                    task.append_log(f"tool done: {event.name} ({event.result.execution_time:.2f}s)")
                else:
                    task.detail = f"{event.name} failed"
                    task.append_log(f"tool failed: {event.name}: {content[:180]}")
            elif isinstance(event, SuggestedActionsEvent):
                labels = [getattr(action, "title", "Next action") for action in event.actions[:5]]
                if labels:
                    task.detail = "suggested next actions"
                    task.append_log("suggested: " + "; ".join(labels))
            elif isinstance(event, StatusEvent):
                task.detail = event.message[:180]
            elif isinstance(event, TokenUsageEvent):
                task.append_log(f"tokens: {event.input_tokens} in / {event.output_tokens} out")
            elif isinstance(event, ErrorEvent):
                task.append_log(f"error: {event.error}")
                raise RuntimeError(event.error)

        answer = "".join(text_parts).strip()
        output = answer
        if tool_outputs:
            output = f"{answer}\n\n" + "\n\n".join(tool_outputs) if answer else "\n\n".join(tool_outputs)
        task.finish("done", output=output or "No output.", detail="completed")
    except asyncio.CancelledError:
        task.finish("cancelled", detail="cancelled by user")
        task.append_log("cancelled by user")
        raise
    except Exception as exc:
        task.finish("failed", error=str(exc), output="\n".join(text_parts).strip(), detail="failed")
        task.append_log(f"failed: {exc}")


def _render_queued_input_notice(renderer: Renderer, remaining: int) -> None:
    """Signal that an instruction typed during the previous turn is now running."""
    suffix = f" · {remaining} en file" if remaining else ""
    renderer.render_status(f"⏳ Instruction mise en file traitée{suffix}")


async def _render_interactive_turn(
    agent: SecOpsAgent,
    renderer: Renderer,
    runtime: RuntimeState,
    user_input: str,
) -> list[str]:
    input_lines = len(str(user_input).splitlines() or [""])
    runtime.advance_ctrl_o_anchor_lines(1 + input_lines)
    renderer.render_user_input(user_input, trailing_blank=False)
    agent_prompt = _prompt_with_attachments(user_input, runtime)
    attachment_parts = build_attachment_model_parts(runtime)
    event_stream = _track_agent_artifacts(
        runtime,
        agent.stream_response(agent_prompt, attachments=attachment_parts),
    )
    runtime.agent_state = "thinking"
    try:
        # Returns any instructions the user typed while the agent was streaming
        # (R1 / Example E), so the loop can process them instead of dropping them.
        queued = await renderer.render_agent_stream(
            event_stream,
            status_right=friendly_model_name(agent.llm.model_name),
            memory=agent.memory,
            runtime=runtime,
        )
    finally:
        runtime.agent_state = "idle"
    return list(queued or [])


async def _run_print_prompt(
    agent: SecOpsAgent,
    runtime: RuntimeState,
    prompt: str,
    timeout_seconds: float,
    output_format: str = "text",
) -> None:
    clean_prompt = prompt.strip()
    if not clean_prompt:
        raise ValueError("--print requires a non-empty prompt.")
    if timeout_seconds <= 0:
        raise ValueError("--print-timeout must be greater than zero.")

    json_mode = str(output_format or "text").strip().lower() == "json"
    _load_runtime_extensions(runtime, agent)

    # JSON mode collects a lossless record (full tool outputs included) instead of
    # the collapsed text stream — the machine-readable counterpart Antigravity CLI
    # exposes via `--output-format json`.
    collected_text: list[str] = []
    collected_tools: list[dict[str, Any]] = []
    collected_actions: list[str] = []
    error_text: str | None = None

    async def consume() -> bool:
        nonlocal error_text
        emitted_text = False
        attachment_parts = build_attachment_model_parts(runtime)
        event_stream = _track_agent_artifacts(
            runtime,
            agent.stream_response(
                _prompt_with_attachments(clean_prompt, runtime),
                attachments=attachment_parts,
            ),
        )
        async for event in event_stream:
            if isinstance(event, TextEvent) and event.content:
                if json_mode:
                    collected_text.append(event.content)
                else:
                    sys.stdout.write(event.content)
                    sys.stdout.flush()
                emitted_text = True
            elif isinstance(event, ToolResultEvent):
                if json_mode:
                    result = event.result
                    collected_tools.append({
                        "name": event.name,
                        "success": bool(getattr(result, "success", False)),
                        "output": str(getattr(result, "output", "") or ""),
                        "error": getattr(result, "error", None),
                        "execution_time": float(getattr(result, "execution_time", 0.0) or 0.0),
                    })
            elif isinstance(event, SuggestedActionsEvent):
                if json_mode:
                    collected_actions.extend(
                        getattr(action, "title", "Next action") for action in event.actions[:5]
                    )
                else:
                    lines = ["\nSuggested next actions:"]
                    for index, action in enumerate(event.actions[:5], 1):
                        lines.append(f"{index}. {getattr(action, 'title', 'Next action')}")
                    lines.append("Reply with a number or describe what to do next.")
                    sys.stdout.write("\n".join(lines) + "\n")
                    sys.stdout.flush()
                    emitted_text = True
            elif isinstance(event, ApprovalRequestEvent):
                if event.approval_future and not event.approval_future.done():
                    event.approval_future.set_result(ApprovalDecision(allowed=False))
                if not json_mode:
                    typer.echo(
                        f"Permission denied in --print mode: {event.resource.value}",
                        err=True,
                    )
            elif isinstance(event, ErrorEvent):
                if json_mode:
                    error_text = str(event.error)
                    break
                raise RuntimeError(event.error)
        return emitted_text

    try:
        emitted = await asyncio.wait_for(consume(), timeout=timeout_seconds)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(f"--print timed out after {timeout_seconds:g}s.") from exc

    if json_mode:
        payload = {
            "prompt": clean_prompt,
            "model": getattr(agent.llm, "model_name", ""),
            "response": "".join(collected_text).strip(),
            "tools": collected_tools,
            "suggested_actions": collected_actions,
            "error": error_text,
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        if error_text:
            raise RuntimeError(error_text)
        return

    if emitted:
        sys.stdout.write("\n")
        sys.stdout.flush()


async def run_chat_loop(
    agent: SecOpsAgent,
    renderer: Renderer,
    input_handler: InputHandler,
    skip_animation: bool = False,
    *,
    initial_prompt: str = "",
    permission_mode: str = "request-review",
    sandbox_enabled: bool = False,
    workspace_dirs: list[Path] | None = None,
    preloaded_session: str = "",
):
    runtime = _new_runtime(
        agent,
        permission_mode=permission_mode,
        sandbox_enabled=sandbox_enabled,
        workspace_dirs=workspace_dirs,
    )
    auto_session_name = preloaded_session or _new_auto_session_name()
    if preloaded_session:
        _load_runtime_from_session(runtime, preloaded_session)
        _apply_loaded_runtime_controls(agent, runtime)
        _restore_runtime_artifacts_after_load(runtime, agent.memory)
    _load_runtime_extensions(runtime, agent)

    # Startup
    startup = StartupAnimation(console=renderer.console, tool_count=len(registry.list_tools()))
    await startup.play(skip=skip_animation)

    renderer.console.print()
    _render_header_banner(renderer, agent.llm.model_name)
    renderer.console.print()

    if preloaded_session:
        renderer.render_success(f"Session '{preloaded_session.replace('.json', '')}' loaded.")
        renderer.render_session_transcript(agent.memory)

    clean_initial_prompt = initial_prompt.strip()
    # Instructions typed while the agent is streaming are captured and processed
    # sequentially here instead of being dropped (R1 / Example E / gap G3).
    pending_inputs: deque[str] = deque()
    if clean_initial_prompt:
        pending_inputs.extend(
            await _render_interactive_turn(agent, renderer, runtime, clean_initial_prompt)
        )

    try:
        while True:
            try:
                if pending_inputs:
                    # Process an instruction the user typed during the last turn
                    # before blocking on a fresh prompt.
                    user_input = pending_inputs.popleft()
                    _render_queued_input_notice(renderer, len(pending_inputs))
                else:
                    stats = agent.memory.get_stats()
                    input_handler.update_context(
                        model_name=agent.llm.model_name,
                        turn_count=agent.turn_count,
                        memory=agent.memory,
                        console=renderer.console,
                        runtime=runtime,
                        statusline=_statusline_payload(agent, runtime),
                    )

                    user_input = await input_handler.get_input(model_name=agent.llm.model_name)

                if user_input is None:
                    continue
                runtime.reset_ctrl_o_surface()
    
                # Handle '?' shortcut guide
                if user_input == InputHandler.SHORTCUT_REQUEST:
                    renderer.render_help(
                        initial_view="shortcuts",
                        status_right=friendly_model_name(agent.llm.model_name),
                        prompt_frame=True,
                    )
                    continue
                if user_input == InputHandler.ARTIFACT_REVIEW_REQUEST:
                    renderer.render_artifacts(
                        runtime,
                        transient=True,
                        status_right=friendly_model_name(agent.llm.model_name),
                    )
                    continue
    
                stripped = user_input.strip()
                if not stripped:
                    continue
    
                # ── Slash commands ────────────────────────────────────
                if stripped.startswith("/"):
                    slash = parse_slash_command(stripped, get_command)
                    cmd = slash.command
                    arg = slash.argument
                    canonical_cmd = slash.canonical_command
                    interactive_surface = should_use_interactive_surface(
                        canonical_cmd,
                        arg,
                        stdin_isatty=sys.stdin.isatty(),
                        stdout_isatty=sys.stdout.isatty(),
                    )
                    if not interactive_surface:
                        renderer.render_user_input(stripped, trailing_blank=False, separator=False)

                    if canonical_cmd == "/exit":
                        _store = getattr(agent, "experience_store", None)
                        if _store is not None:
                            try:
                                _review = format_end_of_mission_review(
                                    _store.load(limit=None),
                                    session_name=agent._mission_session_name(),
                                )
                            except OSError:
                                _review = ""
                            if _review:
                                renderer.render_status(_review)
                        renderer.render_status("Goodbye.")
                        break
                    elif canonical_cmd == "/help":
                        renderer.render_help(
                            initial_view="general",
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /help command")
                    elif canonical_cmd == "/clear":
                        agent.memory.clear()
                        runtime.artifacts.clear()
                        runtime._next_artifact_id = 1
                        agent.permissions.reset_session()
                        _reset_agent_structured_state(agent)
                        auto_session_name = _new_auto_session_name()
                        os.system("clear" if os.name != "nt" else "cls")
                        _render_header_banner(renderer, agent.llm.model_name)
                        renderer.render_welcome()
                    elif canonical_cmd == "/tools":
                        renderer.render_tools(
                            registry.list_tools(),
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /tools command")
                    elif canonical_cmd == "/tool":
                        tool_arg = parse_tool_argument(arg)
                        if tool_arg.action == "list":
                            renderer.render_tools(
                                registry.list_tools(),
                                transient=interactive_surface,
                                status_right=friendly_model_name(agent.llm.model_name),
                                prompt_frame=interactive_surface,
                            )
                            if interactive_surface:
                                renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                                renderer.render_status("Exited /tool command")
                            continue
                        tool_def = registry.get_tool(tool_arg.tool_name)
                        if tool_def is None:
                            renderer.render_error(f"Unknown tool: {tool_arg.tool_name}")
                            continue
                        renderer.render_tool_detail(tool_def)
                    elif canonical_cmd == "/history":
                        s = agent.memory.get_stats()
                        renderer.render_status(
                            f"Messages: {s['total_messages']}  "
                            f"(user: {s['user_messages']}, agent: {s['assistant_messages']}, tool: {s['tool_messages']})  "
                            f"~{s['estimated_tokens']:,} tokens"
                        )
                    elif canonical_cmd == "/lessons":
                        store = getattr(agent, "experience_store", None)
                        lessons_cmd = parse_lessons_command(arg)
                        if store is None:
                            renderer.render_error("No experience store configured.")
                        elif lessons_cmd.action == "error":
                            renderer.render_error(lessons_cmd.error)
                        elif lessons_cmd.action == "list":
                            renderer.render_status(format_lessons_for_review(store.load(limit=None)))
                        else:  # review: promote a lesson (human validation, §5.2)
                            result = store.review_lesson(
                                lessons_cmd.lesson_id,
                                status=lessons_cmd.status,
                                note=lessons_cmd.note,
                                dry_run=False,
                            )
                            if result.changed:
                                msg = f"Lesson {lessons_cmd.lesson_id} marked '{lessons_cmd.status}'."
                                if result.backup_path:
                                    msg += f"  (backup: {result.backup_path})"
                                renderer.render_success(msg)
                            else:
                                renderer.render_error(f"No lesson with id '{lessons_cmd.lesson_id}'.")
                    elif canonical_cmd == "/save":
                        save_arg = parse_save_argument(arg)
                        if save_arg.error:
                            renderer.render_error(save_arg.error)
                            continue
                        path = _save_agent_session(agent, save_arg.name, runtime=runtime)
                        auto_session_name = save_arg.name
                        renderer.render_success(f"Saved to {path}")
                    elif canonical_cmd == "/load":
                        load_arg = parse_load_argument(arg)
                        if load_arg.error:
                            renderer.render_error(load_arg.error)
                            continue
                        if _load_agent_session(agent, load_arg.name, runtime=runtime):
                            _apply_loaded_runtime_controls(agent, runtime)
                            _restore_runtime_artifacts_after_load(runtime, agent.memory)
                            auto_session_name = load_arg.name
                            renderer.render_success(f"Session '{load_arg.name}' loaded.")
                            renderer.render_session_transcript(agent.memory)
                        else:
                            renderer.render_error(f"Session '{load_arg.name}' not found.")
                    elif canonical_cmd == "/sessions":
                        renderer.render_sessions_list(_list_saved_sessions())
                    elif canonical_cmd == "/export":
                        export_arg = parse_export_argument(arg)
                        path = _export_conversation(agent.memory, export_arg.name)
                        runtime.add_artifact(
                            path.name,
                            "export",
                            path.read_text(encoding="utf-8"),
                            source="/export",
                            path=path,
                        )
                        renderer.render_success(f"Exported to {path}")
                    elif canonical_cmd == "/context":
                        s = agent.memory.get_stats()
                        renderer.render_context(
                            model=agent.llm.model_name,
                            total_messages=s["total_messages"],
                            user_messages=s["user_messages"],
                            assistant_messages=s["assistant_messages"],
                            tool_messages=s["tool_messages"],
                            estimated_tokens=s["estimated_tokens"],
                            tools_count=len(registry.list_tools()),
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /context command")
                    elif canonical_cmd == "/add-dir":
                        add_dir_arg = parse_add_dir_argument(arg, cwd=Path.cwd())
                        if add_dir_arg.error or add_dir_arg.path is None:
                            renderer.render_error(add_dir_arg.error)
                            continue
                        path = add_dir_arg.path
                        added = runtime.add_workspace_dir(path)
                        if added:
                            renderer.render_success(f"Added workspace directory: {path.resolve()}")
                        else:
                            renderer.render_status(f"Already in workspace: {path.resolve()}")
                        renderer.render_workspace_dirs(runtime.workspace_dirs)
                    elif canonical_cmd == "/agents":
                        renderer.render_agents(
                            runtime,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /agents command")
                    elif canonical_cmd == "/btw":
                        if not arg:
                            renderer.render_error("Usage: /btw <query>")
                            continue
                        task = runtime.add_task(
                            "side question",
                            "running",
                            arg[:80],
                            kind="side-agent",
                            query=arg,
                        )
                        side_memory = _copy_memory(agent.memory)
                        side_agent = SecOpsAgent(
                            llm=agent.llm,
                            registry=registry,
                            memory=side_memory,
                            permissions=agent.permissions,
                            hooks=agent.hooks,
                            max_iterations=agent.max_iterations,
                        )
                        task.handle = asyncio.create_task(_run_side_question(task, side_agent, arg))
                        renderer.render_success(f"Background task {task.id} started.")
                        renderer.render_status(f"Background task {task.id} is running.")
                    elif canonical_cmd == "/fast":
                        message = _set_response_profile(agent, runtime, not runtime.fast_mode)
                        if runtime.fast_mode:
                            renderer.render_success(f"{message}: shorter loops, lower temperature.")
                        else:
                            renderer.render_success(f"{message}: standard reasoning profile restored.")
                    elif canonical_cmd == "/config":
                        selection = renderer.render_config(
                            model=agent.llm.model_name,
                            timeout=settings.TOOL_TIMEOUT,
                            max_tokens=settings.MODEL_MAX_TOKENS,
                            log_file=settings.LOG_FILE,
                            runtime=runtime,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            if not selection:
                                renderer.render_status(f"Exited {cmd} command")
                                continue
    
                            selected_label = selection.item.label
                            selected_value = selection.value
                            if selected_label == "Response Profile" and selected_value:
                                renderer.render_command_result(
                                    _set_response_profile(agent, runtime, selected_value == "fast")
                                )
                            elif selected_label == "Model" and selected_value:
                                model_key = _model_from_display_name(selected_value)
                                if not model_key:
                                    renderer.render_error(f"Unknown model: {selected_value}")
                                else:
                                    try:
                                        renderer.render_command_result(_set_model_selection(agent, model_key, persist=True))
                                    except ValueError as exc:
                                        renderer.render_error(str(exc))
                            elif selected_label == "Tool Permission" and selected_value:
                                _apply_permission_mode(selected_value, agent, runtime)
                                renderer.render_command_result(f"Permission mode set to {selected_value}")
                            elif selected_label == "Sandbox Mode" and selected_value:
                                runtime.sandbox_enabled = selected_value == "on"
                                set_sandbox_enabled(runtime.sandbox_enabled)
                                renderer.render_command_result(f"Sandbox Mode set to {selected_value}")
                            else:
                                renderer.render_status(f"{selected_label} is read-only in this session")
                    elif canonical_cmd == "/keybindings":
                        renderer.render_keybindings(
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /keybindings command")
                    elif canonical_cmd == "/trajectory":
                        renderer.render_trajectory(agent.memory, runtime)
                    elif canonical_cmd == "/artifact":
                        renderer.render_artifacts(
                            runtime,
                            arg,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /artifact command")
                    elif canonical_cmd == "/attach":
                        attach_arg = parse_attach_argument(arg)
                        if attach_arg.action == "list":
                            renderer.render_attachments(
                                runtime,
                                transient=interactive_surface,
                                status_right=friendly_model_name(agent.llm.model_name),
                            )
                            if interactive_surface:
                                renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                                renderer.render_status(f"Exited {cmd} command")
                            continue
                        try:
                            artifact = attach_file(runtime, attach_arg.argument, cwd=Path.cwd())
                        except AttachmentError as exc:
                            renderer.render_error(str(exc))
                            continue
                        renderer.render_success(f"Attached {artifact.id}: {artifact.title}")
                    elif canonical_cmd == "/auto":
                        arg_lower = arg.lower().strip()
                        if arg_lower == "on":
                            runtime.allow_automatic_planner_execution = True
                            agent.allow_automatic_planner_execution = True
                            renderer.render_success("Automatic planner execution enabled.")
                        elif arg_lower == "off":
                            runtime.allow_automatic_planner_execution = False
                            agent.allow_automatic_planner_execution = False
                            renderer.render_success("Automatic planner execution disabled.")
                        elif not arg_lower:
                            runtime.allow_automatic_planner_execution = not runtime.allow_automatic_planner_execution
                            agent.allow_automatic_planner_execution = runtime.allow_automatic_planner_execution
                            status_str = "enabled" if runtime.allow_automatic_planner_execution else "disabled"
                            renderer.render_success(f"Automatic planner execution {status_str}.")
                        else:
                            renderer.render_error("Usage: /auto [on|off]")
                    elif canonical_cmd == "/permissions":
                        permission_plan = plan_permission_command(arg, interactive_surface=interactive_surface)
                        if permission_plan.action == "menu":
                            new_mode = switch_permissions_menu(
                                runtime.permission_mode,
                                status_right=friendly_model_name(agent.llm.model_name),
                                prompt_frame=True,
                            )
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            if new_mode:
                                _apply_permission_mode(new_mode, agent, runtime)
                                renderer.render_command_result(f"Permission mode set to {new_mode}")
                            else:
                                renderer.render_status(f"Exited {cmd} command")
                        elif permission_plan.action == "clear":
                            agent.permissions.reset_session()
                            runtime.permission_mode = "request-review"
                            renderer.render_success("Session permission rules cleared.")
                        elif permission_plan.action == "rule":
                            permission_arg = permission_plan.argument
                            resource = agent.permissions.parse_resource(permission_arg.resource_text)
                            if not resource:
                                renderer.render_error(PERMISSIONS_RULE_USAGE)
                                continue
                            runtime.permission_mode = "request-review"
                            agent.permissions.remember(resource, PermissionDecision(permission_arg.action))
                            renderer.render_success(
                                f"Permission rule set: {permission_arg.action} {resource.value}"
                            )
                        elif permission_plan.action == "invalid":
                            renderer.render_error(permission_plan.argument.error)
                            continue
                        if permission_plan.render_policy:
                            renderer.render_permissions(
                                registry.list_tools(),
                                agent.permissions,
                                current_mode=runtime.permission_mode,
                            )
                    elif canonical_cmd == "/sandbox":
                        sandbox_arg = parse_sandbox_argument(arg)
                        if sandbox_arg.error:
                            renderer.render_error(sandbox_arg.error)
                            continue
                        if sandbox_arg.enabled is True:
                            runtime.sandbox_enabled = sandbox_arg.enabled
                            set_sandbox_enabled(runtime.sandbox_enabled)
                            renderer.render_success("Sandbox command guard enabled.")
                        elif sandbox_arg.enabled is False:
                            runtime.sandbox_enabled = sandbox_arg.enabled
                            set_sandbox_enabled(runtime.sandbox_enabled)
                            renderer.render_success("Sandbox command guard disabled.")
                        renderer.render_sandbox(runtime)
                    elif canonical_cmd == "/statusline":
                        s = agent.memory.get_stats()
                        renderer.render_statusline(
                            model=agent.llm.model_name,
                            turn_count=agent.turn_count,
                            estimated_tokens=s["estimated_tokens"],
                            tools_count=len(registry.list_tools()),
                            runtime=runtime,
                            permissions=agent.permissions,
                        )
                    elif canonical_cmd == "/diff":
                        renderer.render_diff()
                    elif canonical_cmd == "/tasks":
                        renderer.render_tasks(runtime)
                    elif canonical_cmd == "/task":
                        task_arg = parse_task_argument(arg)
                        if task_arg.error:
                            renderer.render_error(task_arg.error)
                            continue
                        task = runtime.get_task(task_arg.task_id)
                        if not task:
                            renderer.render_error(f"Task not found: {task_arg.task_id}")
                            continue
                        if task_arg.action == "logs":
                            from secops_agent.ui.overlay import view_logs_overlay
                            view_logs_overlay(f"Journaux de la tâche {task.id}", _task_transcript(task))
                        else:
                            renderer.render_task_detail(task)
                    elif canonical_cmd == "/cancel":
                        cancel_arg = parse_cancel_argument(arg)
                        if cancel_arg.error:
                            renderer.render_error(cancel_arg.error)
                            continue
                        task = runtime.cancel_task(cancel_arg.task_id)
                        if not task:
                            renderer.render_error(f"Task not found: {cancel_arg.task_id}")
                        elif task.status != "running":
                            renderer.render_status(f"Task {task.id} is already {task.status}.")
                        else:
                            task.detail = "cancelling"
                            renderer.render_status(f"Cancellation requested for {task.id}.")
                    elif canonical_cmd == "/resume":
                        selected_session = ""
                        if not arg and interactive_surface:
                            selected_session = _choose_saved_session(
                                _list_saved_sessions(),
                                status_right=friendly_model_name(agent.llm.model_name),
                                prompt_frame=True,
                            )
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                        resume_target = resolve_resume_target(
                            arg,
                            interactive_surface=interactive_surface,
                            selected_session=selected_session,
                            latest_session="" if interactive_surface else (_latest_saved_session() or ""),
                        )
                        if resume_target.action == "exit":
                            renderer.render_status("Exited /resume command")
                            continue
                        if resume_target.action == "empty":
                            renderer.render_status("No saved sessions.")
                            continue
                        target = resume_target.target
                        if _load_agent_session(agent, target, runtime=runtime):
                            _apply_loaded_runtime_controls(agent, runtime)
                            _restore_runtime_artifacts_after_load(runtime, agent.memory)
                            auto_session_name = target
                            renderer.render_success(f"Session '{target.replace('.json', '')}' loaded.")
                            renderer.render_session_transcript(agent.memory)
                        else:
                            renderer.render_error(f"Session '{target}' not found.")
                    elif canonical_cmd == "/rewind":
                        removed = _rewind_last_turn(agent.memory)
                        _rebuild_artifacts_from_memory(runtime, agent.memory)
                        if removed:
                            renderer.render_success(f"Rewound {removed} message(s).")
                        else:
                            renderer.render_status("Nothing to rewind.")
                    elif canonical_cmd == "/hooks":
                        if arg.lower() == "reload":
                            count = _refresh_hooks(runtime, agent)
                            renderer.render_success(f"Loaded {count} enabled hook(s).")
                        elif arg:
                            renderer.render_error("Usage: /hooks")
                            continue
                        renderer.render_hooks(
                            runtime.hooks,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /hooks command")
                    elif canonical_cmd == "/mcp":
                        action = arg.lower() if arg else "status"
                        if action == "reload":
                            await _stop_mcp(runtime)
                            count = _refresh_mcp(runtime)
                            renderer.render_success(f"Loaded {count} enabled MCP server config(s).")
                        elif action == "start":
                            count = await _start_mcp(runtime)
                            renderer.render_success(f"Started MCP runtime with {count} tool(s).")
                        elif action == "stop":
                            removed = await _stop_mcp(runtime)
                            renderer.render_success(f"Stopped MCP runtime and removed {removed} tool(s).")
                        elif action == "restart":
                            await _stop_mcp(runtime)
                            _refresh_mcp(runtime)
                            count = await _start_mcp(runtime)
                            renderer.render_success(f"Restarted MCP runtime with {count} tool(s).")
                        elif action in {"status", ""}:
                            pass
                        elif arg:
                            renderer.render_error("Usage: /mcp")
                            continue
                        renderer.render_mcp(
                            runtime.mcp,
                            runtime.mcp_runtime,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /mcp command")
                    elif canonical_cmd == "/skills":
                        if arg.lower() == "reload":
                            count = _refresh_skills(runtime, agent)
                            renderer.render_success(f"Loaded {count} skill(s).")
                        elif arg:
                            renderer.render_error("Usage: /skills")
                            continue
                        renderer.render_skills(
                            runtime.skills,
                            transient=interactive_surface,
                            status_right=friendly_model_name(agent.llm.model_name),
                            prompt_frame=interactive_surface,
                        )
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                            renderer.render_status("Exited /skills command")
                    elif canonical_cmd == "/model":
                        models = selectable_models()
                        if arg:
                            raw_model, *rest = arg.split()
                            thinking = rest[0] if rest else None
                            new = raw_model
                        else:
                            new = switch_model_menu(
                                models,
                                agent.llm.model_name,
                                auto_routing=getattr(agent.llm, "model_auto_routing", False),
                                current_thinking=getattr(agent.llm, "current_thinking_level", ""),
                                prompt_frame=interactive_surface,
                            )
                            thinking = None
                        if interactive_surface:
                            renderer.render_user_input(stripped, trailing_blank=False, separator=False)
                        if new:
                            try:
                                message = _set_model_selection(agent, new, thinking, persist=True)
                            except ValueError as exc:
                                renderer.render_error(str(exc) or "Usage: /model [auto|gemini|gemma|gemma-high|gemma-31b-off|gemma-31b] [default|off|high]")
                                continue
                            renderer.render_command_result(message)
                        else:
                            renderer.render_status("Exited /model command")
                    elif slash.spec:
                        renderer.render_planned_command(slash.spec.name, slash.spec.description)
                    else:
                        renderer.render_error(f"Unknown command: {cmd}")
                    continue
    
                # ── Agent interaction ─────────────────────────────────
                pending_inputs.extend(
                    await _render_interactive_turn(agent, renderer, runtime, stripped)
                )
    
            except KeyboardInterrupt:
                runtime.agent_state = "idle"
                renderer.render_status("Interrupted. /exit to quit.")
            except Exception as e:
                runtime.agent_state = "error"
                renderer.render_error(str(e))
                logger.exception("Error in main loop")
                _safe_autosave_agent_session(
                    agent,
                    runtime,
                    auto_session_name,
                    reason="error",
                )
    finally:
        await _stop_mcp(runtime)
        _safe_autosave_agent_session(
            agent,
            runtime,
            auto_session_name,
            reason="exit",
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Gemini API Key"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model override"),
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Preload session"),
    no_animation: bool = typer.Option(False, "--no-animation", help="Compatibility flag; startup animation is disabled"),
    print_prompt: Optional[str] = typer.Option(
        None,
        "--print",
        "-p",
        "--prompt",
        help="Run one prompt non-interactively and print the response.",
    ),
    print_timeout: float = typer.Option(300.0, "--print-timeout", help="Timeout in seconds for --print mode."),
    output_format: str = typer.Option(
        "text",
        "--output-format",
        help="Output format for --print: 'text' (default) or 'json' (lossless, includes full tool outputs).",
    ),
    prompt_interactive: Optional[str] = typer.Option(
        None,
        "--prompt-interactive",
        "-i",
        help="Run an initial prompt, then continue the TUI session.",
    ),
    sandbox: bool = typer.Option(False, "--sandbox", help="Enable restricted terminal command execution."),
    permission_mode: Optional[str] = typer.Option(
        None,
        "--permission-mode",
        help="Permission mode: request-review, proceed-in-sandbox, always-proceed, strict.",
    ),
    dangerously_skip_permissions: bool = typer.Option(
        False,
        "--dangerously-skip-permissions",
        help="Auto-approve tools and shell commands for this session. Use only on authorized targets.",
    ),
    autonomous: bool = typer.Option(
        False,
        "--autonomous",
        "--auto",
        help="Enable automatic execution of the planner for passive actions by default.",
    ),
    add_dir: Optional[list[Path]] = typer.Option(None, "--add-dir", help="Add a workspace directory; repeatable."),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Override CLI log file path."),
):
    """Launch the SecOps Agent."""
    if ctx.invoked_subcommand is not None:
        return

    if print_prompt is not None and prompt_interactive is not None:
        typer.echo("✗ Use either --print or --prompt-interactive, not both.", err=True)
        raise typer.Exit(code=2)

    try:
        initial_permission_mode = normalize_permission_mode(
            permission_mode,
            dangerously_skip_permissions=dangerously_skip_permissions,
        )
        workspace_dirs = _resolve_workspace_dirs(add_dir)
    except ValueError as exc:
        typer.echo(f"✗ {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if log_file:
        settings.LOG_FILE = str(log_file.expanduser())

    key = api_key or settings.GEMINI_API_KEY
    if not key:
        print("✗ GEMINI_API_KEY not set. Configure it in .env or pass via --api-key.", file=sys.stderr)
        raise typer.Exit(code=1)

    startup_model, startup_thinking = _startup_model_selection(model)
    llm = GeminiProvider(api_key=key, model_name=startup_model)
    if startup_model and startup_thinking and model is None:
        try:
            llm.set_model(startup_model, thinking_level=startup_thinking)
        except ValueError:
            logger.exception("Ignoring invalid persisted model preference")
    memory = ConversationMemory()
    mission = MissionContext(name="SecOps CLI session")
    structured_memory = StructuredMemory(conversation=memory, mission=mission)
    result_parser = ToolResultParser(mission=mission)
    experience_store = ExperienceStore()
    planner = MissionPlanner(
        lessons=experience_store.load(),
        suggestion_signals=experience_store.load_signals(),
    )
    agent = SecOpsAgent(
        llm=llm,
        registry=registry,
        memory=memory,
        structured_memory=structured_memory,
        result_parser=result_parser,
        planner=planner,
        experience_store=experience_store,
        allow_automatic_planner_execution=autonomous,
    )
    preloaded_session = ""
    if session:
        if _load_agent_session(agent, session, restore_model=True):
            preloaded_session = session
        else:
            print(f"✗ Session '{session}' not found.")

    if print_prompt is not None:
        runtime = _new_runtime(
            agent,
            permission_mode=initial_permission_mode,
            sandbox_enabled=sandbox,
            workspace_dirs=workspace_dirs,
        )
        if preloaded_session:
            _load_runtime_from_session(runtime, preloaded_session)
            _apply_loaded_runtime_controls(agent, runtime)
            _restore_runtime_artifacts_after_load(runtime, agent.memory)
        try:
            asyncio.run(_run_print_prompt(agent, runtime, print_prompt, print_timeout, output_format))
        except (RuntimeError, TimeoutError, ValueError) as exc:
            typer.echo(f"✗ {exc}", err=True)
            raise typer.Exit(code=1) from exc
        return

    renderer = Renderer()
    input_handler = InputHandler()

    def _sigint(sig, frame):
        pass  # Let the loop handle it

    signal.signal(signal.SIGINT, _sigint)

    try:
        asyncio.run(
            run_chat_loop(
                agent,
                renderer,
                input_handler,
                skip_animation=no_animation,
                initial_prompt=prompt_interactive or "",
                permission_mode=initial_permission_mode,
                sandbox_enabled=sandbox,
                workspace_dirs=workspace_dirs,
                preloaded_session=preloaded_session,
            )
        )
    except KeyboardInterrupt:
        print("\nGoodbye.")


@app.command()
def doctor():
    """Show local CLI diagnostics without starting the TUI."""
    sessions = _list_saved_sessions()
    typer.echo("SecOps Doctor")
    typer.echo(f"Version: {__version__}")
    typer.echo(f"Python: {platform.python_version()}")
    typer.echo(f"Platform: {platform.system()} {platform.release()}")
    typer.echo(f"CWD: {Path.cwd()}")
    typer.echo(f"API key: {'configured' if settings.GEMINI_API_KEY else 'missing'}")
    startup_model, _startup_thinking = _startup_model_selection(None)
    typer.echo(f"Configured model (.env): {settings.MODEL_NAME}")
    typer.echo(f"Effective model: {startup_model or settings.MODEL_NAME}")
    typer.echo(f"Registered tools: {len(registry.list_tools())}")
    typer.echo(f"Sessions: {len(sessions)} in {settings.sessions_dir}")
    typer.echo(f"Log file: {settings.LOG_FILE}")


if __name__ == "__main__":
    app()
