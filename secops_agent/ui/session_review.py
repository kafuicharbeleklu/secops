"""
Session trajectory and artifact review helpers.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from secops_agent.core.memory import ConversationMemory
from secops_agent.ui.overlay import OverlayChoice, choose_overlay, view_logs_overlay
from secops_agent.ui.runtime import RuntimeArtifact, RuntimeState
from secops_agent.ui.spool_display import spool_reference, supervised_detail_text


def _single_line(text: str, limit: int = 180) -> str:
    clean = " ".join(str(text).split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1] + "…"


def _snippet(text: str, *, max_lines: int = 8, max_chars: int = 1200) -> list[str]:
    if not text:
        return ["(empty)"]
    lines = []
    remaining_chars = max_chars
    for raw_line in str(text).splitlines():
        if len(lines) >= max_lines or remaining_chars <= 0:
            break
        line = raw_line.rstrip()
        if len(line) > remaining_chars:
            line = line[: max(0, remaining_chars - 1)] + "…"
        lines.append(line)
        remaining_chars -= len(line)
    if not lines:
        lines = [_single_line(text, min(max_chars, 180))]
    hidden_lines = max(0, len(str(text).splitlines()) - len(lines))
    if hidden_lines:
        lines.append(f"... {hidden_lines} more line(s)")
    return lines


def _format_tool_call(call: dict[str, Any]) -> str:
    name = call.get("name", "tool")
    arguments = call.get("arguments") or {}
    try:
        args = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
    except TypeError:
        args = str(arguments)
    return f"{name} {args}"


def build_artifact_text(artifact: RuntimeArtifact) -> str:
    lines = [
        f"Artifact: {artifact.id}",
        f"Title: {artifact.title}",
        f"Kind: {artifact.kind}",
    ]
    if artifact.source:
        lines.append(f"Source: {artifact.source}")
    log_path = spool_reference(artifact.metadata)
    if log_path:
        lines.append(f"Log: {log_path}")
    elif artifact.path:
        lines.append(f"Path: {artifact.path}")
    lines.extend(["", supervised_detail_text(artifact.metadata, artifact.content)])
    return "\n".join(lines)


def _latest_tool_artifact(runtime: RuntimeState | None) -> RuntimeArtifact | None:
    if runtime is None:
        return None
    for artifact in reversed(runtime.artifacts):
        if artifact.kind == "tool-result":
            return artifact
    return None


def build_trajectory_text(
    memory: ConversationMemory,
    runtime: RuntimeState | None = None,
    *,
    expand_latest_tool: bool = False,
) -> str:
    artifacts = runtime.artifacts if runtime else []
    attachments = runtime.attachment_artifacts() if runtime else []
    tasks = runtime.tasks if runtime else []
    latest_tool = _latest_tool_artifact(runtime) if expand_latest_tool else None
    lines = [
        "SecOps Trajectory",
        f"Messages: {len(memory.messages)}",
        f"Artifacts: {len(artifacts)}",
        f"Attachments: {len(attachments)}",
        f"Tasks: {len(tasks)}",
        "",
    ]

    if not memory.messages:
        lines.extend(["No messages yet.", ""])
    for index, msg in enumerate(memory.messages, start=1):
        if msg.role == "user":
            lines.append(f"{index:02d} User")
            lines.extend(f"   {line}" for line in _snippet(msg.content, max_lines=6))
        elif msg.role == "model":
            lines.append(f"{index:02d} Agent")
            if msg.content:
                lines.extend(f"   {line}" for line in _snippet(msg.content, max_lines=8))
            else:
                lines.append("   (tool request)")
            if msg.tool_calls:
                lines.append("   Tool calls:")
                for call in msg.tool_calls:
                    lines.append(f"   - {_single_line(_format_tool_call(call), 220)}")
        elif msg.role == "tool":
            for result in msg.tool_results:
                name = result.get("name", "tool")
                content = result.get("content", "")
                lines.append(f"{index:02d} Tool · {name}")
                lines.extend(f"   {line}" for line in _snippet(content, max_lines=8))
        else:
            lines.append(f"{index:02d} {msg.role}")
            lines.extend(f"   {line}" for line in _snippet(msg.content, max_lines=6))
        lines.append("")

    lines.append("Artifacts")
    if artifacts:
        for artifact in artifacts[-20:]:
            label = f"{artifact.id} · {artifact.kind} · {artifact.title}"
            lines.append(f"  {label}")
            lines.append(f"    {_single_line(artifact.preview, 180)}")
    else:
        lines.append("  No artifacts yet.")

    lines.append("")
    lines.append("Attachments")
    if attachments:
        for artifact in attachments[-20:]:
            label = f"{artifact.id} · {artifact.title}"
            lines.append(f"  {label}")
            lines.append(f"    {_single_line(artifact.preview, 180)}")
    else:
        lines.append("  No attachments yet.")

    if latest_tool:
        lines.extend(
            [
                "",
                "Expanded Tool Output",
                f"  {latest_tool.id} · {latest_tool.source or latest_tool.title}",
                "",
            ]
        )
        content_lines = str(latest_tool.content or "(no output)").splitlines() or ["(no output)"]
        lines.extend(f"  {line}" for line in content_lines)

    if tasks:
        lines.extend(["", "Background Tasks"])
        for task in tasks[-20:]:
            detail = f" · {task.detail}" if task.detail else ""
            lines.append(f"  {task.id} · {task.status} · {task.name}{detail}")

    return "\n".join(lines).rstrip() + "\n"


def artifact_choices(runtime: RuntimeState) -> list[OverlayChoice]:
    return [
        OverlayChoice(
            artifact.id,
            f"{artifact.id}  {artifact.title}",
            f"{artifact.kind} · {artifact.source}".strip(" ·"),
            current=index == len(runtime.artifacts) - 1,
        )
        for index, artifact in enumerate(runtime.artifacts)
    ]


def choose_artifact(runtime: RuntimeState) -> RuntimeArtifact | None:
    if not runtime.artifacts:
        return None
    if not sys.stdin.isatty() or len(runtime.artifacts) == 1:
        return runtime.latest_artifact()

    selected_id = choose_overlay(
        "Review Artifact",
        artifact_choices(runtime),
        detail_provider=lambda choice: _artifact_choice_detail(runtime, choice.value),
    )
    if not selected_id:
        return None
    return runtime.get_artifact(selected_id)


def _artifact_choice_detail(runtime: RuntimeState, artifact_id: str) -> list[str]:
    artifact = runtime.get_artifact(artifact_id)
    if not artifact:
        return ["Artifact not found."]
    return [
        f"Kind: {artifact.kind}",
        f"Source: {artifact.source or '-'}",
        "",
        artifact.preview,
    ]


def view_trajectory(
    memory: ConversationMemory,
    runtime: RuntimeState | None = None,
    *,
    expand_latest_tool: bool = False,
) -> bool:
    if not sys.stdin.isatty():
        return False
    view_logs_overlay(
        "Trajectory",
        build_trajectory_text(memory, runtime, expand_latest_tool=expand_latest_tool),
        initial_search="Expanded Tool Output" if expand_latest_tool else "",
    )
    return True


def view_artifact_review(runtime: RuntimeState, artifact_id: str = "") -> RuntimeArtifact | None:
    if artifact_id:
        artifact = runtime.get_artifact(artifact_id)
    else:
        artifact = choose_artifact(runtime)

    if not artifact:
        return None
    if sys.stdin.isatty():
        view_logs_overlay(f"Artifact {artifact.id}: {artifact.title}", build_artifact_text(artifact))
    return artifact
