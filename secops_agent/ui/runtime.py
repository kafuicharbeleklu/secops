"""
In-memory TUI runtime state for interactive UX features.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from time import time

from secops_agent.core.extensions import SkillDefinition
from secops_agent.core.hooks import HookManager
from secops_agent.core.mcp import MCPConfigState, MCPRuntime


@dataclass
class RuntimeArtifact:
    id: str
    title: str
    kind: str
    content: str
    source: str = ""
    path: Path | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    created_at: float = field(default_factory=time)

    @property
    def preview(self) -> str:
        for line in self.content.splitlines():
            clean = line.strip()
            if clean:
                return clean[:160]
        return "No content."

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "content": self.content,
            "source": self.source,
            "path": str(self.path) if self.path is not None else "",
            "metadata": dict(self.metadata or {}),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RuntimeArtifact":
        return cls(
            id=str(data.get("id") or ""),
            title=str(data.get("title") or "artifact"),
            kind=str(data.get("kind") or "artifact"),
            content=str(data.get("content") or ""),
            source=str(data.get("source") or ""),
            path=Path(str(data["path"])).expanduser() if data.get("path") else None,
            metadata=dict(data.get("metadata") or {}),
            created_at=float(data.get("created_at") or time()),
        )


@dataclass
class RuntimeTask:
    id: str
    name: str
    status: str = "running"
    detail: str = ""
    kind: str = "task"
    query: str = ""
    created_at: float = field(default_factory=time)
    completed_at: float | None = None
    output: str = ""
    error: str = ""
    log: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    handle: asyncio.Task | None = field(default=None, repr=False, compare=False)

    @property
    def elapsed(self) -> float:
        end = self.completed_at if self.completed_at is not None else time()
        return max(0.0, end - self.created_at)

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    def append_log(self, line: str):
        if not line:
            return
        self.log.append(line)
        if len(self.log) > 200:
            self.log = self.log[-200:]

    def finish(self, status: str, output: str = "", error: str = "", detail: str = ""):
        self.status = status
        self.completed_at = time()
        if output:
            self.output = output
        if error:
            self.error = error
        if detail:
            self.detail = detail

    def request_cancel(self) -> bool:
        if not self.is_running:
            return False
        self.detail = "cancelling"
        self.append_log("cancellation requested")
        if self.handle and not self.handle.done():
            self.handle.cancel()
            return True
        return False


@dataclass
class RuntimeState:
    workspace_dirs: list[Path] = field(default_factory=list)
    tasks: list[RuntimeTask] = field(default_factory=list)
    artifacts: list[RuntimeArtifact] = field(default_factory=list)
    skills: list[SkillDefinition] = field(default_factory=list)
    hooks: HookManager = field(default_factory=HookManager)
    mcp: MCPConfigState = field(default_factory=MCPConfigState)
    mcp_runtime: MCPRuntime = field(default_factory=MCPRuntime)
    _next_task_id: int = 1
    _next_artifact_id: int = 1
    fast_mode: bool = False
    sandbox_enabled: bool = False
    permission_mode: str = "request-review"
    allow_automatic_planner_execution: bool = False
    agent_state: str = "idle"
    original_temperature: float = 0.7
    original_max_iterations: int = 10
    ctrl_o_expanded_artifact_id: str = ""
    ctrl_o_rendered_lines: int = 0
    ctrl_o_transcript_collapsed: str = ""
    ctrl_o_transcript_expanded: str = ""
    ctrl_o_transcript_is_expanded: bool = False
    ctrl_o_transcript_rendered_lines: int = 0
    ctrl_o_anchor_collapsed: str = ""
    ctrl_o_anchor_expanded: str = ""
    ctrl_o_anchor_is_expanded: bool = False
    ctrl_o_anchor_rendered_lines: int = 0
    ctrl_o_anchor_tail_lines: int = 0
    ctrl_o_anchor_prompt_tail_applied: bool = False

    def reset_ctrl_o_surface(self, *, clear_anchor: bool = False):
        self.ctrl_o_expanded_artifact_id = ""
        self.ctrl_o_rendered_lines = 0
        self.ctrl_o_transcript_collapsed = ""
        self.ctrl_o_transcript_expanded = ""
        self.ctrl_o_transcript_is_expanded = False
        self.ctrl_o_transcript_rendered_lines = 0
        if clear_anchor:
            self.clear_ctrl_o_anchor()

    def clear_ctrl_o_anchor(self):
        self.ctrl_o_anchor_collapsed = ""
        self.ctrl_o_anchor_expanded = ""
        self.ctrl_o_anchor_is_expanded = False
        self.ctrl_o_anchor_rendered_lines = 0
        self.ctrl_o_anchor_tail_lines = 0
        self.ctrl_o_anchor_prompt_tail_applied = False

    def set_ctrl_o_anchor(
        self,
        collapsed_lines: list[str],
        expanded_lines: list[str],
        *,
        tail_lines: int = 0,
    ):
        if not collapsed_lines or not expanded_lines:
            self.clear_ctrl_o_anchor()
            return
        self.ctrl_o_anchor_collapsed = "\n".join(collapsed_lines)
        self.ctrl_o_anchor_expanded = "\n".join(expanded_lines)
        self.ctrl_o_anchor_is_expanded = False
        self.ctrl_o_anchor_rendered_lines = len(collapsed_lines)
        self.ctrl_o_anchor_tail_lines = max(0, int(tail_lines or 0))
        self.ctrl_o_anchor_prompt_tail_applied = False

    def advance_ctrl_o_anchor_lines(self, count: int):
        if count <= 0 or not self.ctrl_o_anchor_collapsed or self.ctrl_o_anchor_rendered_lines <= 0:
            return
        self.ctrl_o_anchor_tail_lines += int(count)

    def add_workspace_dir(self, path: Path) -> bool:
        resolved = path.expanduser().resolve()
        if resolved in self.workspace_dirs:
            return False
        self.workspace_dirs.append(resolved)
        return True

    def add_task(
        self,
        name: str,
        status: str = "running",
        detail: str = "",
        kind: str = "task",
        query: str = "",
        metadata: dict[str, object] | None = None,
    ) -> RuntimeTask:
        task = RuntimeTask(
            id=f"t{self._next_task_id:03d}",
            name=name,
            status=status,
            detail=detail,
            kind=kind,
            query=query,
            metadata=dict(metadata or {}),
        )
        self._next_task_id += 1
        self.tasks.append(task)
        self._trim_tasks()
        return task

    def add_artifact(
        self,
        title: str,
        kind: str,
        content: str,
        *,
        source: str = "",
        path: Path | None = None,
        metadata: dict[str, object] | None = None,
    ) -> RuntimeArtifact | None:
        if not str(content).strip():
            return None
        artifact = RuntimeArtifact(
            id=f"a{self._next_artifact_id:03d}",
            title=title.strip() or kind,
            kind=kind.strip() or "artifact",
            content=str(content),
            source=source,
            path=path,
            metadata=dict(metadata or {}),
        )
        self._next_artifact_id += 1
        self.artifacts.append(artifact)
        self._trim_artifacts()
        self.reset_ctrl_o_surface(clear_anchor=True)
        return artifact

    def _trim_artifacts(self):
        if len(self.artifacts) > 50:
            self.artifacts = self.artifacts[-50:]

    def get_artifact(self, artifact_id: str) -> RuntimeArtifact | None:
        needle = artifact_id.strip().lower().lstrip("#")
        if not needle:
            return None
        if needle.isdigit():
            needle = f"a{int(needle):03d}"
        return next((artifact for artifact in self.artifacts if artifact.id.lower() == needle), None)

    def update_artifact(
        self,
        artifact_id: str,
        *,
        title: str | None = None,
        content: str | None = None,
        metadata: dict[str, object] | None = None,
        path: Path | None = None,
    ) -> RuntimeArtifact | None:
        """Update a durable artifact in place without changing its review ID."""
        artifact = self.get_artifact(artifact_id)
        if artifact is None:
            return None
        if title is not None:
            artifact.title = str(title).strip() or artifact.title
        if content is not None:
            artifact.content = str(content)
        if metadata is not None:
            artifact.metadata = dict(metadata)
        if path is not None:
            artifact.path = path
        self.reset_ctrl_o_surface(clear_anchor=True)
        return artifact

    def attachment_artifacts(self) -> list[RuntimeArtifact]:
        return [artifact for artifact in self.artifacts if artifact.kind == "attachment"]

    def latest_artifact(self) -> RuntimeArtifact | None:
        return self.artifacts[-1] if self.artifacts else None

    def _trim_tasks(self):
        if len(self.tasks) <= 50:
            return
        running = [task for task in self.tasks if task.is_running]
        finished = [task for task in self.tasks if not task.is_running]
        self.tasks = finished[-max(0, 50 - len(running)):] + running

    def get_task(self, task_id: str) -> RuntimeTask | None:
        needle = task_id.strip().lower().lstrip("#")
        if not needle:
            return None
        if needle.isdigit():
            needle = f"t{int(needle):03d}"
        return next((task for task in self.tasks if task.id.lower() == needle), None)

    def running_tasks(self) -> list[RuntimeTask]:
        return [task for task in self.tasks if task.is_running]

    def cancel_task(self, task_id: str) -> RuntimeTask | None:
        task = self.get_task(task_id)
        if task:
            task.request_cancel()
        return task

    def to_session_dict(self) -> dict:
        """Serialize durable runtime state for session resume."""
        return {
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "workspace_dirs": [str(path) for path in self.workspace_dirs],
            "fast_mode": self.fast_mode,
            "sandbox_enabled": self.sandbox_enabled,
            "permission_mode": self.permission_mode,
            "allow_automatic_planner_execution": self.allow_automatic_planner_execution,
        }

    def load_session_dict(self, data: dict | None) -> None:
        """Restore durable runtime state from a saved session."""
        if not isinstance(data, dict):
            return

        self.artifacts = [
            RuntimeArtifact.from_dict(item)
            for item in data.get("artifacts", []) or []
            if isinstance(item, dict)
        ]
        self._trim_artifacts()
        next_id = 1
        for artifact in self.artifacts:
            try:
                next_id = max(next_id, int(artifact.id.lstrip("a")) + 1)
            except ValueError:
                continue
        self._next_artifact_id = next_id

        self.workspace_dirs = [
            Path(str(path)).expanduser()
            for path in data.get("workspace_dirs", []) or []
            if str(path).strip()
        ]
        self.fast_mode = bool(data.get("fast_mode", self.fast_mode))
        self.sandbox_enabled = bool(data.get("sandbox_enabled", self.sandbox_enabled))
        self.allow_automatic_planner_execution = bool(data.get("allow_automatic_planner_execution", self.allow_automatic_planner_execution))
        permission_mode = str(data.get("permission_mode") or self.permission_mode)
        if permission_mode:
            self.permission_mode = permission_mode
        self.reset_ctrl_o_surface()
