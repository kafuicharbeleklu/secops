"""
Command hook loading and execution for SecOps Agent.
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secops_agent.core.tools import ToolResult
from secops_agent.utils.helpers import run_cmd


HOOK_EVENTS = {"before_tool", "after_tool", "on_error"}


@dataclass(frozen=True)
class HookDefinition:
    event: str
    name: str
    command: str | list[str]
    tools: list[str]
    timeout: int
    enabled: bool
    source: str
    path: Path
    command_hash: str = ""
    trust_status: str = "pending_review"

    def matches(self, event: str, tool_name: str) -> bool:
        if not self.enabled or self.event != event:
            return False
        return not self.tools or "*" in self.tools or tool_name in self.tools


@dataclass
class HookRun:
    hook: HookDefinition
    status: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    elapsed: float = 0.0


class HookManager:
    def __init__(self, hooks: list[HookDefinition] | None = None, errors: list[str] | None = None):
        self.hooks = hooks or []
        self.errors = errors or []
        self.last_runs: list[HookRun] = []

    @property
    def enabled_hooks(self) -> list[HookDefinition]:
        return [hook for hook in self.hooks if hook.enabled]

    def hooks_for(self, event: str, tool_name: str) -> list[HookDefinition]:
        return [hook for hook in self.hooks if hook.matches(event, tool_name)]

    async def run(
        self,
        event: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult | None = None,
        error: str = "",
    ) -> list[HookRun]:
        runs: list[HookRun] = []
        if event not in HOOK_EVENTS:
            return runs

        for hook in self.hooks_for(event, tool_name):
            run = await self._run_hook(hook, event, tool_name, arguments, result, error)
            runs.append(run)
            self.last_runs.append(run)
            if len(self.last_runs) > 50:
                self.last_runs = self.last_runs[-50:]
        return runs

    async def _run_hook(
        self,
        hook: HookDefinition,
        event: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult | None,
        error: str,
    ) -> HookRun:
        start = time.monotonic()
        cmd = _hook_command(hook.command)
        env = _hook_environment(event, tool_name, arguments, result, error)

        stdout, stderr, rc = await run_cmd(
            cmd,
            timeout=hook.timeout,
            env=env,
            cwd=str(Path.cwd()),
        )
        status = "ok" if rc == 0 else "failed"
        return HookRun(
            hook=hook,
            status=status,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
            returncode=rc,
            elapsed=time.monotonic() - start,
        )


def discover_hook_files(workspace: Path | None = None) -> list[tuple[str, Path]]:
    root = workspace or Path.cwd()
    return [
        ("workspace", root / ".agents" / "hooks.json"),
        ("global", Path.home() / ".gemini" / "antigravity-cli" / "hooks.json"),
        ("global", Path.home() / ".gemini" / "config" / "hooks.json"),
    ]


def load_hooks(paths: list[tuple[str, Path]] | None = None) -> HookManager:
    hooks: list[HookDefinition] = []
    errors: list[str] = []

    for source, path in paths or discover_hook_files():
        if not path.exists() or not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{path}: {exc}")
            continue

        try:
            hooks.extend(_parse_hook_config(raw, source, path))
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    return HookManager(hooks=hooks, errors=errors)


def _parse_hook_config(raw: Any, source: str, path: Path) -> list[HookDefinition]:
    config = raw.get("hooks", raw) if isinstance(raw, dict) else {}
    hooks: list[HookDefinition] = []

    for event in sorted(HOOK_EVENTS):
        entries = config.get(event, []) if isinstance(config, dict) else []
        if isinstance(entries, (str, dict)):
            entries = [entries]
        if not isinstance(entries, list):
            continue

        for index, entry in enumerate(entries, start=1):
            hook = _parse_hook_entry(event, entry, source, path, index)
            if hook:
                hooks.append(hook)
    return hooks


def _parse_hook_entry(
    event: str,
    entry: Any,
    source: str,
    path: Path,
    index: int,
) -> HookDefinition | None:
    if isinstance(entry, str):
        command: str | list[str] = entry
        name = f"{event}-{index}"
        tools: list[str] = []
        timeout = 10
        raw_enabled = False
        trusted_hash = ""
    elif isinstance(entry, dict):
        command = entry.get("command")
        if not command:
            return None
        name = str(entry.get("name") or f"{event}-{index}")
        raw_tools = entry.get("tools", entry.get("tool", []))
        tools = _normalize_tools(raw_tools)
        timeout = int(entry.get("timeout", 10))
        raw_enabled = bool(entry.get("enabled", False))
        trusted_hash = str(entry.get("trusted_hash") or "").strip()
    else:
        return None

    timeout = max(1, min(timeout, 60))
    command_hash = _command_hash(command)
    if trusted_hash and trusted_hash == command_hash:
        trust_status = "trusted"
    elif trusted_hash:
        trust_status = "hash_changed"
    else:
        trust_status = "pending_review"
    enabled = raw_enabled and trust_status == "trusted"
    return HookDefinition(
        event=event,
        name=name,
        command=command,
        tools=tools,
        timeout=timeout,
        enabled=enabled,
        source=source,
        path=path,
        command_hash=command_hash,
        trust_status=trust_status,
    )


def _normalize_tools(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def _hook_command(command: str | list[str]) -> list[str]:
    if isinstance(command, list):
        return [str(part) for part in command]
    shell = shutil.which("bash") or shutil.which("sh") or "sh"
    flag = "-lc" if shell.endswith("bash") else "-c"
    return [shell, flag, command]


def _command_hash(command: str | list[str]) -> str:
    if isinstance(command, list):
        normalized = json.dumps([str(part) for part in command], separators=(",", ":"))
    else:
        normalized = str(command)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _hook_environment(
    event: str,
    tool_name: str,
    arguments: dict[str, Any],
    result: ToolResult | None,
    error: str,
) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "TERM"}
    }
    env.update(
        {
            "SECOPS_HOOK_EVENT": event,
            "SECOPS_TOOL_NAME": tool_name,
            "SECOPS_TOOL_ARGS_JSON": json.dumps(_redact_sensitive(arguments), ensure_ascii=False),
            "SECOPS_TOOL_SUCCESS": "true" if result and result.success else "false",
            "SECOPS_TOOL_ERROR": _redact_text(error or (result.error if result else "") or ""),
        }
    )
    return env


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = "[REDACTED]"
            else:
                redacted[key_text] = _redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive(item) for item in value]
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold()
    return any(
        marker in normalized
        for marker in (
            "password",
            "passwd",
            "token",
            "secret",
            "api_key",
            "apikey",
            "credential",
            "private",
            "cookie",
        )
    )


def _redact_text(text: str) -> str:
    compact = str(text or "")
    for marker in ("password", "passwd", "token", "secret", "api_key", "apikey", "credential", "private", "cookie"):
        compact = compact.replace(marker, "[redacted]")
        compact = compact.replace(marker.upper(), "[REDACTED]")
    return compact
