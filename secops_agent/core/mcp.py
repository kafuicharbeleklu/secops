"""
MCP configuration loading and validation.

This module validates configured MCP servers and manages stdio MCP sessions.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secops_agent import __version__
from secops_agent.core.sandbox import validate_exec_command
from secops_agent.core.tools import ToolCategory, ToolRegistry, report_progress


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    source: str = ""
    path: Path = Path()
    server_hash: str = ""
    trust_status: str = "trusted"


@dataclass
class MCPConfigState:
    servers: list[MCPServerConfig] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def enabled_servers(self) -> list[MCPServerConfig]:
        return [
            server
            for server in self.servers
            if not server.disabled and getattr(server, "trust_status", "trusted") == "trusted"
        ]


@dataclass(frozen=True)
class MCPToolBinding:
    registry_name: str
    server_name: str
    remote_name: str
    description: str


class MCPProtocolError(RuntimeError):
    pass


class MCPServerSession:
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.process: asyncio.subprocess.Process | None = None
        self._next_id = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self.stderr_lines: list[str] = []
        self.tools: list[dict[str, Any]] = []
        self.started_at: float | None = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.returncode is None

    async def start(self):
        if self.running:
            return

        cmd = [self.config.command, *self.config.args]
        check = validate_exec_command(cmd)
        if not check.allowed:
            raise MCPProtocolError(f"Sandbox blocked MCP server {self.config.name}: {check.reason}")

        env = _mcp_start_environment(self.config.env)
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(Path.cwd()),
        )
        self.started_at = time.monotonic()
        self._reader_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

        await self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "secops-agent", "version": __version__},
            },
            timeout=10,
        )
        await self.notify("notifications/initialized")
        tools_result = await self.request("tools/list", {}, timeout=10)
        raw_tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        self.tools = [tool for tool in raw_tools if isinstance(tool, dict) and tool.get("name")]

    async def stop(self):
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

        for task in (self._reader_task, self._stderr_task):
            if task and not task.done():
                task.cancel()

        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        self.process = None

    async def call_tool(self, remote_name: str, arguments: dict[str, Any]) -> str:
        if not self.running:
            raise MCPProtocolError(f"MCP server {self.config.name} is not running")
        result = await self.request(
            "tools/call",
            {"name": remote_name, "arguments": arguments},
            timeout=60,
        )
        return _format_mcp_tool_result(result)

    async def request(self, method: str, params: dict[str, Any] | None = None, timeout: int = 10) -> Any:
        if not self.process or not self.process.stdin:
            raise MCPProtocolError(f"MCP server {self.config.name} is not started")

        request_id = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[request_id] = future

        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        await self._write_message(payload)

        try:
            response = await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(request_id, None)

        if "error" in response:
            error = response["error"]
            message = error.get("message", error) if isinstance(error, dict) else error
            raise MCPProtocolError(f"{self.config.name}:{method}: {message}")
        return response.get("result", {})

    async def notify(self, method: str, params: dict[str, Any] | None = None):
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        await self._write_message(payload)

    async def _write_message(self, payload: dict[str, Any]):
        if not self.process or not self.process.stdin:
            raise MCPProtocolError(f"MCP server {self.config.name} is not writable")
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        self.process.stdin.write(data)
        await self.process.stdin.drain()

    async def _read_stdout(self):
        assert self.process and self.process.stdout
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            response_id = message.get("id")
            if response_id is None:
                continue
            try:
                response_id = int(response_id)
            except (TypeError, ValueError):
                continue
            future = self._pending.get(response_id)
            if future and not future.done():
                future.set_result(message)

    async def _read_stderr(self):
        assert self.process and self.process.stderr
        while True:
            line = await self.process.stderr.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                self.stderr_lines.append(text)
                if len(self.stderr_lines) > 50:
                    self.stderr_lines = self.stderr_lines[-50:]


class MCPRuntime:
    def __init__(self):
        self.sessions: dict[str, MCPServerSession] = {}
        self.tool_bindings: dict[str, MCPToolBinding] = {}
        self.errors: list[str] = []

    @property
    def running_servers(self) -> list[str]:
        return [name for name, session in self.sessions.items() if session.running]

    async def start(self, state: MCPConfigState, registry: ToolRegistry) -> int:
        await self.stop(registry)
        self.errors = []
        count = 0
        for config in [server for server in state.servers if not server.disabled]:
            if getattr(config, "trust_status", "trusted") != "trusted":
                self.errors.append(f"{config.name}: MCP server requires review before start")
                continue
            session = MCPServerSession(config)
            try:
                await session.start()
            except Exception as exc:
                self.errors.append(f"{config.name}: {exc}")
                await session.stop()
                continue

            self.sessions[config.name] = session
            count += self._register_session_tools(session, registry)
        return count

    async def stop(self, registry: ToolRegistry) -> int:
        removed = registry.unregister_prefix("mcp_")
        for session in list(self.sessions.values()):
            await session.stop()
        self.sessions.clear()
        self.tool_bindings.clear()
        return removed

    def server_status(self, server_name: str) -> str:
        session = self.sessions.get(server_name)
        if session and session.running:
            return f"running · {len(session.tools)} tools"
        return "configured"

    def _register_session_tools(self, session: MCPServerSession, registry: ToolRegistry) -> int:
        count = 0
        for tool in session.tools:
            remote_name = str(tool["name"])
            registry_name = _registry_tool_name(session.config.name, remote_name, self.tool_bindings)
            description = str(tool.get("description") or f"MCP tool {remote_name} from {session.config.name}")
            parameters = _mcp_schema_to_parameters(tool.get("inputSchema", {}))

            async def _call_mcp_tool(_remote_name=remote_name, _server_name=session.config.name, **kwargs):
                await report_progress("calling MCP tool", f"{_server_name}.{_remote_name}")
                active = self.sessions.get(_server_name)
                if not active:
                    raise MCPProtocolError(f"MCP server {_server_name} is not running")
                return await active.call_tool(_remote_name, kwargs)

            registry.register(
                name=registry_name,
                description=description,
                category=ToolCategory.MCP,
                parameters=parameters,
                func=_call_mcp_tool,
                dangerous=True,  # MCP tools are external — require approval
            )
            self.tool_bindings[registry_name] = MCPToolBinding(
                registry_name=registry_name,
                server_name=session.config.name,
                remote_name=remote_name,
                description=description,
            )
            count += 1
        return count


def discover_mcp_files(workspace: Path | None = None) -> list[tuple[str, Path]]:
    root = workspace or Path.cwd()
    return [
        ("workspace", root / ".agents" / "mcp_config.json"),
        ("global", Path.home() / ".gemini" / "antigravity-cli" / "mcp_config.json"),
        ("global", Path.home() / ".gemini" / "config" / "mcp_config.json"),
    ]


def load_mcp_config(paths: list[tuple[str, Path]] | None = None) -> MCPConfigState:
    servers: list[MCPServerConfig] = []
    errors: list[str] = []
    seen: set[str] = set()

    for source, path in paths or discover_mcp_files():
        if not path.exists() or not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
            if not content.strip():
                continue
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            errors.append(f"{_display_path(path)}: invalid JSON at line {exc.lineno}, column {exc.colno}")
            continue
        except Exception as exc:
            errors.append(f"{_display_path(path)}: {exc}")
            continue

        parsed, parse_errors = _parse_mcp_config(raw, source, path)
        errors.extend(parse_errors)
        for server in parsed:
            if server.name in seen:
                continue
            servers.append(server)
            seen.add(server.name)

    return MCPConfigState(servers=servers, errors=errors)


def _display_path(path: Path) -> str:
    try:
        return str(path.expanduser()).replace(str(Path.home()), "~", 1)
    except Exception:
        return str(path)


def _parse_mcp_config(raw: Any, source: str, path: Path) -> tuple[list[MCPServerConfig], list[str]]:
    errors: list[str] = []
    servers: list[MCPServerConfig] = []

    if not isinstance(raw, dict):
        return [], [f"{path}: root must be a JSON object"]

    container = raw.get("mcpServers", raw.get("servers", {}))
    if isinstance(container, list):
        iterable = []
        for item in container:
            if isinstance(item, dict) and "name" in item:
                iterable.append((str(item["name"]), item))
            else:
                errors.append(f"{path}: list server entries must include name")
    elif isinstance(container, dict):
        iterable = [(str(name), value) for name, value in container.items()]
    else:
        return [], [f"{path}: mcpServers or servers must be an object or list"]

    for name, config in iterable:
        server, error = _parse_server(name, config, source, path)
        if error:
            errors.append(error)
        elif server:
            servers.append(server)

    return servers, errors


def _parse_server(
    name: str,
    config: Any,
    source: str,
    path: Path,
) -> tuple[MCPServerConfig | None, str | None]:
    if not isinstance(config, dict):
        return None, f"{path}: server {name} must be an object"

    command = config.get("command")
    if not isinstance(command, str) or not command.strip():
        return None, f"{path}: server {name} missing command"

    args = config.get("args", [])
    if isinstance(args, str):
        args = [args]
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        return None, f"{path}: server {name} args must be a string array"

    env = config.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        return None, f"{path}: server {name} env must be a string map"

    disabled = bool(config.get("disabled", config.get("enabled") is False))
    server_hash = _mcp_server_hash(command.strip(), args, env)
    trusted_hash = str(config.get("trusted_hash") or "").strip()
    if trusted_hash and trusted_hash == server_hash:
        trust_status = "trusted"
    elif trusted_hash:
        trust_status = "hash_changed"
    else:
        trust_status = "pending_review"

    return (
        MCPServerConfig(
            name=name,
            command=command.strip(),
            args=args,
            env=env,
            disabled=disabled,
            source=source,
            path=path,
            server_hash=server_hash,
            trust_status=trust_status,
        ),
        None,
    )


def _mcp_server_hash(command: str, args: list[str], env: dict[str, str]) -> str:
    payload = {
        "command": str(command),
        "args": [str(arg) for arg in args],
        "env": {str(key): str(value) for key, value in sorted(env.items())},
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()


def _mcp_start_environment(config_env: dict[str, str]) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "TERM"}
    }
    env.update({str(key): str(value) for key, value in config_env.items()})
    return env


def _registry_tool_name(server_name: str, remote_name: str, existing: dict[str, MCPToolBinding]) -> str:
    base = f"mcp_{_safe_identifier(server_name)}_{_safe_identifier(remote_name)}"
    if len(base) > 60:
        base = base[:60].rstrip("_")
    if base not in existing:
        return base

    suffix = 2
    while True:
        candidate = f"{base[:56]}_{suffix}"
        if candidate not in existing:
            return candidate
        suffix += 1


def _safe_identifier(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower()).strip("_")
    if not safe:
        safe = "server"
    if safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def _mcp_schema_to_parameters(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    if not isinstance(properties, dict):
        return {}

    parameters: dict[str, Any] = {}
    for name, definition in properties.items():
        if not isinstance(definition, dict):
            definition = {}
        normalized = _normalize_mcp_schema_definition(definition)
        normalized.update(
            {
                "description": str(definition.get("description") or definition.get("title") or ""),
                "required": str(name) in required,
            }
        )
        parameters[str(name)] = normalized
    return parameters


def _normalize_mcp_schema_definition(definition: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "type": _schema_type(definition),
    }
    if "enum" in definition and isinstance(definition["enum"], list):
        normalized["enum"] = [item for item in definition["enum"] if isinstance(item, (str, int, float, bool))]
    if "default" in definition and isinstance(definition["default"], (str, int, float, bool)):
        normalized["default"] = definition["default"]

    if normalized["type"] == "array":
        items = definition.get("items", {})
        if isinstance(items, dict):
            normalized["items"] = _normalize_nested_schema_definition(items)
    elif normalized["type"] == "object":
        nested_properties = definition.get("properties", {})
        if isinstance(nested_properties, dict):
            nested_required = set(definition.get("required", []))
            normalized["properties"] = {}
            for nested_name, nested_definition in nested_properties.items():
                if not isinstance(nested_definition, dict):
                    nested_definition = {}
                nested_value = _normalize_nested_schema_definition(nested_definition)
                nested_value["required"] = str(nested_name) in nested_required
                normalized["properties"][str(nested_name)] = nested_value
    return normalized


def _normalize_nested_schema_definition(definition: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_mcp_schema_definition(definition)
    if "description" in definition or "title" in definition:
        normalized["description"] = str(definition.get("description") or definition.get("title") or "")
    return normalized


def _schema_type(definition: dict[str, Any]) -> str:
    raw_type = definition.get("type")
    if isinstance(raw_type, list):
        raw_type = next((item for item in raw_type if item != "null"), "string")
    if raw_type in {"string", "integer", "number", "boolean", "array", "object"}:
        return str(raw_type)
    if "enum" in definition:
        return "string"
    return "string"


def _format_mcp_tool_result(result: Any) -> str:
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False)

    if result.get("isError"):
        prefix = "MCP tool returned an error:\n"
    else:
        prefix = ""

    content = result.get("content")
    if not isinstance(content, list):
        return prefix + json.dumps(result, ensure_ascii=False, indent=2)

    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            parts.append(str(item))
            continue
        item_type = item.get("type")
        if item_type == "text":
            parts.append(str(item.get("text", "")))
        else:
            parts.append(json.dumps(item, ensure_ascii=False))

    text = "\n".join(part for part in parts if part)
    return prefix + (text or json.dumps(result, ensure_ascii=False, indent=2))
