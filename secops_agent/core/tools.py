"""
Tool registry and execution framework for the SecOps Agent.
"""

from __future__ import annotations

import time
import inspect
import asyncio
import contextvars
import logging
from enum import Enum
from typing import Awaitable, Callable, Dict, Any, Iterable, List, Optional
from dataclasses import dataclass, field

from secops_agent.config import settings

logger = logging.getLogger(__name__)

_LONG_RUNNING_SHELL_MARKERS = (
    " apt update",
    " apt upgrade",
    " apt install",
    " apt-get update",
    " apt-get upgrade",
    " apt-get install",
    " apt full-upgrade",
    " apt-get dist-upgrade",
    " do-release-upgrade",
    " dnf upgrade",
    " dnf install",
    " yum update",
    " yum install",
    " pacman -syu",
)
_LONG_RUNNING_SHELL_TIMEOUT = 1800

class ToolCategory(str, Enum):
    RECON = "recon"
    NETWORK = "network"
    WEB = "web"
    EXPLOIT = "exploit"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    OSINT = "osint"
    SYSTEM = "system"
    MCP = "mcp"


class ToolRiskClass(str, Enum):
    PURE_LOCAL_COMPUTATION = "r0_pure_local_computation"
    LOCAL_OBSERVATION = "r1_local_observation"
    NETWORK_OBSERVATION = "r2_network_observation"
    ACTIVE_ENUMERATION = "r3_active_enumeration"
    LOCAL_FILE_ACCESS = "r4_local_file_access"
    PRIVILEGED_LOCAL_ACTION = "r5_privileged_local_action"
    OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE = "r6_offensive_payload_or_exploit_assistance"
    EXTENSION_SUPPLY_CHAIN_EXECUTION = "r7_extension_supply_chain_execution"
    CREDENTIALED_REMOTE_OR_IDENTITY_ACTION = "r8_credentialed_remote_or_identity_action"


_BUILTIN_TOOL_RISK_CLASSES: Dict[str, ToolRiskClass] = {
    "hash_identify": ToolRiskClass.PURE_LOCAL_COMPUTATION,
    "hash_generate": ToolRiskClass.PURE_LOCAL_COMPUTATION,
    "password_strength": ToolRiskClass.PURE_LOCAL_COMPUTATION,
    "sysinfo": ToolRiskClass.LOCAL_OBSERVATION,
    "lab_setup_check": ToolRiskClass.LOCAL_OBSERVATION,
    "vpn_status": ToolRiskClass.LOCAL_OBSERVATION,
    "ping_host": ToolRiskClass.NETWORK_OBSERVATION,
    "traceroute": ToolRiskClass.NETWORK_OBSERVATION,
    "port_check": ToolRiskClass.NETWORK_OBSERVATION,
    "dns_lookup": ToolRiskClass.NETWORK_OBSERVATION,
    "whois_lookup": ToolRiskClass.NETWORK_OBSERVATION,
    "http_headers": ToolRiskClass.NETWORK_OBSERVATION,
    "tech_detect": ToolRiskClass.NETWORK_OBSERVATION,
    "ssl_check": ToolRiskClass.NETWORK_OBSERVATION,
    "ssl_audit": ToolRiskClass.NETWORK_OBSERVATION,
    "cve_lookup": ToolRiskClass.NETWORK_OBSERVATION,
    "nmap_scan": ToolRiskClass.ACTIVE_ENUMERATION,
    "dir_brute": ToolRiskClass.ACTIVE_ENUMERATION,
    "subdomain_enum": ToolRiskClass.ACTIVE_ENUMERATION,
    "nikto_scan": ToolRiskClass.ACTIVE_ENUMERATION,
    "sql_injection_test": ToolRiskClass.ACTIVE_ENUMERATION,
    "xss_test": ToolRiskClass.ACTIVE_ENUMERATION,
    "waf_detect": ToolRiskClass.ACTIVE_ENUMERATION,
    "file_analyze": ToolRiskClass.LOCAL_FILE_ACCESS,
    "log_analyze": ToolRiskClass.LOCAL_FILE_ACCESS,
    "find_files": ToolRiskClass.LOCAL_FILE_ACCESS,
    "searchsploit": ToolRiskClass.LOCAL_FILE_ACCESS,
    "exploit_info": ToolRiskClass.LOCAL_FILE_ACCESS,
    "run_shell": ToolRiskClass.PRIVILEGED_LOCAL_ACTION,
    "connect_vpn_config": ToolRiskClass.PRIVILEGED_LOCAL_ACTION,
    "disconnect_vpn": ToolRiskClass.PRIVILEGED_LOCAL_ACTION,
    "generate_payload": ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE,
    # Exploitation tools
    "http_request": ToolRiskClass.ACTIVE_ENUMERATION,
    "fetch_url": ToolRiskClass.NETWORK_OBSERVATION,
    "write_file": ToolRiskClass.LOCAL_FILE_ACCESS,
    "start_listener": ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE,
    "webshell_exec": ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE,
}


def _coerce_tool_risk_class(value: ToolRiskClass | str | None) -> Optional[ToolRiskClass]:
    if value is None:
        return None
    if isinstance(value, ToolRiskClass):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return ToolRiskClass(text)
    except ValueError:
        normalized = text.upper().replace("-", "_").replace(" ", "_")
        try:
            return ToolRiskClass[normalized]
        except KeyError as exc:
            raise ValueError(f"unknown tool risk class: {value}") from exc


def infer_tool_risk_class(
    name: str,
    category: ToolCategory,
    dangerous: bool = False,
) -> ToolRiskClass:
    """Return the internal risk class for a tool without changing approvals."""
    if name in _BUILTIN_TOOL_RISK_CLASSES:
        return _BUILTIN_TOOL_RISK_CLASSES[name]
    if category == ToolCategory.MCP:
        return ToolRiskClass.EXTENSION_SUPPLY_CHAIN_EXECUTION
    if category == ToolCategory.SYSTEM:
        return (
            ToolRiskClass.PRIVILEGED_LOCAL_ACTION
            if dangerous else ToolRiskClass.LOCAL_OBSERVATION
        )
    if category in {ToolCategory.NETWORK, ToolCategory.RECON, ToolCategory.WEB}:
        return (
            ToolRiskClass.ACTIVE_ENUMERATION
            if dangerous else ToolRiskClass.NETWORK_OBSERVATION
        )
    if category == ToolCategory.FORENSICS:
        return ToolRiskClass.LOCAL_FILE_ACCESS
    if category == ToolCategory.EXPLOIT:
        return (
            ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE
            if dangerous else ToolRiskClass.LOCAL_FILE_ACCESS
        )
    if category in {ToolCategory.CRYPTO, ToolCategory.OSINT}:
        return ToolRiskClass.PURE_LOCAL_COMPUTATION
    return ToolRiskClass.ACTIVE_ENUMERATION if dangerous else ToolRiskClass.PURE_LOCAL_COMPUTATION

@dataclass
class ToolResult:
    success: bool
    output: str
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ToolProgress:
    phase: str
    detail: str = ""
    percent: Optional[float] = None

@dataclass
class ToolDefinition:
    name: str
    description: str
    category: ToolCategory
    parameters: Dict[str, Any]
    func: Callable
    dangerous: bool = False
    risk_class: ToolRiskClass = ToolRiskClass.PURE_LOCAL_COMPUTATION


class ToolArgumentValidationError(ValueError):
    """Raised when a tool call cannot be reconciled with its schema."""

ProgressReporter = Callable[[ToolProgress], Awaitable[None] | None]
_current_progress: contextvars.ContextVar[Optional[ProgressReporter]] = contextvars.ContextVar(
    "secops_tool_progress",
    default=None,
)
_current_tool_metadata: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "secops_tool_metadata",
    default=None,
)


async def report_progress(phase: str, detail: str = "", percent: Optional[float] = None):
    """Report a structured progress phase for the currently executing tool."""
    reporter = _current_progress.get()
    if not reporter:
        return

    result = reporter(ToolProgress(phase=phase, detail=detail, percent=percent))
    if inspect.isawaitable(result):
        await result


def report_tool_metadata(key: str, value: Any) -> None:
    """Attach trusted execution metadata to the current tool result."""
    metadata = _current_tool_metadata.get()
    if metadata is None:
        return
    clean_key = str(key or "").strip()
    if not clean_key:
        return
    metadata[clean_key] = value


class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        category: ToolCategory,
        parameters: Dict[str, Any],
        func: Callable,
        dangerous: bool = False,
        risk_class: ToolRiskClass | str | None = None,
    ):
        resolved_risk_class = _coerce_tool_risk_class(risk_class) or infer_tool_risk_class(
            name,
            category,
            dangerous,
        )
        self.tools[name] = ToolDefinition(
            name=name,
            description=description,
            category=category,
            parameters=parameters,
            func=func,
            dangerous=dangerous,
            risk_class=resolved_risk_class,
        )

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self.tools.get(name)

    def unregister(self, name: str) -> bool:
        return self.tools.pop(name, None) is not None

    def unregister_prefix(self, prefix: str) -> int:
        names = [name for name in self.tools if name.startswith(prefix)]
        for name in names:
            self.tools.pop(name, None)
        return len(names)

    def list_tools(self, category: Optional[ToolCategory] = None) -> List[ToolDefinition]:
        if category:
            return [t for t in self.tools.values() if t.category == category]
        return list(self.tools.values())

    @staticmethod
    def _parameter_definitions(parameters: Dict[str, Any]) -> tuple[Dict[str, Any], set[str]]:
        """Return property definitions and required names for flat or object schemas."""
        if (
            isinstance(parameters, dict)
            and parameters.get("type") == "object"
            and isinstance(parameters.get("properties"), dict)
        ):
            properties = {
                str(name): definition if isinstance(definition, dict) else {}
                for name, definition in parameters.get("properties", {}).items()
            }
            required = {
                str(name)
                for name in parameters.get("required", []) or []
                if str(name) in properties
            }
            required.update(
                name for name, definition in properties.items()
                if isinstance(definition, dict) and definition.get("required", False)
            )
            return properties, required

        properties = {
            str(name): definition if isinstance(definition, dict) else {}
            for name, definition in (parameters or {}).items()
        }
        required = {
            name for name, definition in properties.items()
            if isinstance(definition, dict) and definition.get("required", False)
        }
        return properties, required

    def get_tools_schema(self, names: Iterable[str] | None = None) -> List[Dict[str, Any]]:
        if names is None:
            ordered = list(self.tools.values())
        else:
            # Preserve caller order (and dedupe) so a ranked selection keeps
            # its priority tools first in the schema sent to the model.
            ordered = []
            seen: set[str] = set()
            for name in names:
                key = str(name)
                if key in seen:
                    continue
                seen.add(key)
                tool = self.tools.get(key)
                if tool is not None:
                    ordered.append(tool)
        schema_list = []
        for t in ordered:
            properties = {}
            param_definitions, required = self._parameter_definitions(t.parameters)
            for param_name, definition in param_definitions.items():
                # Build a clean property schema without non-standard keys
                prop = {
                    k: v for k, v in definition.items()
                    if k not in ("required", "default")
                }
                properties[param_name] = prop
            schema_entry: Dict[str, Any] = {
                "name": t.name,
                "description": t.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                },
            }
            if required:
                schema_entry["parameters"]["required"] = sorted(required)
            schema_list.append(schema_entry)
        return schema_list

    def _validated_arguments(self, tool_def: ToolDefinition, arguments: Dict[str, Any]) -> Dict[str, Any]:
        properties, required = self._parameter_definitions(tool_def.parameters)
        if not properties:
            # Some internal tests and extension hooks register deliberately
            # untyped tools. With no schema, there is nothing reliable to
            # validate, so preserve compatibility and pass arguments through.
            return dict(arguments or {})

        supplied = dict(arguments or {})
        unknown = sorted(str(name) for name in supplied if str(name) not in properties)
        if unknown:
            logger.warning(
                "Ignoring unexpected argument(s) for tool %s: %s",
                tool_def.name,
                ", ".join(unknown),
            )

        validated: Dict[str, Any] = {}
        errors: list[str] = []
        for name, definition in properties.items():
            has_value = name in supplied and supplied[name] is not None
            if has_value and self._is_blank_required_string(supplied[name], definition, name in required):
                has_value = False

            if not has_value:
                if "default" in definition:
                    validated[name] = definition["default"]
                    continue
                if name in required:
                    errors.append(f"missing required argument '{name}'")
                continue

            try:
                validated[name] = self._coerce_argument_value(
                    supplied[name],
                    definition,
                    path=name,
                )
            except ToolArgumentValidationError as exc:
                errors.append(str(exc))

        if errors:
            raise ToolArgumentValidationError("; ".join(errors))
        return validated

    @staticmethod
    def _is_blank_required_string(value: Any, definition: Dict[str, Any], required: bool) -> bool:
        raw_type = str(definition.get("type") or "string").lower()
        return required and raw_type == "string" and isinstance(value, str) and not value.strip()

    def _coerce_argument_value(self, value: Any, definition: Dict[str, Any], *, path: str) -> Any:
        raw_type = str(definition.get("type") or "string").lower()
        enum_values = definition.get("enum")

        if raw_type in {"str", "string"}:
            coerced = self._coerce_string(value, path)
        elif raw_type in {"int", "integer"}:
            coerced = self._coerce_integer(value, path)
        elif raw_type in {"float", "number"}:
            coerced = self._coerce_number(value, path)
        elif raw_type in {"bool", "boolean"}:
            coerced = self._coerce_boolean(value, path)
        elif raw_type == "array":
            coerced = self._coerce_array(value, definition, path)
        elif raw_type == "object":
            if not isinstance(value, dict):
                raise ToolArgumentValidationError(f"argument '{path}' must be an object")
            coerced = dict(value)
        else:
            coerced = value

        if isinstance(enum_values, (list, tuple)) and enum_values:
            allowed = {str(item) for item in enum_values}
            if str(coerced) not in allowed:
                raise ToolArgumentValidationError(
                    f"argument '{path}' must be one of {sorted(allowed)}"
                )
        return coerced

    @staticmethod
    def _coerce_string(value: Any, path: str) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, (list, tuple)):
            parts = []
            for item in value:
                if isinstance(item, (dict, list, tuple)):
                    raise ToolArgumentValidationError(f"argument '{path}' must be a string")
                parts.append(str(item))
            return ",".join(parts)
        raise ToolArgumentValidationError(f"argument '{path}' must be a string")

    @staticmethod
    def _coerce_integer(value: Any, path: str) -> int:
        if isinstance(value, bool):
            raise ToolArgumentValidationError(f"argument '{path}' must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                try:
                    numeric = float(stripped)
                except ValueError as exc:
                    raise ToolArgumentValidationError(f"argument '{path}' must be an integer") from exc
                if numeric.is_integer():
                    return int(numeric)
        raise ToolArgumentValidationError(f"argument '{path}' must be an integer")

    @staticmethod
    def _coerce_number(value: Any, path: str) -> float:
        if isinstance(value, bool):
            raise ToolArgumentValidationError(f"argument '{path}' must be a number")
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError as exc:
                raise ToolArgumentValidationError(f"argument '{path}' must be a number") from exc
        raise ToolArgumentValidationError(f"argument '{path}' must be a number")

    @staticmethod
    def _coerce_boolean(value: Any, path: str) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "yes", "y", "on", "1"}:
                return True
            if normalized in {"false", "no", "n", "off", "0"}:
                return False
        raise ToolArgumentValidationError(f"argument '{path}' must be a boolean")

    def _coerce_array(self, value: Any, definition: Dict[str, Any], path: str) -> list[Any]:
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]

        item_definition = definition.get("items")
        if not isinstance(item_definition, dict):
            return items
        return [
            self._coerce_argument_value(item, item_definition, path=f"{path}[]")
            for item in items
        ]

    def _execution_timeout(self, tool_def: ToolDefinition, arguments: Dict[str, Any]) -> int:
        timeout = settings.TOOL_TIMEOUT
        raw_timeout = arguments.get("timeout")
        if raw_timeout is None:
            raw_timeout = (tool_def.parameters.get("timeout") or {}).get("default")
        try:
            requested = int(raw_timeout)
        except (TypeError, ValueError):
            requested = 0
        if requested > 0:
            timeout = max(timeout, requested + 5)
        if tool_def.name == "run_shell":
            command = f" {' '.join(str(arguments.get('command') or '').lower().split())}"
            if any(marker in command for marker in _LONG_RUNNING_SHELL_MARKERS):
                timeout = max(timeout, _LONG_RUNNING_SHELL_TIMEOUT + 5)
        return max(1, timeout)

    async def execute(
        self,
        name: str,
        arguments: Dict[str, Any],
        progress: Optional[ProgressReporter] = None,
    ) -> ToolResult:
        tool_def = self.get_tool(name)
        if not tool_def:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{name}' not found in registry."
            )

        start_time = time.time()
        metadata: Dict[str, Any] = {
            "risk_class": tool_def.risk_class.value,
            "tool_category": tool_def.category.value,
        }
        try:
            arguments = self._validated_arguments(tool_def, arguments)
        except ToolArgumentValidationError as exc:
            return ToolResult(
                success=False,
                output="",
                error=f"Invalid arguments for tool '{name}': {exc}",
                execution_time=time.time() - start_time,
                metadata=dict(metadata),
            )
        progress_token = _current_progress.set(progress)
        metadata_token = _current_tool_metadata.set(metadata)
        execution_timeout = self._execution_timeout(tool_def, arguments)
        try:
            # Handle async vs sync execution
            if inspect.iscoroutinefunction(tool_def.func):
                output = await asyncio.wait_for(
                    tool_def.func(**arguments),
                    timeout=execution_timeout
                )
            else:
                # Run sync functions in thread executor
                loop = asyncio.get_running_loop()
                output = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: tool_def.func(**arguments)),
                    timeout=execution_timeout
                )
            
            execution_time = time.time() - start_time
            output_str = str(output)

            # Truncate excessively large outputs (e.g. nmap full scans)
            max_chars = getattr(settings, "MAX_TOOL_OUTPUT_CHARS", 50_000)
            if len(output_str) > max_chars:
                half = max_chars // 2
                output_str = (
                    output_str[:half]
                    + f"\n\n… [output truncated: {len(output_str)} chars total, "
                    f"showing first and last {half} chars] …\n\n"
                    + output_str[-half:]
                )

            return ToolResult(
                success=True,
                output=output_str,
                execution_time=execution_time,
                metadata=dict(metadata),
            )
            
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                output="",
                error=f"Tool execution timed out after {execution_timeout}s.",
                execution_time=execution_time,
                metadata=dict(metadata),
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time,
                metadata=dict(metadata),
            )
        finally:
            _current_progress.reset(progress_token)
            _current_tool_metadata.reset(metadata_token)

# Global tool registry
registry = ToolRegistry()

def tool(
    name: str,
    description: str,
    category: ToolCategory,
    parameters: Dict[str, Any],
    dangerous: bool = False,
    risk_class: ToolRiskClass | str | None = None,
):
    """Decorator to register a function as an agent tool."""
    def decorator(func: Callable):
        registry.register(
            name=name,
            description=description,
            category=category,
            parameters=parameters,
            func=func,
            dangerous=dangerous,
            risk_class=risk_class,
        )
        return func
    return decorator
