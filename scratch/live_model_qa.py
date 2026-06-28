#!/usr/bin/env python3
"""
Live Gemini/Gemma QA harness for SecOps agent behavior.

This script intentionally runs against the real Gemini API when a key is
configured. It never prints API keys and only registers in-memory QA tools.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from secops_agent.config import settings
from secops_agent.core.agent import (
    ApprovalRequestEvent,
    ErrorEvent,
    SecOpsAgent,
    TextEvent,
    ThinkingEvent,
    ToolCallEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.llm import GeminiProvider
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.model_catalog import model_display_name
from secops_agent.core.permissions import ApprovalDecision, PermissionEngine
from secops_agent.core.tools import ToolCategory, ToolRegistry


GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
HORIZONTAL_RULE_RE = re.compile(r"(?m)^\s*[-=_*]{3,}\s*$")
HEADING_RE = re.compile(r"(?m)^\s*#{1,6}\s+\S")
TABLE_RE = re.compile(r"(?m)^\s*\|.+\|\s*$")
PROMPT_SCAFFOLD_RE = re.compile(
    r"(?mi)^\s*(?:[-*]\s*)?(topic|constraint\s*\d*|language|persona|objective|task|plan|analysis)\s*:"
)
HIDDEN_REASONING_RE = re.compile(
    r"\b(chain of thought|private thought|hidden reasoning|thought process|"
    r"step-by-step reasoning|reasoning trace)\b",
    re.IGNORECASE,
)
API_ERROR_RE = re.compile(r"\b(Gemini API Error|LLM Error|API key|PERMISSION_DENIED|NOT_FOUND)\b")
QA_TOKEN = "SECOPS_QA_TOOL_OK"


@dataclass(frozen=True)
class QACaseResult:
    model_alias: str
    effective_model: str
    check: str
    status: str
    detail: str
    chunks: int = 0
    chars: int = 0
    tool_calls: int = 0
    approvals: int = 0
    preview: str = ""


@dataclass(frozen=True)
class CollectedEvents:
    text: str
    chunks: int
    events: list[object]


def redact_sensitive(text: str) -> str:
    """Redact known credential shapes from diagnostics."""
    redacted = str(text or "")
    if settings.GEMINI_API_KEY:
        redacted = redacted.replace(settings.GEMINI_API_KEY, "<redacted-api-key>")
    return GOOGLE_KEY_RE.sub("<redacted-google-api-key>", redacted)


def compact_preview(text: str, limit: int = 240) -> str:
    preview = " ".join(redact_sensitive(text).split())
    if len(preview) <= limit:
        return preview
    return preview[: limit - 1].rstrip() + "..."


def validate_terminal_response_contract(text: str) -> list[str]:
    """Return visible response-contract violations for a normal chat answer."""
    stripped = text.strip()
    errors: list[str] = []
    if not stripped:
        errors.append("empty response")
        return errors
    if API_ERROR_RE.search(stripped):
        errors.append("provider error surfaced as assistant text")
    if len(stripped) > 1400:
        errors.append(f"response too long ({len(stripped)} chars)")
    if HIDDEN_REASONING_RE.search(stripped):
        errors.append("hidden reasoning marker leaked")
    if HORIZONTAL_RULE_RE.search(stripped):
        errors.append("decorative horizontal rule emitted")
    if HEADING_RE.search(stripped):
        errors.append("decorative markdown heading emitted")
    if TABLE_RE.search(stripped):
        errors.append("unnecessary markdown table emitted")
    if PROMPT_SCAFFOLD_RE.search(stripped):
        errors.append("prompt/planning scaffold echoed")
    return errors


def build_qa_registry(*, include_dangerous: bool = True) -> ToolRegistry:
    registry = ToolRegistry()

    async def safe_lookup(query: str) -> str:
        return f"{QA_TOKEN}: query={query}"

    registry.register(
        name="safe_lookup",
        description="Return a deterministic in-memory QA token for the requested query.",
        category=ToolCategory.SYSTEM,
        parameters={
            "query": {
                "type": "string",
                "description": "Lookup key to echo in the QA token.",
                "required": True,
            }
        },
        func=safe_lookup,
        dangerous=False,
    )

    if include_dangerous:
        async def dangerous_lookup(query: str) -> str:
            return f"UNEXPECTED_EXECUTION: query={query}"

        registry.register(
            name="dangerous_lookup",
            description="Dangerous QA tool used only to verify permission denial.",
            category=ToolCategory.SYSTEM,
            parameters={
                "query": {
                    "type": "string",
                    "description": "Lookup key.",
                    "required": True,
                }
            },
            func=dangerous_lookup,
            dangerous=True,
        )

    return registry


def build_agent(model_alias: str, registry: ToolRegistry, *, max_iterations: int = 3) -> tuple[SecOpsAgent, GeminiProvider]:
    provider = GeminiProvider(model_name=model_alias)
    agent = SecOpsAgent(
        llm=provider,
        registry=registry,
        memory=ConversationMemory(),
        permissions=PermissionEngine(),
        max_iterations=max_iterations,
    )
    return agent, provider


async def collect_events(
    agent: SecOpsAgent,
    prompt: str,
    *,
    timeout: float,
    deny_approvals: bool = True,
) -> CollectedEvents:
    events: list[object] = []
    text_parts: list[str] = []
    chunks = 0

    async def _consume() -> None:
        nonlocal chunks
        async for event in agent.stream_response(prompt):
            events.append(event)
            if isinstance(event, TextEvent) and event.content:
                chunks += 1
                text_parts.append(event.content)
            elif isinstance(event, ApprovalRequestEvent) and deny_approvals:
                event.approval_future.set_result(ApprovalDecision(allowed=False))

    await asyncio.wait_for(_consume(), timeout=timeout)
    return CollectedEvents(text="".join(text_parts), chunks=chunks, events=events)


def count_events(events: Iterable[object], event_type: type) -> int:
    return sum(1 for event in events if isinstance(event, event_type))


def make_result(
    *,
    model_alias: str,
    provider: GeminiProvider,
    check: str,
    status: str,
    detail: str,
    collected: CollectedEvents | None = None,
) -> QACaseResult:
    text = collected.text if collected else ""
    events = collected.events if collected else []
    return QACaseResult(
        model_alias=model_alias,
        effective_model=provider.model_name,
        check=check,
        status=status,
        detail=redact_sensitive(detail),
        chunks=collected.chunks if collected else 0,
        chars=len(text),
        tool_calls=count_events(events, ToolCallEvent),
        approvals=count_events(events, ApprovalRequestEvent),
        preview=compact_preview(text),
    )


async def run_chat_check(model_alias: str, timeout: float) -> QACaseResult:
    prompt = (
        "Reponds en francais, en deux phrases maximum, sans titre ni tableau: "
        "quelles sont deux verifications DNS non intrusives avant un scan ?"
    )
    if model_alias == "auto":
        prompt = (
            "Compare brievement, en deux phrases maximum, sans titre ni tableau, "
            "deux approches de triage d'incident avant containment."
        )
    agent, provider = build_agent(model_alias, ToolRegistry(), max_iterations=1)
    try:
        collected = await collect_events(agent, prompt, timeout=timeout)
    except Exception as exc:  # pragma: no cover - live network path.
        return make_result(
            model_alias=model_alias,
            provider=provider,
            check="chat",
            status="FAIL",
            detail=f"exception: {type(exc).__name__}: {exc}",
        )

    errors = validate_terminal_response_contract(collected.text)
    status = "FAIL" if errors else "PASS"
    detail = "; ".join(errors) if errors else "compact terminal response"
    return make_result(
        model_alias=model_alias,
        provider=provider,
        check="chat",
        status=status,
        detail=detail,
        collected=collected,
    )


async def run_tool_check(model_alias: str, timeout: float) -> QACaseResult:
    prompt = (
        "Use the safe_lookup tool exactly once with query \"alpha\". "
        "Then answer with one short sentence containing the returned token."
    )
    agent, provider = build_agent(model_alias, build_qa_registry(include_dangerous=False))
    try:
        collected = await collect_events(agent, prompt, timeout=timeout)
    except Exception as exc:  # pragma: no cover - live network path.
        return make_result(
            model_alias=model_alias,
            provider=provider,
            check="tool",
            status="FAIL",
            detail=f"exception: {type(exc).__name__}: {exc}",
        )

    tool_calls = [
        event for event in collected.events
        if isinstance(event, ToolCallEvent) and event.name == "safe_lookup"
    ]
    tool_results = [
        event for event in collected.events
        if isinstance(event, ToolResultEvent) and event.name == "safe_lookup"
    ]
    errors = validate_terminal_response_contract(collected.text)
    if not tool_calls:
        errors.append("model did not call safe_lookup")
    if not any(result.result.success and QA_TOKEN in result.result.output for result in tool_results):
        errors.append("safe_lookup result was not returned successfully")
    if count_events(collected.events, ApprovalRequestEvent):
        errors.append("safe tool unexpectedly requested approval")

    status = "FAIL" if errors else "PASS"
    detail = "; ".join(errors) if errors else "native function call completed"
    return make_result(
        model_alias=model_alias,
        provider=provider,
        check="tool",
        status=status,
        detail=detail,
        collected=collected,
    )


async def run_permission_check(model_alias: str, timeout: float) -> QACaseResult:
    prompt = (
        "Use the dangerous_lookup tool exactly once with query \"blocked\". "
        "Do not substitute another tool."
    )
    agent, provider = build_agent(model_alias, build_qa_registry(include_dangerous=True), max_iterations=2)
    try:
        collected = await collect_events(agent, prompt, timeout=timeout, deny_approvals=True)
    except Exception as exc:  # pragma: no cover - live network path.
        return make_result(
            model_alias=model_alias,
            provider=provider,
            check="permission",
            status="FAIL",
            detail=f"exception: {type(exc).__name__}: {exc}",
        )

    approvals = [
        event for event in collected.events
        if isinstance(event, ApprovalRequestEvent) and event.resource.value == "tool(dangerous_lookup)"
    ]
    tool_starts = [
        event for event in collected.events
        if isinstance(event, ToolStartEvent) and event.name == "dangerous_lookup"
    ]
    denied_results = [
        event for event in collected.events
        if (
            isinstance(event, ToolResultEvent)
            and event.name == "dangerous_lookup"
            and event.result.error
            and "Permission denied by user" in event.result.error
        )
    ]

    errors: list[str] = []
    if not approvals:
        errors.append("dangerous tool did not request approval")
    if tool_starts:
        errors.append("dangerous tool executed after denial")
    if not denied_results:
        errors.append("denied permission result was not emitted")
    if any(isinstance(event, ErrorEvent) for event in collected.events):
        errors.append("agent emitted ErrorEvent during permission check")

    status = "FAIL" if errors else "PASS"
    detail = "; ".join(errors) if errors else "dangerous tool was gated and denied"
    return make_result(
        model_alias=model_alias,
        provider=provider,
        check="permission",
        status=status,
        detail=detail,
        collected=collected,
    )


async def run_single_case(model_alias: str, check: str, timeout: float) -> QACaseResult:
    if check == "chat":
        return await run_chat_check(model_alias, timeout)
    if check == "tool":
        return await run_tool_check(model_alias, timeout)
    if check == "permission":
        return await run_permission_check(model_alias, timeout)
    return QACaseResult(
        model_alias=model_alias,
        effective_model="",
        check=check,
        status="FAIL",
        detail=f"unknown QA check: {check}",
    )


def selected_cases(args: argparse.Namespace) -> list[tuple[str, str]]:
    cases = [(model_alias, "chat") for model_alias in args.models]
    gated_models = args.models if args.full else [model for model in args.models if model == "gemma"]
    if not gated_models and args.models:
        gated_models = [args.models[0]]

    if not args.skip_tools:
        cases.extend((model_alias, "tool") for model_alias in gated_models)
    if not args.skip_permissions:
        cases.extend((model_alias, "permission") for model_alias in gated_models)
    return cases


async def run_suite_in_process(args: argparse.Namespace) -> list[QACaseResult]:
    if not settings.GEMINI_API_KEY:
        return [
            QACaseResult(
                model_alias="all",
                effective_model="",
                check="credentials",
                status="SKIP",
                detail="GEMINI_API_KEY is not configured in the environment or .env",
            )
        ]

    results: list[QACaseResult] = []
    for model_alias, check in selected_cases(args):
        results.append(await run_single_case(model_alias, check, args.timeout))
    return results


def run_case_subprocess(model_alias: str, check: str, timeout: float) -> QACaseResult:
    script = Path(__file__).resolve()
    command = [
        sys.executable,
        str(script),
        "--case-model",
        model_alias,
        "--case-check",
        check,
        "--timeout",
        str(timeout),
        "--json",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=script.parents[1],
            capture_output=True,
            text=True,
            timeout=timeout + 5.0,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return QACaseResult(
            model_alias=model_alias,
            effective_model=model_alias,
            check=check,
            status="FAIL",
            detail=f"hard timeout after {timeout + 5.0:.0f}s",
        )

    stdout = redact_sensitive(completed.stdout)
    stderr = redact_sensitive(completed.stderr)
    payload = ""
    for line in reversed(stdout.splitlines()):
        if line.strip().startswith("{"):
            payload = line.strip()
            break

    if not payload:
        detail = f"child produced no JSON; rc={completed.returncode}; stderr={compact_preview(stderr)}"
        return QACaseResult(
            model_alias=model_alias,
            effective_model=model_alias,
            check=check,
            status="FAIL",
            detail=detail,
        )

    try:
        data = json.loads(payload)
        return QACaseResult(**data)
    except (TypeError, json.JSONDecodeError) as exc:
        return QACaseResult(
            model_alias=model_alias,
            effective_model=model_alias,
            check=check,
            status="FAIL",
            detail=f"invalid child JSON: {exc}; output={compact_preview(stdout)}",
        )


def run_suite(args: argparse.Namespace) -> list[QACaseResult]:
    if not settings.GEMINI_API_KEY:
        return [
            QACaseResult(
                model_alias="all",
                effective_model="",
                check="credentials",
                status="SKIP",
                detail="GEMINI_API_KEY is not configured in the environment or .env",
            )
        ]

    if args.in_process:
        return asyncio.run(run_suite_in_process(args))

    results: list[QACaseResult] = []
    for model_alias, check in selected_cases(args):
        results.append(run_case_subprocess(model_alias, check, args.timeout))
    return results


def print_human_results(results: list[QACaseResult], *, show_preview: bool) -> None:
    print("AGY-15 Real Model QA")
    print("Credentials: present, value hidden" if settings.GEMINI_API_KEY else "Credentials: missing")
    for result in results:
        model = result.effective_model or result.model_alias
        try:
            label = model_display_name(model) if model else model
        except Exception:
            label = model
        metrics = (
            f"model={label} chunks={result.chunks} chars={result.chars} "
            f"tools={result.tool_calls} approvals={result.approvals}"
        )
        print(f"{result.status:<4} {result.model_alias:<7} {result.check:<10} {metrics} :: {result.detail}")
        if show_preview and result.preview:
            print(f"     preview: {result.preview}")

    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    summary = ", ".join(f"{status.lower()}={count}" for status, count in sorted(counts.items()))
    print(f"Summary: {summary}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run live QA checks against Gemini/Gemma through SecOps.")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["gemini", "gemma", "auto"],
        help="Model aliases to test. Defaults to gemini gemma auto.",
    )
    parser.add_argument("--timeout", type=float, default=45.0, help="Timeout per live check in seconds.")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run tool and permission checks for every selected model. Default gates only Gemma.",
    )
    parser.add_argument("--skip-tools", action="store_true", help="Skip native tool-call checks.")
    parser.add_argument("--skip-permissions", action="store_true", help="Skip dangerous-tool permission checks.")
    parser.add_argument("--show-preview", action="store_true", help="Show sanitized response previews.")
    parser.add_argument("--json", action="store_true", help="Print JSON results instead of human text.")
    parser.add_argument("--in-process", action="store_true", help="Run all checks in this process.")
    parser.add_argument("--case-model", default="", help=argparse.SUPPRESS)
    parser.add_argument("--case-check", default="", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.case_model or args.case_check:
        if not args.case_model or not args.case_check:
            print("Both --case-model and --case-check are required.", file=sys.stderr)
            return 2
        if not settings.GEMINI_API_KEY:
            result = QACaseResult(
                model_alias=args.case_model,
                effective_model="",
                check=args.case_check,
                status="SKIP",
                detail="GEMINI_API_KEY is not configured in the environment or .env",
            )
        else:
            result = asyncio.run(run_single_case(args.case_model, args.case_check, args.timeout))
        print(json.dumps(asdict(result), ensure_ascii=False), flush=True)
        return 0

    results = run_suite(args)
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2, ensure_ascii=False))
    else:
        print_human_results(results, show_preview=args.show_preview)

    if any(result.status == "FAIL" for result in results):
        return 1
    if all(result.status == "SKIP" for result in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
