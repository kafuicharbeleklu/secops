# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SecOps Agent — a terminal-first **autonomous pentesting agent** (Python 3.12+, Typer + `rich` + `prompt_toolkit`) backed by Google Gemini/Gemma. The target behavior is "a senior analyst, augmented": plan → act → observe → reflect over a mission, with long-term cross-mission memory. The TUI/TUX deliberately tracks **Antigravity CLI (`agy`)**; the agentic behavior tracks Claude Code / Codex CLI applied to offensive security.

`docs/ARCHITECTURE.md` is the canonical, authoritative architecture document — **read it before any non-trivial change to the agent core, memory, planning, or autonomy.** It describes the *target* design (~80% realized in code) and uses section numbers (§3 loop, §5 memory, §6 tools, §7 autonomy) that the code references in comments.

## Commands

Use the project venv (`.venv/bin/python`) and `PYTHONDONTWRITEBYTECODE=1` to avoid `__pycache__` churn.

```bash
./setup.sh                              # (re)create .venv and install -e . ; run after moving the repo
./secops                                # portable launcher: self-repairs a broken/missing venv, then runs the TUI
GEMINI_API_KEY=... secops               # installed console-script entrypoint (same as python -m secops_agent.main)
./secops doctor                         # local diagnostics; no API key / no TUI

# Tests (unittest is the canonical runner; pytest is also available)
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_request_routing.SafeBaselineToolExposureTests   # one class
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_request_routing.SafeBaselineToolExposureTests.test_goal_specific_tools_rank_before_baseline  # one test

# Lint (CI-blocking gate) — correctness-only: E4/E7/E9/F, with F401 ignored
.venv/bin/ruff check secops_agent tests

# TUI smoke harness — run after touching prompt/overlay/footer/model/permission UI
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/tui_smoke.py --show
```

Config lives in `.env` (`GEMINI_API_KEY`, `MODEL_NAME`, `GOOGLE_SEARCH_GROUNDING`). The default model is a Gemini *flash* tier — expect transient `500 INTERNAL` / `429` on heavy turns; a single 500 currently aborts a `--print` run.

### Driving the agent non-interactively

```bash
secops --print "…" --permission-mode always-proceed            # one-shot, prints text
secops --print "…" --output-format json                        # one-shot, lossless JSON incl. FULL tool outputs
secops --prompt-interactive "…"                                # run a prompt, then keep the TUI open
secops --dangerously-skip-permissions                          # authorized targets only (see autonomy note below)
```

`--print` text mode emits only model text (tool outputs are collapsed/dropped); use `--output-format json` when you need the complete tool output.

## Architecture: the parts that span multiple files

### Separation of powers (the core invariant — do not violate)

The single most important rule (ARCHITECTURE.md §1): each layer has one power and never reaches into the next. The **only** path to executing a tool is through the safety gate.

- **Planner** (`core/planner.py`, `MissionPlanner.plan` → `NextAction[]`) *proposes* candidate actions from mission state — never executes.
- **LLM** (`core/llm.py`, `GeminiProvider`) *reasons* and picks/justifies — never bypasses the gate.
- **Autonomy** (`core/autonomy.py`, `AutonomyPolicy`) decides *what tool schemas the model even sees* and *when to pause* — never authorizes execution.
- **Safety** (`core/permissions.py` `PermissionEngine`, `scope_guard.py`, `sudo.py`, `sandbox.py`, `preflight.py`) *authorizes* execution — never proposes.

**Critical distinction:** `AutonomyPolicy.exposes_tool_schemas()` (can the model *see* the tool) is independent from `PermissionEngine` (may the agent *run* it). `--dangerously-skip-permissions` normalizes to permission mode `always-proceed`, which `_apply_permission_mode` (main.py) maps to `AutonomyLevel.SANDBOX` so high-risk exploit schemas are exposed; execution is still gated by `PermissionEngine`. Even under skip-permissions, a high-risk decision exposes the **safe baseline floor** of tools (never an empty schema) so the model is never blinded.

### Request routing decides everything per turn

`core/request_context.py` `classify_request()` → `RequestDecision` (`.risk` = `RequestRisk` EXPLOIT/DESTRUCTIVE/…, `.user_intent`, `.environment_hint`). This decision drives schema exposure, pause behavior, and tool selection (`tool_schema_selector`). `EnvironmentHint` CTF/LAB escalates autonomy automatically (`AutonomyPolicy.for_environment`).

### The agent loop

`core/agent.py` `SecOpsAgent.stream_response()` is the ~800-line ReAct-style loop (the target is to extract a first-class `MissionLoop`, ARCHITECTURE.md §3). It yields events consumed by the UI and by `--print`: `TextEvent`, `ToolResultEvent`, `ApprovalRequestEvent`, `SuggestedActionsEvent`, `ErrorEvent`. Bounded by `max_iterations` (default 14). Two convergence guardrails live here: the *announced-but-unexecuted* retry (`_announces_unexecuted_action`) and the *repeated identical tool call* stop.

### Deterministic local-answer templates (easy to miss)

For common recon questions (nmap "how many ports / what version", gobuster "hidden directory"), `agent.py` runs the tool and formats a **canned French template that bypasses the LLM entirely** — `SecOpsAgent._local_preflight_answer` (with `_local_preflight_tool_calls`), in the `nmap_scan` / `dir_brute` branches. If a recon answer's wording/format is wrong, fix it **here**, not in a prompt. Gobuster candidate prioritization uses `SecOpsAgent._dir_candidate_score`.

### Memory: three short-term registers + one long-term store

(ARCHITECTURE.md §5.) Short term: `ConversationMemory` (sliding window, `core/memory.py`), `MissionContext`/`PentestPhase` (the **blackboard** = canonical mission state, `core/mission.py`), `KnowledgeBase` (facts extracted from tool output, `core/structured_memory.py`). Long term, cross-mission: `ExperienceStore`/`CaseLesson` (`core/experience.py`) — annotates and reranks proposals, **never authorizes**. Tool output reaches memory only via `core/result_parser.py` (`ToolResultParser` → `ParsedResult` → `KnowledgeBase.integrate`); a tool with no parser is a blind spot in OBSERVE.

### Tools

Implementations live in `secops_agent/tools/` by domain (`network.py` nmap, `web.py` gobuster/nikto/sqlmap wrappers, `exploitation.py` `http_request`/`write_file`/`start_listener`/`webshell_exec`, `recon.py`, `crypto.py`, `forensics.py` VPN + `run_shell`). Register with the `@tool(name, description, category=ToolCategory.…, parameters={…}, dangerous=True/False)` decorator (`core/tools.py`); set `risk_class` (`ToolRiskClass` r0–r6) so the autonomy/permission layers can gate correctly. Real subprocess execution belongs only in `tools/`.

### Extensions and non-interactive surfaces

Workspace extensions load from `.agents/`: `skills/*.md` (markdown skills — **only injected once trusted via `/skills`**, gated by content hash), `hooks.json` (`before_tool`/`after_tool`/`on_error`), `mcp_config.json`, and `agents/`. Restart the TUI after editing extension files.

## Conventions

- 4-space indent, `snake_case`/`PascalCase`, type hints across module boundaries, async for tool/LLM I/O.
- Ruff is a **correctness-only** gate (`E4/E7/E9/F`); `F401` is intentionally ignored because many "unused" imports are tool-registration / re-export side effects.
- Mock LLM, network, and shell in unit tests. `tests/test_*.py` is the suite; `secops_agent/test_agent_run.py` is for manual live runs only (real key + authorized target).
- Only run scan/exploit tooling against authorized targets. New high-impact tools must be `dangerous=True` with an appropriate `risk_class`.
