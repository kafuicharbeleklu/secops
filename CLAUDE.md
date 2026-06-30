# CLAUDE.md

A **map + conventions** for Claude Code instances in this repo — not a procedure
manual. Multi-step playbooks live in skills and `docs/`, never here.

## What this is

SecOps Agent — a terminal-first **autonomous pentesting agent** (Python 3.12+,
Typer + `rich` + `prompt_toolkit`) backed by Google Gemini/Gemma. Target behavior:
"a senior analyst, augmented" — plan → act → observe → reflect over a mission,
with cross-mission long-term memory. The TUI/TUX tracks **Antigravity CLI (`agy`)**;
the agentic behavior tracks Claude Code / Codex CLI applied to offensive security.

**`docs/ARCHITECTURE.md` is canonical — read it before any non-trivial change to
the agent core, memory, planning, or autonomy.** It describes the *target* design
(~80% realized) and its §-numbers (§3 loop, §5 memory, §6 tools, §7 autonomy) are
referenced from code comments. `docs/BACKEND_REVIEW_2026-06-28.md` holds the live
agentic-quality backlog (P1–P6).

## Commands

Use the project venv (`.venv/bin/python`) and `PYTHONDONTWRITEBYTECODE=1`.

```bash
./setup.sh                     # (re)create .venv and install -e .
./secops                       # portable launcher: self-repairs venv, runs the TUI
GEMINI_API_KEY=... secops      # console entrypoint (= python -m secops_agent.main)
./secops doctor                # local diagnostics; no API key / no TUI

# Tests — unittest is canonical (pytest also available)
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests

# Lint — CI-blocking, correctness-only: E4/E7/E9/F (F401 ignored on purpose)
.venv/bin/ruff check secops_agent tests

# TUI smoke — run after touching prompt/overlay/footer/model/permission UI
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/tui_smoke.py --show
```

Config lives in `.env` (`GEMINI_API_KEY`, `MODEL_NAME`, `GOOGLE_SEARCH_GROUNDING`).
Default model is a Gemini *flash* tier — expect transient `500`/`429` on heavy turns.

### Driving non-interactively

```bash
secops --print "…" --permission-mode always-proceed   # one-shot text
secops --print "…" --output-format json               # lossless JSON incl. FULL tool output
secops --dangerously-skip-permissions                 # authorized targets only
```

`--print` text mode drops tool outputs; use `--output-format json` for the full output.

## Architecture (one paragraph per layer — full detail in ARCHITECTURE.md)

**Separation of powers (the core invariant — never violate).** Planner *proposes*
(`core/planner.py`), LLM *reasons/arbitrates* (`core/llm.py`), AutonomyPolicy decides
*what schemas the model sees and when to pause* (`core/autonomy.py`), Safety *authorizes*
(`permissions.py`, `scope_guard.py`, `sudo.py`, `sandbox.py`, `preflight.py`). The
**only** path to executing a tool is the safety gate. Critical: `AutonomyPolicy
.exposes_tool_schemas()` (can the model *see* it) ≠ `PermissionEngine` (may it *run* it).

**Request routing decides every turn.** `core/request_context.py` `classify_request()`
→ `RequestDecision` drives schema exposure, pause behavior, and tool selection.
`EnvironmentHint` CTF/LAB auto-escalates autonomy.

**The loop.** `core/agent.py` `SecOpsAgent.stream_response()` is the ReAct loop
(target: extract a first-class `MissionLoop`, §3). Bounded by `max_iterations` (14).
Two convergence guardrails: announced-but-unexecuted retry, and repeated-identical-call stop.

**Deterministic local-answer templates (easy to miss).** For common recon questions
(nmap "how many ports/version", gobuster "hidden dir"), `agent.py` runs the tool and
formats a **canned French template that bypasses the LLM** (`_local_preflight_answer`).
If a recon answer's wording is wrong, fix it **there**, not in a prompt.

**Memory.** Short-term: `ConversationMemory`, `MissionContext` (the **blackboard** =
canonical mission state), `KnowledgeBase`. Long-term: `ExperienceStore`/`CaseLesson`
(`core/experience.py`) — annotates and reranks, **never authorizes**; lessons are
written `unreviewed` and quarantined until human-promoted. Tool output reaches memory
**only** via `core/result_parser.py` — a tool with no parser is an OBSERVE blind spot.

**Tools.** Implementations in `secops_agent/tools/` by domain. Register with `@tool(...)`
(`core/tools.py`) and set `risk_class` (r0–r6) so autonomy/permission layers gate
correctly. Real subprocess execution belongs **only** in `tools/`. `core/mcp.py` is an
MCP **client** — it consumes external stdio servers under the `mcp_` prefix.

**Autonomy.** Default = semi-autonomous by risk: low-risk recon chains; high-risk
(exploit/write/destructive/sudo) pauses for approval. `--dangerously-skip-permissions`
→ `always-proceed` → `SANDBOX` exposure, but execution is **still** gated. A high-risk
decision always exposes the **safe-baseline floor** (never an empty schema).

## Extensions

Workspace extensions load from `.agents/`: `skills/*.md` (the *agent's own* offensive
playbooks — injected only once trusted via `/skills`, content-hash gated), `hooks.json`,
`mcp_config.json`, `agents/`. Restart the TUI after editing these.

## Conventions

- 4-space indent, `snake_case`/`PascalCase`, type hints across module boundaries,
  async for tool/LLM I/O.
- Ruff is **correctness-only** (`E4/E7/E9/F`); `F401` ignored (many "unused" imports are
  tool-registration / re-export side effects).
- Mock LLM, network, and shell in unit tests. `tests/test_*.py` is the suite;
  `secops_agent/test_agent_run.py` is for manual live runs only (real key + auth target).
- New high-impact tools must be `dangerous=True` with an appropriate `risk_class`.
  Only run scan/exploit tooling against **authorized** targets.

## Dev-environment skills (Claude Code copilot)

These are the **copilot's** skills (installed in `.claude/skills/`, project-scoped and
git-ignored), distinct from `.agents/skills/` (the *agent's* offensive playbooks).
Installed set, by axis:

- **MCP / authoring:** `mcp-builder`, `skill-creator` (`anthropics/skills`).
- **Security / hardening:** `semgrep`, `codeql`, `sarif-parsing`, `insecure-defaults`,
  `atheris` + fuzzing helpers (`trailofbits/skills`) — use to fuzz/audit the
  attacker-facing parsers (`result_parser.py`) and the `http_request`/`write_file` paths.
- **Dev hygiene:** the `superpowers` suite (`test-driven-development`,
  `systematic-debugging`, `using-git-worktrees`, `writing-plans`, …) + `modern-python`
  (matches the uv/ruff/pytest stack).

Reinstall from marketplaces (team parity): `/plugin marketplace add anthropics/skills`,
`/plugin marketplace add trailofbits/skills`, `/plugin install superpowers@claude-plugins-official`.
