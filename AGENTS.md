# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.12+ CLI/TUI package for a SecOps agent. The installable package is `secops_agent/`. `secops_agent/main.py` defines the Typer entry point and chat loop, while `config.py` loads environment settings. Core agent logic lives in `secops_agent/core/` (`agent.py`, `llm.py`, `memory.py`, `tools.py`). Security tool implementations are grouped in `secops_agent/tools/` by domain, such as `network.py`, `web.py`, `recon.py`, and `forensics.py`. Terminal rendering, menus, input handling, and theme code live in `secops_agent/ui/`. Shared helpers and logging are in `secops_agent/utils/`. Root-level assets include `.env.example`, `README.md`, `logo .jpeg`, and `agy_dropdown_capture.bin`.

## Build, Test, and Development Commands

- `uv pip install -e ".[dev]"`: install the package plus dev tooling (ruff, pytest).
- `GEMINI_API_KEY=... secops`: launch the interactive agent.
- `secops --model gemini-2.5-pro`: run with an explicit Gemini model.
- `ruff check secops_agent tests`: run the correctness lint gate (matches CI).
- `python -m unittest discover -s tests`: run the unit test suite (canonical runner).
- `python -m compileall secops_agent`: perform a quick syntax/import compilation check.
- `python secops_agent/test_agent_run.py`: run the live smoke script; requires `GEMINI_API_KEY` and may invoke agent tools.

## Coding Style & Naming Conventions

Use 4-space indentation, standard Python naming (`snake_case` for functions and modules, `PascalCase` for classes), and type hints where interfaces cross modules. Keep event/result containers as dataclasses when they are simple structured data. Prefer async functions for tool or LLM operations that perform I/O. Register agent tools with the existing `@tool(...)` decorator and a clear `ToolCategory`; name tool functions after their command intent, for example `nmap_scan` or `dns_lookup`.

## Testing Guidelines

The `tests/` directory holds ~33 `unittest`-style modules (`test_*.py`). Run them with `python -m unittest discover -s tests`. Add focused tests as `tests/test_*.py`. Mock LLM calls, network probes, and shell command execution for unit tests. Reserve `secops_agent/test_agent_run.py` for manual live verification with real credentials and authorized targets only.

Known baseline: ~19 TUI-parity tests in `test_tui_polish.py` currently fail on glyph/spacing drift and need triage (renderer vs. stale assertions). The CI test job is non-blocking until this is resolved; see `docs/ARCHITECTURE.md` §8.

## Commit & Pull Request Guidelines

Local Git history is unavailable in this checkout, so no existing commit convention can be inferred. Use concise, imperative commit subjects such as `Add DNS lookup timeout handling`. Pull requests should describe the behavior change, list verification commands, call out security impact, and include terminal screenshots or recordings for TUI changes.

## Security & Configuration Tips

Copy `.env.example` to `.env` for local configuration, but never commit real API keys or logs. Treat scan and exploit-oriented tools as sensitive: run them only against systems you are authorized to test, and mark new high-impact tools with `dangerous=True` so the approval flow can protect users.
