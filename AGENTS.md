# AGENTS.md — SECOPS Agent

## Project Overview

SECOPS is a conversational pentest agent with a rich terminal UI. It provides an agentic loop powered by Gemini that can reason, execute tools, manage targets, and maintain memory across authorized lab environments.

The codebase is entirely in **Python 3.14** with no web frontend. The terminal UI uses `prompt_toolkit` and `colorama`.

## Repository Layout

```
secops/
├── .env                          # API keys (GEMINI_API_KEY)
├── entrypoints/
│   ├── setup_secops_agent.sh     # First-time setup (venv + deps)
│   ├── run_secops_agent.sh       # Launch the agent
│   ├── setup_secops_agent.bat    # Windows setup
│   └── run_secops_agent.bat      # Windows launcher
├── knowledge/                    # Case memory files (TryHackMe, HTB…)
├── templates/automation_project/ # Main application
│   ├── main.py                   # Entrypoint
│   ├── requirements.txt          # colorama, prompt-toolkit, google-genai
│   ├── app/
│   │   ├── shell_template.py     # Generic TUI shell base class
│   │   ├── project_shell.py      # SECOPS shell (main orchestrator)
│   │   ├── agent_loop.py         # Agentic reasoning loop
│   │   ├── terminal_renderer.py  # Codex-style event stream renderer
│   │   ├── tool_executor.py      # Tool execution engine
│   │   ├── tool_registry.py      # Pentest tool detection & install
│   │   ├── llm_client.py         # Gemini tool-calling LLM wrapper
│   │   ├── gemini_client.py      # Low-level Gemini API client
│   │   ├── knowledge_store.py    # Case memory store
│   │   ├── target_context.py     # Target detection & context
│   │   ├── methodology.py        # Pentest phase state machine
│   │   ├── findings.py           # Findings accumulator
│   │   ├── settings.py           # Environment & config resolution
│   │   ├── branding.py           # Project name, palette, chrome
│   │   ├── catalog.py            # Target/profile catalog
│   │   └── workflows.py          # Pluggable workflow handlers
│   ├── tests/                    # Unit test suite (122 tests)
│   ├── docs/                     # ADAPTATION_CHECKLIST.md, PROJECT_MAP.md
│   ├── workspace/                # Generated artifacts
│   └── config/                   # Runtime config & history
└── workspace/                    # Top-level workspace artifacts
```

## Setup & Run

```bash
# First-time setup
cd secops/entrypoints
sudo bash setup_secops_agent.sh

# Run the agent
bash run_secops_agent.sh
```

The virtual environment lives at `templates/automation_project/.venv`.

## Running Tests

```bash
cd templates/automation_project
.venv/bin/python -m unittest discover -s tests
```

All 122 tests must pass. Never submit changes that break existing tests.

## Environment Variables

| Variable             | Required | Default            | Description                    |
|----------------------|----------|--------------------|--------------------------------|
| `GEMINI_API_KEY`     | Yes      | —                  | Gemini API key                 |
| `GOOGLE_API_KEY`     | Fallback | —                  | Alternative API key variable   |
| `GEMINI_MODEL`       | No       | `gemini-2.5-flash` | Model to use                   |
| `SECOPS_COMMAND_MODE`| No       | `ask`              | `ask`, `session`, or `deny`    |

Variables are read from `secops/.env` via `app/settings.py`.

## Architecture Principles

### Agent-Centric Design
All user input goes through the agentic loop (`agent_loop.py`). There are **no regex-based command shortcuts** that intercept natural language — the LLM handles intent processing. Only explicit `/commands` are dispatched by the shell.

### Shell Commands
Commands are defined in `COMMAND_SPECS` at the top of `project_shell.py`. Current commands:

- `/help` — Show available commands
- `/case [list|slug|off]` — List, show, activate or deactivate a case
- `/target [list|ip/url]` — List, show or set the active target
- `/phase [name]` — Show or change the pentest phase
- `/tools` — List available pentest tools
- `/findings` — Show accumulated findings
- `/quit` — Exit the shell

**No duplicate commands.** `/case` handles both listing and activation. `/target` handles both listing and setting. Do not re-introduce `/cases` or `/targets` as separate commands.

### Event Stream & Terminal Rendering
The agent loop yields events that are rendered by `TerminalRenderer`:
- `thought` → displayed as `• [text]` (no emoji, never 💭)
- `tool_start` → displayed as `• Ran [action]`
- `tool_success` → displayed as `  └ [result]`
- `answer` → final answer text
- `error` → error events

The UI follows a **Codex-inspired aesthetic**: minimal, tree-structured output with Braille spinners (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`).

### Prompt Placeholder (not Banner)
The contextual hint ("Decris ton objectif…") is rendered as a `prompt_toolkit` **placeholder** inside the input field, not as a printed banner above the prompt. It disappears when the user starts typing. Do not add printed `Tip:` or `hint` banners.

### Live Streaming
`self.live_agent_stream = True` enables real-time incremental display of agent thoughts and actions. The shell does **not** clear the screen between interactions — it preserves conversation history.

## Key Design Constraints

1. **No emojis in the UI.** Use ASCII/Unicode symbols only (bullets `•`, tree connectors `└`, Braille spinners).
2. **French language.** All user-facing strings, command descriptions, tips, and panel content are in French.
3. **`ask` mode for sudo.** When `SECOPS_COMMAND_MODE=ask`, privileged commands require interactive user approval. Passwords are never persisted.
4. **No placeholder IPs.** The agent must never invent `TARGET_IP` or similar placeholders. If a target is needed, it asks the user.
5. **Tool installation via `install_pentest_tool`.** The agent never runs `apt install` directly through `execute_command`. It uses the dedicated `install_pentest_tool` tool which routes through `tool_executor.py`.
6. **Preserve comments and docstrings.** When editing code, keep existing documentation intact unless specifically modifying it.

## Code Style

- Pure Python, no type-checking enforced but type hints welcome.
- `dataclass` for value objects (`StatusEntry`, `ShellPalette`, `Target`, etc.).
- Inheritance: `AutomationProjectShell` extends `BaseTerminalShell` from `shell_template.py`.
- Tests use `unittest` with `unittest.mock`. No pytest.
- No external test dependencies beyond the standard library.

## Common Pitfalls

- `KnowledgeStore` exposes `.cases` (a list property) and `.case_count`. There is no `list_cases()` method.
- `project_shell.py` overrides `render_shell_header()`, `prompt()`, `_toolbar()`, and `interactive_loop()` from the base class. Changes to the base class may not take effect if the override exists.
- The base class `shell_template.py` also defines `prompt()` and `render_shell_header()`. The project shell has its own versions. When modifying prompt behavior, edit `project_shell.py`, not `shell_template.py` alone.
- Tests mock `GeminiClient` and `ToolCallingLLMClient` extensively. Check test fixtures when modifying these classes.

## File Editing Priority

When making changes, the most commonly modified files are:

1. `app/project_shell.py` — Shell logic, commands, UI orchestration
2. `app/agent_loop.py` — Agent reasoning, tool calling loop
3. `app/terminal_renderer.py` — Output formatting
4. `app/tool_executor.py` — Tool execution, permissions
5. `app/shell_template.py` — Base TUI framework
6. `tests/test_project_shell.py` — Main test suite

## Verification Checklist

Before considering any change complete:

1. Run the full test suite: `.venv/bin/python -m unittest discover -s tests`
2. All 122+ tests must pass
3. No new warnings or deprecation errors
4. If UI was changed, verify the shell renders correctly via `bash run_secops_agent.sh`
