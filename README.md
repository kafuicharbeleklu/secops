# SecOps Agent

SecOps Agent is a terminal-first security operations assistant with an Antigravity-style TUI. It combines Gemini/Gemma model routing, slash-command workflows, guarded tool execution, async side tasks, MCP servers, workspace skills, hooks, and structured scan progress.

## Features

- Minimal `rich` + `prompt_toolkit` interface with inline slash completion and a persistent statusline.
- Gemini/Gemma model aliases with optional automatic routing.
- Security tools for recon, network scanning, web testing, exploitation support, crypto checks, forensics, and system inspection.
- Granular approval flow for dangerous tools, with session-level allow/deny rules.
- Background side questions via `/btw`, plus shared `/agents` and `/tasks` orchestration views.
- Extension surfaces for `.agents/agents`, `.agents/skills`, `.agents/hooks.json`, and `.agents/mcp_config.json`.
- Pseudo-terminal smoke harness for prompt, overlay, model, and permission UX checks.

## Installation

```bash
./setup.sh
cp .env.example .env
```

## Portabilité et Maintenance

Si vous déplacez le dossier du projet, l'environnement virtuel (`.venv`) risque de se casser à cause des chemins absolus. 

- **Pour tout réparer d'un coup** : Lancez `./setup.sh`. Il recréera l'environnement proprement.
- **Utilisation recommandée** : Utilisez le script `./secops` à la racine. Il est conçu pour être portable et trouvera toujours le bon environnement, même après un déplacement.

Set a Gemini API key in `.env` or in the environment:

```bash
export GEMINI_API_KEY="your_api_key_here"
```

Launch the agent:

```bash
secops
```

Useful options:

```bash
secops --model gemma
secops --model auto
secops --session previous_session
secops --print "Summarize safe DNS checks before scanning example.com"
secops --prompt-interactive "Start a recon checklist for an authorized target"
secops --sandbox --permission-mode proceed-in-sandbox
secops doctor
```

Pre-TUI CLI entrypoints:

- `--api-key` / `-k <key>` supplies the Gemini API key for this run.
- `--model` / `-m <alias-or-model>` selects the startup model.
- `--session` / `-s <name>` preloads a saved session.
- `--print` / `-p` / `--prompt <text>` runs one prompt and prints the response without entering the TUI.
- `--print-timeout <seconds>` changes the non-interactive prompt timeout.
- `--prompt-interactive` / `-i <text>` runs an initial prompt, then keeps the interactive session open.
- `--sandbox` enables restricted terminal command execution from startup.
- `--permission-mode plan|request-review|proceed-in-sandbox|always-proceed|strict` selects the initial approval policy. `plan` renders proposed active steps but denies every tool and shell execution for the session.
- `--dangerously-skip-permissions` auto-approves tools and shell commands for the current session; use only on authorized targets.
- `--add-dir <path>` adds an extra workspace directory before the TUI starts.
- `--log-file <path>` overrides the CLI log file path.
- `--no-animation` is accepted as a compatibility flag; startup animation is already disabled.
- `doctor` prints local diagnostics without requiring an API key or starting the TUI.

## Models

Accepted model aliases:

- `gemini`, `flash`, `gemini-flash`, `default`, or `defaut`: `gemini-2.5-flash`
- `gemma`, `gemma-4`, `gemma-fast`, or `gemma-26b`: `gemma-4-26b-a4b-it` with thinking off
- `gemma-high`, `gemma-thinking`, or `gemma-26b-high`: `gemma-4-26b-a4b-it` with thinking high
- `gemma-31b-off`: `gemma-4-31b-it` with thinking off
- `gemma-31b` or `gemma-31b-high`: `gemma-4-31b-it` with thinking high
- `auto`: routes between Gemma fast and strategy profiles based on the prompt
- `pro`, `gemini-pro`, `gemini-2.5-pro`, or `25-pro`: gemini-2.5-pro
- `gemini-3.5`, `gemini-3.5-flash`, or `flash-3.5`: gemini-3.5-flash
- `gemini-3`, `gemini-3-flash`, or `3-flash`: gemini-3-flash-preview
- `gemini-3-pro` or `3-pro`: gemini-3-pro-preview
- `gemini-2.0`, `gemini-2.0-flash`, or `2.0-flash`: gemini-2.0-flash
- `gemini-3.1-pro` or `3.1-pro`: gemini-3.1-pro-preview
- `gemini-3.1-flash-lite` or `3.1-flash-lite`: gemini-3.1-flash-lite
- `gemini-2.5` or `gemini-25-flash`: gemini-2.5-flash

Gemma 4 thinking can be passed with `/model`, for example:

```text
/model gemma off
/model gemma high
/model gemma-31b-off
/model gemma-31b
```

Gemma 4 uses Gemini API thinking as an on/off capability in this agent.
`low` and `medium` are intentionally rejected for Gemma 4 instead of being
silently mapped to another mode.

Gemini/Gemma hosted models also receive attached images as multimodal input when
you add them with `/attach <path>` or press `ctrl+v` with a copied local file or
clipboard image. Clipboard image capture uses local desktop tools when available
(`wl-paste` on Wayland, `xclip` on X11) and falls back to plain text paste when
they are missing. Google Search grounding is controlled with
`GOOGLE_SEARCH_GROUNDING=off|auto|on`; `auto` enables grounding only for
web/current-information prompts.

`GEMINI_MODEL` is still accepted as an OldSecops-compatible environment alias.

## Slash Commands

Core workflow:

```text
/help
/tools
/tool <name>
/context
/history
/trajectory
/clear
/exit
```

Runtime and UX:

```text
/model
/statusline
/config
/fast
/permissions [allow|ask|deny|clear] <resource>
/sandbox [on|off|status]
/keybindings
/auto [on|off]
```

Tasks and sessions:

```text
/btw <query>
/agents
/tasks
/task <id> [logs]
/cancel <id>
/save <name>
/load <name>
/sessions
/resume
/rewind
/export <name>
/report [name]
/lessons [list|review <id> <reviewed|blocked|deprecated> [note]]
```

Evidence review:

```text
/plan [scope <target>]
/artifact [id|list]
/attach <path> [note]
```

Extensions and workspace:

```text
/skills
/hooks
/mcp
/add-dir <path>
/diff
```

## Tools And Safety

Tools are registered by category in `secops_agent/tools/`. Dangerous actions such as `nmap_scan`, `subdomain_enum`, `dir_brute`, `nikto_scan`, `sql_injection_test`, `xss_test`, `waf_detect`, `generate_payload`, `run_shell`, `connect_vpn_config`, `disconnect_vpn`, `ffuf_scan`, `nuclei_scan`, `start_listener`, `write_file`, `webshell_exec`, and `http_request` require approval unless a session rule allows them. Active-enumeration scans (`nmap_scan`, `subdomain_enum`, r3) route through approval before they touch a real target — their permission tier tracks their `risk_class`, not a laxer default.

Example permission rules:

```text
/permissions allow tool(nmap_scan)
/permissions deny tool(run_shell)
/permissions clear
```

Granting a *blanket allow* on a privileged/exploit tool (r5+, e.g. `run_shell`) or a compound command needs an explicit second confirmation, so the CLI can't silently widen the approval UI's safety posture:

```text
/permissions allow tool(run_shell) confirm
```

Only run scan and exploitation tools against systems you are authorized to test.

## Extensions

Agent profiles are discovered from:

```text
.agents/agents/{agent_name}/agent.json
~/.secops_agent/agents/{agent_name}/agent.json
```

Workspace skills are Markdown files loaded from:

```text
.agents/skills/*.md
```

Hooks are loaded from:

```text
.agents/hooks.json
```

Supported hook events are `before_tool`, `after_tool`, and `on_error`.

MCP servers are loaded from:

```text
.agents/mcp_config.json
```
Restart the TUI after editing extension files for a clean refresh.

## Validation

Run unit tests in the project venv:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -v
```

Run the TUI smoke harness after changing prompt, overlay, footer, model, or permission code:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/tui_smoke.py --show
```

The harness waits for the prompt, sends slash commands with a real Enter event, validates the permission approval prompt, and stores raw/clean captures in `/tmp/secops_tui_smoke.*`.
