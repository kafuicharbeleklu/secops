# AGY TUI/TUX Rebaseline - 2026-06-03

## Purpose

Refresh the Antigravity CLI reference after the SecOps refactor work and compare
it against the current SecOps TUI before continuing implementation.

This pass is evidence-first. It does not open a new implementation ticket unless
the captured behavior shows a concrete SecOps-relevant mismatch.

## Evidence Generated

| Surface | Evidence |
| --- | --- |
| AGY full capture | `/tmp/secops_agy_rebaseline_20260603_unsandboxed/` |
| AGY focused settings/permissions capture | `/tmp/secops_agy_rebaseline_20260603_focus2/` |
| AGY request-review permission prompt | `/tmp/secops_agy_permission_rebaseline_20260603/` |
| SecOps PTY smoke capture | `/tmp/secops_tui_rebaseline_20260603.txt` |
| SecOps PTY raw capture | `/tmp/secops_tui_rebaseline_20260603.bin` |
| SecOps R11 PTY smoke capture | `/tmp/secops_tui_r11_20260603.txt` |
| SecOps R11 PTY raw capture | `/tmp/secops_tui_r11_20260603.bin` |

AGY had to be captured outside the sandbox because the sandbox blocks AGY's
local language-server socket and log file writes. The initial sandboxed AGY
capture is invalid and should not be used for comparison.

## Commands

```bash
env PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/agy_capture.py --mode full --out-dir /tmp/secops_agy_rebaseline_20260603_unsandboxed --rows 34 --cols 120 --max-scenario-seconds 35 --redacted-summary --no-print-frames
env PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/agy_capture.py --mode full --scenario config_command --scenario settings_command --scenario permissions_command --out-dir /tmp/secops_agy_rebaseline_20260603_focus2 --rows 34 --cols 120 --max-scenario-seconds 45 --redacted-summary --no-print-frames --skip-static
env PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scratch/agy_permission_prompt_capture.py --out-dir /tmp/secops_agy_permission_rebaseline_20260603 --rows 34 --cols 120 --mode request-review --max-seconds 45
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120 --raw-output /tmp/secops_tui_rebaseline_20260603.bin --text-output /tmp/secops_tui_rebaseline_20260603.txt
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120 --raw-output /tmp/secops_tui_r11_20260603.bin --text-output /tmp/secops_tui_r11_20260603.txt
```

## Capture Notes

- AGY full capture: valid after unsandboxed rerun.
- AGY `/settings`: valid and shows the settings list with `Tool Permission`.
- AGY `/permissions`: valid and shows the active permission mode picker.
- AGY `/config`: not a stable settings reference in this pass; it triggered an
  authentication flow. Use `/settings` for the settings comparison.
- AGY request-review permission prompt: valid through the dedicated capture
  script and settings restoration.
- Initial SecOps smoke: 31 pass, 2 fail.
- Post-R11 SecOps smoke: 33 pass, 0 fail.

## Initial SecOps Smoke Result

| Result | Count | Details |
| --- | ---: | --- |
| PASS | 31 | Slash palette, help, trajectory, model, config, context, hooks, MCP, skills, agents, artifact, ctrl+r, tools, statusline, tasks, slash permission commands, attachments, tool detail, editor, tool display, ctrl+o, artifact/attachment preview, tool running, streaming, streaming cancel. |
| FAIL | 2 | `permission prompt`, `permission edit`. |

## Post-R11 SecOps Smoke Result

| Result | Count | Details |
| --- | ---: | --- |
| PASS | 33 | All previous surfaces plus `permission prompt` and `permission edit`. |
| FAIL | 0 | None. |

## Current Parity Matrix

| Area | Verdict | Notes |
| --- | --- | --- |
| Startup and idle | Acceptable | SecOps intentionally keeps its own logo and does not add AGY login/account ceremony. |
| Slash palette | Pass | SecOps keeps backed commands/tools only. Pagination, filtering, backspace refresh, and duplicate suppression pass smoke. |
| Help and shortcuts | Pass | General/commands/shortcuts views match the AGY inline overlay grammar for SecOps content. |
| Model picker | Pass | Picker shape and keyboard footer match the AGY surface while using SecOps model profiles. |
| Settings/config | Pass with scope note | SecOps `/config` matches AGY `/settings` shape for backed runtime settings. AGY `/config` triggered auth in this pass, so `/settings` is the reference. |
| Artifacts and attachments | Pass | `p preview`, `enter open`, `esc dismiss` grammar is aligned. |
| Tool display and ctrl+o | Pass | Running/final rows, collapsed output, and inline ctrl+o expansion pass SecOps smoke and match captured AGY tool frames. |
| Long generation and cancel | Pass | Both show spinner progress and interruption follow-up. Text differs only in product name. |
| Permissions mode panel | Pass | AGY active permissions picker and SecOps permission mode panel share the same list/picker grammar. |
| Permission request prompt | Pass with safety scope | SecOps now matches AGY wording/shape for low-risk single-token command prompts and intentionally suppresses persistent approval for dangerous tools, sensitive commands, and broad active-scan command prefixes. |

## Concrete Gap: Permission Request Options

AGY request-review command prompt, captured from
`/tmp/secops_agy_permission_rebaseline_20260603/agy_permission_prompt_request_review.txt`:

```text
Requesting permission for: pwd
> 1. Yes
  2. Yes, and always allow in this conversation for commands that start with 'pwd'
  3. Yes, and always allow for commands that start with 'pwd' (Persist to settings.json)
  4. No
  ↑/↓ Navigate · tab Amend · e edit command
```

SecOps current prompt, captured from `/tmp/secops_tui_rebaseline_20260603.txt`:

```text
Requesting permission for: nmap 127.0.0.1
> 1. Yes
  2. Yes, allow commands that start with 'nmap 127.0.0.1' in this conversation
  3. No
  ↑/↓ Navigate · tab Amend · e edit command
```

This was a real parity gap, not only a stale smoke expectation.

However, it intersects with the SecOps permission policy from the previous
business-logic work: broad or persistent approvals for dangerous tools/commands
can be intentionally suppressed. The selected decision is hybrid parity.

## R11 Resolution

R11 is resolved.

Selected policy: **Hybrid**.

- Low-risk single-token commands such as `pwd` use AGY-like prompt grammar:
  once, session prefix, persistent prefix, and no.
- Active-scan prefixes such as `nmap 127.0.0.1` keep AGY-like session wording
  but do not expose persistent approval.
- Dangerous tools and sensitive commands keep SecOps-safe suppression.

This keeps AGY's TUI/TUX grammar for harmless commands while preserving
SecOps-specific safety for dangerous pentest actions.

## Do Not Reopen Yet

No fresh mismatch was found that justifies reopening these by default:

- Direct shell `!`.
- Login/account ceremony.
- Keybinding customization.
- Plugin/update/install/changelog lifecycle flows.
- New commands or shortcuts.

## Script Change

`scratch/agy_capture.py` now waits for the AGY prompt before sending scenario
keystrokes. This makes focused AGY captures more reliable after sign-in or slow
startup.
