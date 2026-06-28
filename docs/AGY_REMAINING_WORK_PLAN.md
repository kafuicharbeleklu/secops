# AGY Remaining Work Plan

Date: 2026-06-02

## Purpose

This is the active, short plan for what remains after the AGY parity pass.

The parity freeze report is `docs/AGY_PARITY_FREEZE_REPORT.md`.
The short operational dashboard is `docs/AGY_PARITY_STATUS_DASHBOARD.md`.
The long historical plan remains in `docs/AGY_FULL_TUI_TUX_IMPROVEMENT_PLAN.md`.
Use the dashboard for current go/no-go state, the historical plan for evidence
inventory and old comparison details, and this file to decide the next piece of
work.

## Current Position

Captured AGY parity work P1-P14 is implemented for the current SecOps scope.
The remaining work is no longer a broad implementation backlog. It is a small
set of rebaseline, evidence, and explicit decision gates.

Latest rebaseline: `docs/AGY_REBASELINE_2026-06-03.md`.

The 2026-06-03 rebaseline keeps the broad parity freeze intact. Its only
focused gap, R11 permission prompt parity versus SecOps safety policy, is now
resolved with the hybrid policy: AGY-like wording and persistent prefix approval
for low-risk single-token commands, with persistent approval suppressed for
dangerous tools, sensitive commands, and broad active-scan command prefixes.
After R11, the SecOps PTY smoke passes all 33 checked surfaces.

Current accepted constraints:

- Keep the SecOps logo.
- Do not add account/login ceremony.
- Do not add new commands or shortcuts unless explicitly selected.
- Do not copy AGY coding/browser features unless they map to real SecOps agent
  behavior.
- Keep shell execution routed through the backed tool and permission flow unless
  a direct shell shortcut is explicitly approved.
- Treat `/tmp` captures as ephemeral. Regenerate evidence before making exact
  visual decisions from an old capture path.

## What Is Done

The following surfaces are considered done for captured AGY behavior and current
SecOps scope:

| Area | Current status |
| --- | --- |
| Startup and idle frame | Done. Logo kept, account-like metadata removed, model/workspace context preserved. |
| Slash palette | Done. Backed commands only, compact rows, no invented extension/task action rows. |
| Help and shortcuts | Done. Flat list grammar, counters, selected rows, restrained shortcut coloring. |
| Model picker | Done. AGY-like picker over supported SecOps model profiles. |
| Long generation | Done. Spinner, delayed tips, `esc to cancel`, interruption follow-up. |
| Tool execution | Done. Running/final states, collapsed/expanded summaries, state-derived markers. |
| `ctrl+o` | Done. Local transcript expand/collapse, no duplicate tool rows, no trajectory fallback. |
| Permissions | Done for captured request-review behavior. Low-risk command prompts use AGY-like session/persistent prefix options; dangerous or sensitive prompts suppress persistent approval. |
| Settings/config | Done for backed runtime rows. Env/source rows stay read-only. |
| Context | Done. AGY-like budget/context display with SecOps actions. |
| Agents/tasks | Done for backed SecOps orchestration state. |
| Artifacts/attachments | Done. Review grammar uses preview/open/dismiss semantics. |
| Hooks/MCP/skills/tools | Done as backed navigable panels, without fake mutation hints. |
| CLI before TUI | Done for relevant flags, non-interactive print flow, sandbox/permission options, and `doctor`. |

## Real Remaining Work

These are the only remaining items worth tracking. Everything else should stay
closed unless new AGY evidence or a user decision reopens it.

| ID | Priority | Type | Work | Why it remains | Acceptance |
| --- | --- | --- | --- | --- | --- |
| R1 | Done | Rebaseline | Full current verification pass after the recent guard tests. | Completed on 2026-06-02. | `compileall` passed, the full suite ran `197` tests OK, and the `34x120` PTY smoke passed with regenerated `/tmp/secops_tui_smoke.txt` and `/tmp/secops_tui_smoke.bin`. |
| R2 | Done | Evidence | Stable evidence pack for the current SecOps state. | Completed on 2026-06-02. | `docs/evidence/secops_tui_2026-06-02/` stores a sanitized manifest and PTY smoke pass index while keeping raw terminal captures regenerated in `/tmp`. |
| R3 | Done | Evidence | Refreshed AGY full capture against the currently installed AGY version. | Completed on 2026-06-02. | AGY `1.0.4` was captured to `/tmp/secops_agy_full`; `docs/evidence/agy_refresh_2026-06-02/` documents the manifest, 69 interactive scenarios, 8 static CLI files, and quota limits on LLM/tool scenarios. No new implementation ticket was opened from this quota-limited refresh. |
| R4 | Deferred | Evidence | Capture strict/write-specific AGY approval prompts if possible. | The 2026-06-02 AGY `1.0.4` refresh hit individual quota on LLM/tool scenarios, so prompt-planning evidence is not currently obtainable. | Keep strict/write prompt variants deferred until quota permits a clean capture and permission UX is still a priority. |
| R5 | Done | Regression | Safe PTY smoke checks at multiple terminal sizes. | Completed on 2026-06-02. | `80x24`, `120x34`, and `160x40` PTY smoke runs passed. Captures are documented in `docs/evidence/secops_tui_2026-06-02/SIZE_REGRESSION.md`. |
| R6 | Done | Manual UX | Human review script over the important surfaces. | Completed after reviewer accepted the post-fix TUI state. | `docs/evidence/secops_tui_2026-06-02/R6_MANUAL_REVIEW_RESULT.md` records the pass; `R6_POST_FIX_REGRESSION.md` records compileall, `203` tests, and multi-size PTY smoke. |
| R7 | No-go | Scope | Direct shell `!` is not implemented in the current AGY parity scope. | It would add a new shortcut, and SecOps already has governed shell execution through tool and permission flow. | Closed by default in `docs/evidence/secops_tui_2026-06-02/R7_R8_R10_SCOPE_CLOSURE.md`. Reopen only on explicit user request. |
| R8 | No-go | Scope | Real `/keybindings` customization is not implemented in the current AGY parity scope. | `/keybindings` remains shortcut discovery; customization needs persistence, conflict handling, and a defined workflow. | Closed by default in `docs/evidence/secops_tui_2026-06-02/R7_R8_R10_SCOPE_CLOSURE.md`. Reopen only on explicit user request. |
| R9 | Done | Scope | AGY-like inline `/config` editing for backed settings only. | Completed after reviewer supplied AGY config interaction evidence. Env/config-source rows remain read-only because no real runtime editor exists. | `docs/evidence/secops_tui_2026-06-02/R9_CONFIG_INLINE_EDIT.md` documents the implementation and validation. |
| R10 | Deferred | Scope | Plugin/update/install/changelog flows. | Captured AGY surfaces are coding-agent or product lifecycle features, not current pentest-agent needs. | Deferred in `docs/evidence/secops_tui_2026-06-02/R7_R8_R10_SCOPE_CLOSURE.md`. Remain out of scope unless a real SecOps extension lifecycle is specified. |
| R11 | Done | Decision | Permission request prompt parity versus SecOps safety policy. | Completed with the hybrid policy: harmless single-token commands such as `pwd` can show AGY-like once/session/persistent/no options, while dangerous tools and sensitive or broad command prefixes do not expose persistent approval. | `scratch/tui_smoke.py` passes all 33 surfaces, including `permission prompt` and `permission edit`, with `/tmp/secops_tui_r11_20260603.txt` and `/tmp/secops_tui_r11_20260603.bin`. |

## Recommended Order

1. No broad AGY parity backlog remains for the current SecOps scope.
2. Reopen only with a failed manual row, fresh AGY evidence, or an explicit
   user decision to revisit R7, R8, R10, or R11.

## Stop Rules

- Do not continue adding guard tests without tying them to one of R1-R10.
- Do not implement a new command, shortcut, or setting editor without an
  explicit selected ID from this plan.
- Do not treat old `/tmp` evidence as authoritative if the file is missing.
- Do not reopen P1-P14 unless a fresh AGY capture shows a concrete mismatch.

## Verification Baseline

Use this command set for R1 and after any selected implementation ticket:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/agy_capture.py scratch/agy_permission_prompt_capture.py scratch/tui_smoke.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

For any TUI change, add one targeted PTY capture and compare it to the relevant
AGY evidence before marking the ticket done.
