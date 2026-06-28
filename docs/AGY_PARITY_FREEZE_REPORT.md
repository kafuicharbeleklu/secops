# AGY Parity Freeze Report

Date: 2026-06-02

## Status

The AGY-style TUI/TUX parity pass is frozen for the current SecOps scope.

No additional implementation work should be started from the AGY parity backlog
unless one of these happens:

- A new manual review finds a concrete failed surface.
- A fresh AGY capture shows a concrete mismatch that is relevant to SecOps.
- The user explicitly selects one of the remaining scope decisions.

## Completed Scope

The following areas are complete for captured AGY behavior and SecOps-relevant
functionality:

- Startup and idle frame.
- Slash palette and slash filtering.
- Help and shortcuts views.
- Model picker.
- Long generation and interruption UX.
- Tool execution, status markers, collapsed/expanded output.
- `ctrl+o` inline transcript expand/collapse.
- Permission mode panel and request-review approval prompt.
- `/config` settings list and inline editing for backed settings.
- Context usage view.
- Agents/tasks orchestration view.
- Artifacts and attachments review.
- Hooks, MCP, skills, and tools panels backed by SecOps state.
- Relevant CLI flags and non-interactive flow.
- `/clear` banner rendering.

## Frozen Defaults

| Item | Frozen default |
| --- | --- |
| SecOps logo | Keep. |
| Account/login ceremony | Do not add. |
| New shortcuts | Do not add unless explicitly selected. |
| AGY direct shell `!` | Do not implement by default. |
| `/keybindings` customization | Do not implement by default. |
| Plugin/update/install/changelog flows | Keep deferred. |
| Env/source config rows | Keep read-only until real persistence exists. |

## Evidence

| Evidence | File |
| --- | --- |
| Active remaining-work plan | `docs/AGY_REMAINING_WORK_PLAN.md` |
| Operational status dashboard | `docs/AGY_PARITY_STATUS_DASHBOARD.md` |
| Historical comparison and implementation plan | `docs/AGY_FULL_TUI_TUX_IMPROVEMENT_PLAN.md` |
| SecOps evidence pack | `docs/evidence/secops_tui_2026-06-02/` |
| AGY refresh evidence | `docs/evidence/agy_refresh_2026-06-02/` |
| R6 manual pass | `docs/evidence/secops_tui_2026-06-02/R6_MANUAL_REVIEW_RESULT.md` |
| R6 post-fix regression | `docs/evidence/secops_tui_2026-06-02/R6_POST_FIX_REGRESSION.md` |
| R9 config inline edit | `docs/evidence/secops_tui_2026-06-02/R9_CONFIG_INLINE_EDIT.md` |

## Latest Verification

- Compileall: pass.
- Full unit suite: `203` tests OK.
- Multi-size PTY smoke after fixes:
  - `80x24`: pass.
  - `120x34`: pass.
  - `160x40`: pass.
- Manual R6 review: pass.

## Remaining Non-Frozen Gates

| ID | State | Default |
| --- | --- | --- |
| R4 | Deferred | Wait for AGY quota before strict/write approval capture. |
| R7 | No-go | Reopen only if direct shell `!` is explicitly selected. |
| R8 | No-go | Reopen only if real keybinding customization is explicitly selected. |
| R10 | Deferred | No-go unless a real SecOps lifecycle requirement exists. |

## Resume Rule

If this work is resumed later, start from this file and
`docs/AGY_PARITY_STATUS_DASHBOARD.md`.

Do not restart the broad AGY comparison. Open a focused ticket only when there is
new evidence or an explicit selected decision item.
