# R7-R10 Decision Brief

Date: 2026-06-02

## Purpose

This brief turns the remaining scope questions from
`docs/AGY_REMAINING_WORK_PLAN.md` into explicit go/no-go decisions.

No runtime behavior is changed by this document. The goal is to prevent the AGY
parity work from drifting into unrequested commands, shortcuts, or product
lifecycle features.

## Decision Summary

| ID | Topic | Recommendation | Reason |
| --- | --- | --- | --- |
| R7 | AGY direct shell `!` | No-go | The user asked not to add unrequested shortcuts. SecOps already has governed shell execution through tool and permission flow. |
| R8 | Real `/keybindings` customization | No-go | Current scope is AGY-like discoverability, not user-defined shortcut persistence. |
| R9 | Editable `/config` rows | Done | Backed runtime settings now edit inline. Env/source rows remain read-only until a real config editor exists. |
| R10 | Plugin/update/install/changelog flows | Deferred | These are AGY product/coding-agent lifecycle surfaces, not current SecOps pentest-agent needs. |

## R7: Direct Shell `!`

Status: no-go for the current AGY parity scope.

AGY exposes direct shell entry behavior, but adding a new `!` shortcut to
SecOps would conflict with the current constraint: do not add commands or
shortcuts unless explicitly selected.

If R7 is later approved, the acceptance bar should be strict:

- `!<command>` must route through the existing SecOps shell tool.
- It must use the same permission prompt, dangerous-command handling, and audit
  path as normal tool execution.
- It must not become a raw local shell escape hatch.
- It must have PTY smoke coverage for approval, execution, output collapse, and
  `ctrl+o` expand/collapse.

No-go consequence: keep the current command/tool-mediated shell path.

## R8: `/keybindings` Customization

Status: no-go for the current AGY parity scope.

The AGY surface suggests keybinding customization, but SecOps currently needs a
clear shortcuts/help experience more than a customizable input layer. A partial
implementation would create settings complexity without a defined user workflow.

If R8 is later approved, define these first:

- Persistence target and precedence with environment settings.
- Which keys are editable and which are reserved.
- Conflict behavior when two actions use the same key.
- Reset-to-default behavior.
- Non-interactive fallback behavior when the terminal cannot capture a key.

No-go consequence: keep `/help` and shortcuts as read-only discovery surfaces.

## R9: Editable `/config` Rows

Status: done for backed runtime settings.

The reviewer supplied AGY evidence for the inline settings editor, so SecOps now
implements the same interaction model for settings that already have backed
runtime semantics. Rows that reflect environment variables, source paths,
availability, or detected state remain read-only.

Allowed candidates:

- Current model/profile selection.
- Permission mode when already backed by the permission manager.
- Sandbox mode when already backed by settings.
- UI profile/theme only if already backed by settings.

Do not edit:

- API key presence or secret values.
- Paths that are only detected from the current process.
- Provider availability rows.
- Any row without clear persistence semantics.

Implemented criteria:

- The editable row can be changed, persisted, reloaded, and tested.
- Read-only rows are visually distinct without noisy warning text.
- Narrow-terminal rendering still truncates cleanly.

Implementation evidence:

- `docs/evidence/secops_tui_2026-06-02/R9_CONFIG_INLINE_EDIT.md`

## R10: Plugin, Update, Install, Changelog Flows

Recommendation: deferred.

AGY includes product and coding-agent lifecycle surfaces. SecOps should not copy
those unless the project defines an actual SecOps extension lifecycle.

R10 should stay deferred until at least one real requirement exists, such as:

- Installable SecOps tool packs.
- Versioned rules or knowledge packs.
- A supported update channel for the CLI.
- A changelog source that can be shown from inside the TUI.

Deferred consequence: do not add plugin/update/install/changelog rows only for
visual AGY parity.

## Current Result

R7 and R8 are closed as no-go for the current scope, R9 is done, and R10 remains
deferred. See:

- `docs/evidence/secops_tui_2026-06-02/R7_R8_R10_SCOPE_CLOSURE.md`
