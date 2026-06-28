# R7/R8/R10 Scope Closure

Date: 2026-06-02

## Purpose

This closes the remaining AGY parity scope gates that were intentionally left
as decisions after R6 and R9.

No runtime behavior is changed by this document.

## Decisions

| ID | Decision | Reason |
| --- | --- | --- |
| R7 | No-go by default | Direct shell `!` would add a new shortcut. SecOps already routes shell execution through governed tool and permission flow. |
| R8 | No-go by default | Real keybinding customization is beyond AGY-like discoverability and would need persistence, conflict handling, and a defined user workflow. |
| R10 | Deferred | Plugin/update/install/changelog flows require a real SecOps extension or product lifecycle before they should exist in the TUI. |

## R7: Direct Shell `!`

Closed as no-go for the current AGY parity scope.

The command should not be implemented unless the user explicitly reopens R7.
If reopened, acceptance remains strict:

- Route through existing permission and audit controls.
- No raw shell escape hatch.
- PTY coverage for approval, execution, output collapse, and `ctrl+o`.

## R8: Keybinding Customization

Closed as no-go for the current AGY parity scope.

`/keybindings` remains a read-only shortcut discovery surface. Do not advertise
customization until persistence, reserved keys, conflict behavior, reset
behavior, and terminal fallback are designed.

## R10: Lifecycle Flows

Deferred.

Do not add plugin/update/install/changelog rows just for visual AGY parity.
Reopen only if SecOps gains a real backed lifecycle such as tool packs,
versioned rules, an update channel, or a changelog source.

## Result

There is no active AGY parity implementation backlog for the current SecOps
scope.

Future work should start from a concrete failed manual row, fresh AGY evidence,
or an explicit user decision to reopen R7, R8, or R10.
