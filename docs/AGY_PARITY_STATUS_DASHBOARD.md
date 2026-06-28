# AGY Parity Status Dashboard

Date: 2026-06-03

## Status

The AGY-style TUI/TUX parity pass is implemented for the current SecOps scope.
The focused R11 decision from the 2026-06-03 rebaseline has been resolved with
the hybrid permission prompt policy.

This dashboard is the short operational view. The freeze report is
`docs/AGY_PARITY_FREEZE_REPORT.md`, the active plan remains
`docs/AGY_REMAINING_WORK_PLAN.md`, and the historical comparison remains
`docs/AGY_FULL_TUI_TUX_IMPROVEMENT_PLAN.md`.

## Current State

| Area | State | Evidence |
| --- | --- | --- |
| AGY parity freeze | Complete | `docs/AGY_PARITY_FREEZE_REPORT.md` |
| P1-P14 implementation | Complete for captured SecOps-relevant scope | `docs/AGY_REMAINING_WORK_PLAN.md` |
| Latest rebaseline | Complete; R11 resolved | `docs/AGY_REBASELINE_2026-06-03.md`; after the R11 hybrid permission prompt fix, SecOps PTY smoke passes all 33 checked surfaces. |
| SecOps evidence pack | Complete | `docs/evidence/secops_tui_2026-06-02/` |
| Fresh AGY capture | Complete with quota limits | `docs/evidence/agy_refresh_2026-06-02/` |
| Multi-size SecOps smoke | Complete | `80x24`, `120x34`, `160x40` passed |
| R6 assisted precheck | Complete after post-fix regression | `docs/evidence/secops_tui_2026-06-02/R6_ASSISTED_PRECHECK.md`, `docs/evidence/secops_tui_2026-06-02/R6_POST_FIX_REGRESSION.md` |
| R6 human review | Complete | `docs/evidence/secops_tui_2026-06-02/R6_MANUAL_REVIEW_RESULT.md` |
| R7-R10 decisions | Closed for current scope: R7 no-go, R8 no-go, R9 done, R10 deferred | `docs/evidence/secops_tui_2026-06-02/R7_R8_R10_SCOPE_CLOSURE.md`, `docs/evidence/secops_tui_2026-06-02/R9_CONFIG_INLINE_EDIT.md` |

## Open Gates

| Gate | State | What would close it |
| --- | --- | --- |
| R4 strict/write AGY approval capture | Deferred | AGY quota must allow clean LLM/tool-planning capture. |
| R6 manual UX review | Done | Reviewer accepted the post-fix TUI state. |
| R7 direct shell `!` | No-go | Reopen only on explicit user request. |
| R8 real keybinding customization | No-go | Reopen only on explicit user request. |
| R9 editable config rows | Done | Inline editor implemented for backed runtime settings only; env/source rows remain read-only. |
| R10 plugin/update/install/changelog flows | Deferred | Real SecOps extension or lifecycle requirement must be defined. |
| R11 permission prompt parity | Done | Hybrid low-risk-only persistent approval implemented and validated; dangerous/sensitive prompts keep SecOps-safe suppression. |

## Recommended Next Move

1. Treat AGY parity as frozen for the current SecOps scope unless a
   new failed manual row is reported.
2. Reopen R7, R8, or R10 only if that scope decision is explicitly useful.
3. Keep R4 deferred until AGY quota permits strict/write approval capture.

## Defaults Unless User Overrides

| Item | Default |
| --- | --- |
| R7 direct shell `!` | Do not implement. |
| R8 custom keybindings | Do not implement. |
| R9 editable config | Done for backed runtime settings; do not extend to env/source rows without real persistence. |
| R10 lifecycle flows | Keep deferred. |
| R11 permission prompt parity | Done with hybrid policy; do not broaden persistent approvals without a new safety decision. |

## Stop Conditions

- Do not add more guard tests unless tied to a failed R6 row or selected R7-R10
  item.
- Do not add new commands or shortcuts without an explicit selected item.
- Do not copy AGY plugin/update/install/changelog surfaces without backed
  SecOps lifecycle behavior.
- Do not reopen R6 without a concrete failed manual row.
- Do not reopen R7, R8, or R10 without an explicit user request or backed
  SecOps lifecycle requirement.
