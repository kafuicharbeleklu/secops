# R6 Assisted Precheck

Date: 2026-06-02

## Scope

This is an automated, text-based precheck for R6 from
`docs/AGY_REMAINING_WORK_PLAN.md`.

It does not replace the required human review in a real terminal. It only
checks that the latest scripted TTY capture does not show the known regressions
that previously caused user-visible pollution.

## Fresh Capture

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

Outputs:

- Raw capture: `/tmp/secops_tui_smoke.bin`
- Text capture: `/tmp/secops_tui_smoke.txt`

Result: all scripted scenarios passed.

## Checked Regressions

| Area | Automated result | Notes |
| --- | --- | --- |
| Slash/help/model/config panels | Pass after R6 slash-palette fix | Scripted overlay scenarios passed. Slash palette now hides alias duplicate rows, refreshes suggestions after backspace/delete, and renders `↑/↓ N more` according to list position. |
| Permission prompt | Pass with manual attention | Current command approval wording uses the documented AGY request-review `commands that start with ...` shape plus SecOps shell-control guards. Strict/write-specific AGY prompt variants remain quota-blocked. |
| Tool result collapse | Pass | Fresh capture shows a single final `Bash(pwd)` output block for the TTY `ctrl+o` path. |
| `ctrl+o` fallback | Pass | Fresh capture did not open `/trajectory` as the `ctrl+o` result. |
| Running tool state | Pass | Running state uses `○ Bash(...)` and final state uses `● Bash(...)`. |
| Streaming/cancel | Pass | Scripted generation and cancellation scenarios passed. Raw text contains repeated spinner frames because the smoke log records time progression, not because the final terminal frame is stale. |
| Unrequested lifecycle rows | Pass with scope caveat | Plugin/update/install/changelog mutation flows remain out of scope. `/keybindings` is still a shortcuts view, not advertised here as customization. |

## Human Review Still Required

R6 should remain `Ready`, not `Done`, until a reviewer runs
`MANUAL_UX_REVIEW.md` in a real terminal.

The most important rows to inspect visually are:

- Permission prompt spacing and long option truncation.
- `ctrl+o` expand/collapse during and after a real tool execution.
- Long-generation spinner cleanup after interruption.
- Slash/help scrolling with actual arrow keys at the user's daily terminal size.

## Recommendation

Do not open new implementation work from this precheck alone.

If the real terminal review fails, create focused follow-up tickets from the
exact failed rows in `R6_RESULT_TEMPLATE.md`.

## Follow-Up Fixes

- `R6_FIX_SLASH_PALETTE.md`: fixed duplicate alias rows, disappearing slash
  suggestions after deletion, and missing upper pagination hint.
- `R6_FIX_CLEAR_BANNER.md`: fixed `/clear` printing raw ANSI fragments in the
  banner.
- `R9_CONFIG_INLINE_EDIT.md`: aligned backed `/config` settings with AGY-style
  inline edit/select behavior.
- `R6_POST_FIX_REGRESSION.md`: records the post-fix compile, `203` tests, and
  multi-size PTY smoke pass.
