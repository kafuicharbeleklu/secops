# SecOps TUI Size Regression

Date: 2026-06-02

## Scope

This records R5 from `docs/AGY_REMAINING_WORK_PLAN.md`: PTY smoke verification
across small, standard, and wide terminal sizes.

## Results

| Terminal size | Result | Text capture | Raw ANSI capture |
| --- | --- | --- | --- |
| `80x24` | Pass | `/tmp/secops_tui_smoke_80x24.txt` | `/tmp/secops_tui_smoke_80x24.bin` |
| `120x34` | Pass | `/tmp/secops_tui_smoke_120x34.txt` | `/tmp/secops_tui_smoke_120x34.bin` |
| `160x40` | Pass | `/tmp/secops_tui_smoke_160x40.txt` | `/tmp/secops_tui_smoke_160x40.bin` |

## Note

The first `80x24` run exposed a smoke-harness assertion that was too strict for
truncated permission-copy at narrow width. The runtime rendered a clipped line
with an ellipsis instead of overflowing. The harness was updated to accept this
valid narrow rendering while preserving the wider AGY wording checks.

All final reruns passed, including:

- `permission prompt`
- `permission edit`
- `tool display`
- `ctrl+o inline`
- `tool running`
- `tool running ctrl+o`
- `streaming display`
- `streaming cancel`

