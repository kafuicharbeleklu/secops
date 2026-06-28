# R6 Post-Fix Regression

Date: 2026-06-02

## Scope

This records the automated regression pass after the manual R6 fixes for:

- Slash palette duplicate cleanup and backspace refresh.
- AGY-like inline `/config` editing.
- `/clear` banner ANSI leak.

R6 still requires human visual review before it can be marked done.

## Commands

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/tui_smoke.py tests
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 24 --cols 80 --raw-output /tmp/secops_tui_smoke_80x24_postfix.bin --text-output /tmp/secops_tui_smoke_80x24_postfix.txt
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120 --raw-output /tmp/secops_tui_smoke_120x34_postfix.bin --text-output /tmp/secops_tui_smoke_120x34_postfix.txt
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 40 --cols 160 --raw-output /tmp/secops_tui_smoke_160x40_postfix.bin --text-output /tmp/secops_tui_smoke_160x40_postfix.txt
```

## Results

| Check | Result |
| --- | --- |
| Compileall | Pass |
| Full unittest suite | Pass, `203` tests OK |
| `80x24` PTY smoke | Pass |
| `120x34` PTY smoke | Pass |
| `160x40` PTY smoke | Pass |

## Capture Outputs

| Terminal size | Text capture | Raw ANSI capture |
| --- | --- | --- |
| `80x24` | `/tmp/secops_tui_smoke_80x24_postfix.txt` | `/tmp/secops_tui_smoke_80x24_postfix.bin` |
| `120x34` | `/tmp/secops_tui_smoke_120x34_postfix.txt` | `/tmp/secops_tui_smoke_120x34_postfix.bin` |
| `160x40` | `/tmp/secops_tui_smoke_160x40_postfix.txt` | `/tmp/secops_tui_smoke_160x40_postfix.bin` |

## Covered Surfaces

All final PTY smoke runs passed, including:

- Slash palette root, prefix filtering, deletion refresh, hidden-row hints.
- Help views and arrow navigation.
- `/config` inline edit mode.
- `/clear` banner leak check through dedicated PTY verification.
- Permission prompt and permission edit flow.
- Tool result, `ctrl+o`, running tool, and running-tool `ctrl+o`.
- Artifact and attachment review.
- Streaming display and cancellation.

## Remaining Manual Step

Run the R6 manual review script in a real terminal and record pass/fail rows in
`R6_RESULT_TEMPLATE.md`. Automated regression is clean, but R6 should not be
marked done until the real terminal review passes.
