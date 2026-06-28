# R6 Fix: `/clear` Banner ANSI Leak

Date: 2026-06-02

## Reported Issue

After running `/clear`, the SecOps banner was printed with visible ANSI escape
fragments such as:

```text
[1;38;2;255;205;17m...
[m
```

## Cause

Startup rendered the ANSI banner through `Text.from_ansi(...)`, but `/clear`
printed the raw banner string directly through Rich. That exposed color escape
sequences as text in some terminal paths.

## Fix

- Added a shared `_render_header_banner(...)` helper.
- Startup and `/clear` now both render the banner through `Text.from_ansi(...)`.
- Added a regression test to ensure the helper output does not expose textual
  ANSI fragments.

## Validation

Commands run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_tui_polish.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/tui_smoke.py tests
```

Results:

- `tests/test_tui_polish.py`: 163 tests OK.
- Full unittest suite: 203 tests OK.
- Compileall: OK.

Manual PTY check:

- Sent `/clear`.
- Final terminal frame showed the SecOps banner, welcome line, prompt, and
  footer.
- `ANSI_LEAK_VISIBLE=False`.
