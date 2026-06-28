# R6 Fix: Slash Palette Alias And Backspace Behavior

Date: 2026-06-02

## Reported Issue

During manual R6 review, the slash palette showed duplicate command surfaces for
aliases such as:

- `/permissions` and `/permission`
- `/artifact` and `/artifacts`

Follow-up review found remaining semantic duplicates:

- `/task` alongside `/tasks`
- bare `/tool` alongside `/tools` and direct `/tool <name>` tool entries

The reviewer also observed that suggestions could disappear after typing a
valid command prefix and then deleting characters. The palette also only showed
the lower pagination hint in some states, while AGY shows both `↑ N more` and
`↓ N more` when the visible window is in the middle of the list.

## Fix

Runtime changes:

- Root slash completion now lists canonical commands only. Aliases still work
  when typed manually, but they are not advertised as separate palette rows.
- Detail-only duplicates are hidden from the root palette:
  - `/task` remains executable when typed manually, but `/tasks` is the visible
    task entry.
  - bare `/tool` remains executable when typed manually, but `/tools` and direct
    `/tool <name>` rows are the visible tool entries.
- Backspace/delete refresh slash completions when the current input still starts
  with `/`.
- The completion toolbar now renders `↑ N more` above the visible rows when
  hidden commands exist above the current window, and `↓ N more` below when
  hidden commands exist below.

Smoke coverage:

- `/per` shows `/permissions` only.
- Backspace from `/per` to `/pe` keeps `/permissions` visible.
- `/art` shows `/artifact` only.
- `/ta` shows `/tasks` only.
- `/to` shows `/tools` plus direct `/tool <name>` entries, without a bare
  `/tool` row.
- Deep slash navigation shows both upper and lower hidden-row indicators.

## Validation

Commands run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_tui_polish.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/tui_smoke.py tests
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120 --raw-output /tmp/secops_tui_smoke.bin --text-output /tmp/secops_tui_smoke.txt
```

Results:

- `tests/test_tui_polish.py`: 160 tests OK.
- Follow-up `tests/test_tui_polish.py`: 161 tests OK.
- Follow-up full unittest suite: 201 tests OK.
- Compileall: OK.
- Full `34x120` PTY smoke: all scenarios PASS.

Additional direct frame checks:

- `/per` frame showed only `/permissions`.
- Backspace frame showed prompt `/pe` with `/permissions` still visible.
- `/art` frame showed only `/artifact`; `ALIAS_VISIBLE=False`.
- Follow-up `/ta` smoke showed only `/tasks`.
- Follow-up `/to` smoke showed `/tools` plus direct `/tool <name>` rows, with
  no bare `/tool` row.
