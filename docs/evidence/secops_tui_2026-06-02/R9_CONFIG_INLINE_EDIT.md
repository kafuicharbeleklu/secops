# R9 Fix: AGY-Like Inline Config Editing

Date: 2026-06-02

## AGY Evidence Added By Reviewer

AGY `/config` renders a settings list with:

- `Search:` field.
- Selected setting row with `enter Edit`.
- Inline expanded choices under the selected setting.
- Current value marked with `(current)`.
- Footer changing from `↑/↓ Navigate · enter Edit · Esc Clear Search/Exit` to
  `↑/↓ Navigate · enter Select` while editing.
- Esc returning from edit mode to the settings list.

## SecOps Scope

SecOps now follows that interaction model for backed runtime settings only.

Editable rows:

- `Response Profile`: `standard`, `fast`
- `Model`: supported SecOps model display names
- `Tool Permission`: `request-review`, `proceed-in-sandbox`, `always-proceed`, `strict`
- `Sandbox Mode`: `on`, `off`

Read-only rows remain read-only:

- `Tool Timeout`
- `Max Output Tokens`
- `Rendering Mode`
- `Workspace Access`
- `Log File`
- `Config Source`

## Fix

- `SettingsItem` now supports inline options.
- `/config` no longer jumps to separate `/model` or `/permissions` menus when
  editing from the settings panel.
- `enter` expands editable rows in place.
- `esc` exits edit mode back to the settings list.
- Selecting a value applies it through the existing SecOps runtime handlers.

## Validation

Commands run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_tui_polish.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/tui_smoke.py tests
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120 --raw-output /tmp/secops_tui_smoke.bin --text-output /tmp/secops_tui_smoke.txt
```

Results:

- `tests/test_tui_polish.py`: 162 tests OK.
- Full unittest suite: 202 tests OK.
- Compileall: OK.
- Full `34x120` PTY smoke: all scenarios PASS.

Evidence capture:

- `/tmp/secops_tui_config_inline.txt` shows `Sandbox Mode` expanded inline with
  `on`, `> off (current)`, and `↑/↓ Navigate · enter Select`.
- `/tmp/secops_tui_smoke.txt` was regenerated after the full smoke pass.
