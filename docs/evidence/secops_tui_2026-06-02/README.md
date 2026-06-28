# SecOps TUI Evidence Pack

Date: 2026-06-02

## Scope

This evidence pack preserves the current SecOps TUI state after the AGY parity
pass and the R1 rebaseline.

It intentionally does not copy raw AGY captures. It also does not copy the full
SecOps PTY transcript into versioned docs because the transcript contains local
workspace paths. The current raw and text smoke captures remain regenerated in
`/tmp` and can be recreated with the command below.

## Verification Result

| Check | Result |
| --- | --- |
| Syntax/import compilation | Pass |
| Full unit suite | Pass, `197` tests |
| Full PTY smoke | Pass, `34x120` terminal |
| Smoke text capture | `/tmp/secops_tui_smoke.txt` |
| Smoke raw ANSI capture | `/tmp/secops_tui_smoke.bin` |
| Smoke text line count | `1180` lines |

## Commands Used

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent scratch/agy_capture.py scratch/agy_permission_prompt_capture.py scratch/tui_smoke.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

## Evidence Files

- `SMOKE_PASS_INDEX.md`: stable index of the PTY smoke scenarios and source
  line numbers in `/tmp/secops_tui_smoke.txt`.

## Regeneration Notes

Use the commands above to regenerate the current evidence. If the `/tmp` files
are missing, do not make visual claims from this pack alone; rerun the smoke and
compare the regenerated transcript against the scenario index.

