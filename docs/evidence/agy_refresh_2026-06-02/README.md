# AGY Refresh Evidence

Date: 2026-06-02

## Scope

This pack records the metadata for the refreshed AGY full capture used by R3 of
`docs/AGY_REMAINING_WORK_PLAN.md`.

Raw AGY captures are not copied into versioned docs because they may contain
account or local-machine identifiers. The regenerated raw capture root is:

```text
/tmp/secops_agy_full
```

## Capture Summary

| Item | Value |
| --- | --- |
| AGY version | `1.0.4` |
| Capture mode | `full` |
| Terminal size | `34x120` |
| Capture root | `/tmp/secops_agy_full` |
| Static CLI files | `8` |
| Interactive frame captures | `69` |
| Total files | `216` |
| Approximate size | `992K` |
| Capture harness | `scratch/agy_capture.py` |

## Static CLI Captures

The refreshed capture includes static help outputs for:

- `agy --version`
- `agy --help`
- `agy help`
- `agy plugin --help`
- `agy plugins --help`
- `agy install --help`
- `agy update --help`
- `agy changelog --help`

These remain evidence sources only. Plugin, install, update, and changelog
flows are not SecOps implementation targets without backed SecOps behavior.

## Capture Limits

The AGY refresh hit an individual quota limit during the LLM-dependent
scenarios:

- `generation_short_prompt`
- `long_generation`
- `long_generation_cancel_esc`
- `permission_probe_pwd`
- `tool_pwd_ctrl_o_after`
- `tool_sleep_long`
- `tool_sleep_ctrl_o_during`

Because of that quota state, this refresh does not provide new usable evidence
for generation, tool execution, `ctrl+o` during tool execution, or permission
prompt behavior. The earlier captured request-review evidence and existing
SecOps implementation remain the current source for those areas until a clean
AGY capture is available.

## Evidence Files

- `SCENARIO_INDEX.md`: stable index of the refreshed AGY scenario names and
  descriptions from `/tmp/secops_agy_full/manifest.txt`.

