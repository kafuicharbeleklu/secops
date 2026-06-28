# SecOps Manual UX Review

Date: 2026-06-02

## Purpose

This is the R6 manual review script from
`docs/AGY_REMAINING_WORK_PLAN.md`.

Automated PTY smoke tests have passed, including `80x24`, `120x34`, and
`160x40`. This checklist is for a human reviewer in a real terminal to confirm
that the TUI feels clean and AGY-like, not only technically correct.

## Setup

Run from the project root:

```bash
secops
```

Recommended terminal sizes to sample:

- `80x24`
- `120x34`
- any normal daily-use size

## Suggested Review Flow

Run this sequence in a real terminal. Keep the session simple and stop at the
first visual issue that looks wrong enough to require a ticket.

```text
/
/help
/model
/permissions
/config
/agents
/artifact
```

Then trigger a harmless tool path:

```text
what time is it on my system?
```

After the tool result appears:

```text
press ctrl+o
press ctrl+o again
```

For a long-running path, ask for a harmless wait command or any safe local
operation that takes a few seconds, then try `ctrl+o` while it is active.

Use `/exit` when done.

## Checklist

| Surface | Action | Expected result | Status |
| --- | --- | --- | --- |
| Startup | Launch `secops`. | Logo is kept, no login/account ceremony appears, footer is sparse. | Pending |
| Slash palette | Type `/`, use arrows, type a few filters. | Five visible rows, rest reachable by arrows, no invented plugin/update/install rows. | Pending |
| Help | Run `/help`, move between tabs, scroll commands and shortcuts. | Headings and shortcuts are readable, no `ctrl+k` approval hint, no `/keybindings to customize`. | Pending |
| Model picker | Run `/model`, move selection, exit or select a model. | Rows align cleanly, current model is clear, no unsupported model rows. | Pending |
| Permissions panel | Run `/permissions`. | AGY-like active-permissions list, compact controls, no hidden `j/k/q` hints. | Pending |
| Permission prompt | Trigger a harmless command/tool approval. | `Requesting permission for:` copy is clear; options fit or truncate cleanly on narrow terminals. | Pending |
| Tool result | Ask for a harmless local command such as system time. | Tool row uses running/final state, no duplicated command row. | Pending |
| `ctrl+o` | Press `ctrl+o` after a tool result and during a running tool if possible. | Latest transcript expands/collapses in place; `/trajectory` does not open as fallback. | Pending |
| Settings | Run `/config`, search, edit backed rows only. | Search is usable; model/profile/permissions/sandbox can edit; env/source rows remain read-only. | Pending |
| Artifacts | Run `/artifact` or press `ctrl+r` after evidence exists. | Review grammar shows preview/open/dismiss behavior without extra command recommendations. | Pending |
| Agents | Run `/agents`. | Panel opens collapsed on available agents and shows only backed SecOps orchestration state. | Pending |
| Long output | Watch any long generation or tool execution. | Spinner/status clears cleanly; final screen has no stale `Generating...` or duplicate tool block. | Pending |

## Pass Criteria

R6 can be marked done only when the reviewer confirms all rows as Pass or opens
specific follow-up tickets for failed rows.

Use `R6_RESULT_TEMPLATE.md` to record the outcome.
