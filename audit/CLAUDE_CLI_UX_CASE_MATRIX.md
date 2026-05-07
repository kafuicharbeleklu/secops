# Claude CLI UX Case Matrix

Date: 2026-05-07

Reference checked:
- https://code.claude.com/docs/en/interactive-mode
- https://code.claude.com/docs/en/keybindings
- https://code.claude.com/docs/en/permission-modes

Goal: compare SECOPS UX contexts case by case against current Claude Code CLI contexts. This matrix separates exact alignments, compatible mappings, and intentional divergences. It must be updated before adding more navigation changes.

## Context Mapping

| SECOPS UX surface | Claude CLI context | Claude behavior | SECOPS behavior after this pass | Status |
| --- | --- | --- | --- | --- |
| Main prompt | Chat | `Enter` submits; `Ctrl+J` inserts newline; `\` + `Enter` multiline; `Escape` cancels input; `Ctrl+C` interrupts; `Ctrl+D` exits. | `Enter`, `Ctrl+J`, `\` + `Enter`, `Escape`, `Ctrl+C`, and `Ctrl+D` are mapped through prompt_toolkit or explicit bindings. | Aligned enough. |
| Prompt clear/redraw | Chat | `Ctrl+L` clears/redraws prompt input while preserving conversation history. | `Ctrl+L` now clears the typed prompt and keeps the shell session/history. | Aligned enough. |
| Prompt external editor | Chat | `Ctrl+G` and `Ctrl+X Ctrl+E` open external editor. | prompt_toolkit external editor support is enabled; `Ctrl+X Ctrl+E` is available. `Ctrl+G` is not explicitly mapped. | Partial. |
| Prompt model shortcut | Chat / ModelPicker | `Meta+P` opens model picker without clearing current prompt. | `Alt/Meta+P` opens `/model` and preserves a non-empty prompt draft for the next prompt. | Compatible mapping. |
| Prompt thinking shortcut | Chat | `Meta+T` toggles extended thinking. | `Alt/Meta+T` toggles current model thinking between default and `off` when the active model supports thinking. | Compatible mapping. |
| Prompt fast mode | Chat | `Meta+O` toggles fast mode. | No SECOPS fast-mode equivalent. | Intentional divergence. |
| Prompt permission cycle | Chat | `Shift+Tab` / some `Alt+M` configs cycles permission modes. | `Shift+Tab` and `Alt/Meta+M` cycle SECOPS command modes. SECOPS modes differ from Claude modes. | Compatible mapping. |
| Permission modes | Permission modes | Claude cycle defaults: `default -> acceptEdits -> plan`; optional `auto` and `bypassPermissions`. | SECOPS cycle: `ask -> auto-low-risk -> read-only -> session`; `deny` remains explicit via `/permissions deny`. | Domain divergence; labels differ by security model. |
| Command history | History / HistorySearch | `Up`/`Down` history; `Ctrl+R` opens interactive history search; `Ctrl+S` cycles search scope. | `Up`/`Down` use prompt_toolkit history. `Ctrl+R` recalls latest matching entry, but no full interactive search/scope UI. | Partial. |
| Slash commands | Chat / command menu | Typing `/` shows/filter commands. | Slash completions exist via prompt_toolkit; `/menu` provides fuzzy command palette. | Partial but usable. |
| Autocomplete | Autocomplete | `Tab` accept; `Escape` dismiss; `Up`/`Down` navigate. | prompt_toolkit completion behavior covers this. | Aligned by library. |
| `@` mentions | Chat | `@` triggers file path autocomplete. | SECOPS `@target`, `@findings`, `@case`, `@jobs`, `@log:last` inject policy-aware context. | Intentional divergence. |
| Bash/shell mode | Chat / Bash mode | `!` enters bash mode; output goes to conversation; `Escape`, `Backspace`, `Ctrl+U` on empty shell prompt exits shell mode. | `!<command>` executes through SECOPS permission policy and records panel output. There is no persistent bash sub-mode. | Domain divergence. |
| Backgrounding | Task | `Ctrl+B` backgrounds running bash commands/agents. | SECOPS jobs can be tracked/cancelled, but foreground tool execution is not backgrounded by keypress. | Intentional divergence until executor architecture changes. |
| Task list | Task | `Ctrl+T` toggles Claude task list. | `Ctrl+T` opens `/jobs` and preserves a non-empty prompt draft. | Compatible mapping, not exact. |
| Transcript viewer | Transcript | `Ctrl+O` toggles transcript viewer; `Ctrl+E` show all; `q`/`Ctrl+C`/`Esc` exit. | `Ctrl+O` opens `/view last --pager` and preserves a non-empty prompt draft. Native pager handles exit/search. | Partial. |
| Scroll | Scroll | fullscreen scroll context supports `PageUp`, `PageDown`, `Ctrl+Home`, `Ctrl+End`. | SECOPS uses terminal scrollback and native pager for full output. | Intentional divergence unless fullscreen renderer is adopted. |
| Generic select menus | Select | `Down`/`J`/`Ctrl+N`, `Up`/`K`/`Ctrl+P`, `Enter`, `Escape`. | Transient choice menus support these via RadioList + custom `Ctrl+N`/`Ctrl+P`/`Escape`. | Aligned. |
| Model picker | ModelPicker + Select | Select model; `Left`/`Right` adjusts effort level. | `/model` uses one picker for model + thinking; `Left`/`Right` moves to adjacent thinking level on the selected model. | Compatible mapping. |
| Permission confirmation | Confirmation / Permission | `Y`/`Enter` yes, `N`/`Escape` no, `Up`/`Down`, `Tab`, `Shift+Tab`, `Ctrl+E` explanation. | Tool permission dialog now supports `Y` once, `N` deny, `Escape` cancel, `Ctrl+N`/`Ctrl+P`, and `Shift+Tab`/`Alt+M` mode cycle. No `Ctrl+E` explanation panel. | Partial. |
| Install/admin confirmation | Confirmation | Same confirmation model. | Still plain inline `[o/n]` input for sudo/install follow-up. | Needs future cleanup. |
| Theme picker | ThemePicker | `/theme` picker supports `Ctrl+T` for syntax highlighting. | SECOPS `/theme` is command-only (`dark`, `light`, `mono`), no syntax-highlighting picker. | Intentional divergence. |
| Help | Help | `?` shows environment shortcuts; `Escape` dismisses help menu. | `/help` renders a static panel; no `?` prompt binding or dismissible help overlay. | Partial. |
| Side question | Side question `/btw` | Ephemeral answer; dismiss with `Space`, `Enter`, or `Escape`; no tools. | `/side` answers without agent memory mutation, but displays a regular panel and is not available while a turn is running. | Partial. |
| Vim mode | Vim editor mode | Optional via `/config`; vim navigation/editing in prompt. | Not exposed. | Intentional divergence. |
| Footer/statusline | Footer | Footer items can be navigated/opened in fullscreen contexts. | SECOPS footer/statusline is passive context only. | Intentional divergence. |

## Corrections Applied In This Pass

- Preserved typed prompt drafts when opening `/model`, `/jobs`, or `/view last --pager` from prompt shortcuts.
- Added explicit `Ctrl+L` prompt clear behavior.
- Added `Alt/Meta+M` as an alias for permission-mode cycling.
- Added `Alt/Meta+T` to toggle active model thinking on/off when supported.
- Added `Y`/`N` confirmation shortcuts to the tool permission dialog.
- Kept `/model` as a single model+thinking picker with `Left`/`Right` effort adjustment.

## Do Not Claim Exact Claude Parity For These

- Permission modes: SECOPS command authorization is not Claude file-edit permission mode.
- Transcript: SECOPS does not have Claude fullscreen transcript viewer.
- Task list: SECOPS jobs are not Claude task lists.
- Fast mode: no current SECOPS equivalent.
- Backgrounding: SECOPS command execution cannot be moved to background by `Ctrl+B` yet.
- `@` mentions: SECOPS references are semantic/security context, not raw file paths.

