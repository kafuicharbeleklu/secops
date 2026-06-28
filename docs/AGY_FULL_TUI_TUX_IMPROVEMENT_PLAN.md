# AGY Full TUI/TUX Improvement Plan

Date: 2026-05-31

## Progress

- Step 1 started: `scratch/agy_capture.py` now supports targeted scenarios via
  `--scenario` and can write `summary_redacted.md` with account-like identifiers
  redacted.
- Step 1 verification capture: `/tmp/secops_agy_target_idle/summary_redacted.md`.
- Step 2 started: SecOps startup metadata no longer renders an account-like
  `user@host` line; it now preserves logo, product/version, session role, model,
  workspace path, prompt separators, and footer.
- Step 2 verification capture: `/tmp/secops_v2_idle_after_step2_frame.txt`.
- Step 3 started: slash completion now uses five visible rows, compact command
  labels, AGY-like overflow/footer grammar, and registry-backed `/tool <name>`
  entries for real SecOps tools.
- Step 3 verification capture: `/tmp/secops_v2_after_step3_tui.txt`.
- Step 3 correction: dynamic slash providers for skills, hooks, MCP actions,
  agent profiles, and workflows are out of scope unless AGY captures and real
  SecOps command behavior justify them. Existing panels can expose their data,
  but the slash palette must not invent extra action commands.
- Step 3 slash-action cleanup: argument completion no longer advertises
  uncaptured action variants such as `/skills reload`, `/hooks reload`, `/mcp
  start`, `/task <id>`, or `/cancel <id>`. The underlying typed commands remain
  supported where the SecOps command handler already implements them.
- Step 3 extension-description cleanup: slash/help descriptions for `/skills`,
  `/hooks`, and `/mcp` now describe the visible panel only, without advertising
  `reload`, `start`, `stop`, or `manage` action variants in the default TUI.
- Step 3 visible-doc cleanup: the README command list now presents `/skills`,
  `/hooks`, and `/mcp` as panel entrypoints only, and no longer recommends
  reload/action variants as the default extension-editing workflow.
- Step 3 usage-metadata cleanup: `/skills`, `/hooks`, and `/mcp` command
  metadata and invalid-argument usage errors now keep the same panel-only label
  as the slash palette, while the existing advanced typed handlers remain in
  place.
- Surface-copy cleanup: secondary command recommendations such as
  `Use /tasks...`, `/artifact list`, `/task <id>`, and `/tool <name>` were
  removed from status/footer copy so panels stay descriptive instead of
  advertising extra command paths.
- Panel-shortcut cleanup: the reusable task/detail panel no longer advertises
  or accepts hidden `j/k`, `l/o logs`, or `q` aliases; its visible control
  grammar now stays with arrow navigation, `enter`, and `esc`.
- Log-pager shortcut cleanup: the full log pager no longer advertises or accepts
  hidden `j/k`, `g/G`, or `q` aliases; it keeps arrow/page/home/end navigation
  plus `esc` close.
- Inline-panel alias cleanup: generic choice overlays, help tabs, context,
  hooks, MCP, skills, tools, and agents no longer keep hidden `j`, `q`, `h/l`,
  navigation aliases. Visible tab cycling remains only on tabbed headers that
  explicitly say `(←/→ or tab to cycle)`. Advertised domain actions such as
  artifact preview `p` and agents `k Kill Active Subagent` remain.
- Smoke-harness cleanup: the `/config` search smoke now uses `gem` instead of
  `gemi`, so the check remains valid after `/model` changes from Gemini to a
  Gemma profile in the same smoke run.
- Re-baseline pass: a fresh full SecOps TTY capture at `34x120` passes all smoke
  scenarios after stabilizing the artifact-preview harness timing. The capture is
  `/tmp/secops_v2_rebaseline_34x120.txt` with raw ANSI at
  `/tmp/secops_v2_rebaseline_34x120.bin`.
- Step 4 completed: `/help`, `?`, and `/keybindings` now use AGY-like flat list
  grammar for commands and shortcuts, active `>` rows, `[1-21 of N items]`
  counters, and a general tab without account/login concepts.
- Step 4 shortcut regression cleanup: removed the SecOps-only `ctrl+k`
  permission approval shortcut from the permission prompt and help surface. AGY
  captures label `ctrl+k` as `Approve subagent fast`, so SecOps should not reuse
  it for permission approval without a backed equivalent subagent approval flow.
- Step 4 shortcut wording cleanup: aligned supported shortcut descriptions for
  `ctrl+o` (`Toggle trajectory view`) and `ctrl+y` (`Yank (paste from kill
  ring)`) with captured AGY wording. `ctrl+v` keeps SecOps-specific evidence
  wording because it is backed by `/attach` and clipboard-image/file intake.
- Step 4 version cleanup: the startup banner, `/help` general tab, `doctor`,
  package metadata, and MCP client info now share the same SecOps CLI version
  (`1.0.3`) instead of mixing the banner version with stale `0.1.0` metadata.
- Step 4 verification capture: `/tmp/secops_v2_after_step4_tui.txt`.
- Step 5 completed: `/model` now renders an AGY-like model-only picker with no
  interactive `Auto` row, a stable `(current)` suffix column, unchanged keyboard
  footer grammar, and `/model auto` preserved as a typed command.
- Step 5 verification capture: `/tmp/secops_v2_after_step5_tui.txt`.
- Pre-Step 6 bugfix: transient overlays now reserve terminal rows for prompt
  chrome and the `esc to cancel` statusline before rendering list content. This
  prevents `/tools` and similar panels from overflowing into scrollback during
  arrow-key redraws.
- Pollution/scroll verification capture: `/tmp/secops_v2_fix_pollution_tui.txt`.
- Long-list pagination fix: `/help` now has real selected-row navigation for
  commands and shortcuts, and long lists across help, tools, and generic choice
  overlays are capped to 10 visible entries with counters and arrow-key paging.
- Help pagination verification capture: `/tmp/secops_v2_help_pagination_tui.txt`.
- Step 6 completed: generation feedback now keeps `Generating...` as the primary
  spinner line, moves delayed wait tips to a secondary `└ Tip: ...` line, shows
  `esc to cancel`, and renders the interruption follow-up
  `Interrupted · What should SecOps CLI do instead?`.
- Step 6 verification capture: `/tmp/secops_v2_step6_generation_tui.txt`.
- Step 7 started: `ctrl+o` now prefers the latest local tool transcript using
  `● Tool(args)` and `⎿ output (ctrl+o to collapse)` grammar. `/trajectory`
  remains the explicit full-session review command.
- Step 7 verification capture: `/tmp/secops_v2_step7_ctrl_o_tui.txt`.
- Step 7 running-state pass: active tool execution now renders
  `○ Tool(args) (ctrl+o to expand)` and the generic AGY-like `Running...`
  spinner before the result collapse/expansion path.
- Step 7 running verification capture: `/tmp/secops_v2_step7_running_tui.txt`.
- Step 7 toggle pass: repeated `ctrl+o` now tracks the latest transcript/artifact
  state, expanding to `ctrl+o to collapse` and collapsing back to
  `ctrl+o to expand` without opening `/trajectory`.
- Step 7 toggle verification capture: `/tmp/secops_v2_step7_ctrl_o_toggle_tui.txt`.
- Step 7 pollution fix: repeated `ctrl+o` clears the previous inline block before
  rendering the next state, and the `○ Tool(args)` running row is cleared before
  the final tool result. Raw TTY evidence includes terminal clear sequences.
- Step 7 pollution verification capture: `/tmp/secops_v2_ctrl_o_pollution_fix_tui.txt`
  and `/tmp/secops_v2_ctrl_o_pollution_fix_tui.bin`.
- Step 7 status-color pass: AGY raw captures show state changes around tool
  execution (`○` active, `●` final/expanded) but no explicit SGR color in the
  captured environment. SecOps now treats tool marker color as execution state:
  warning for pending/running, success for completed tools, and error for failed,
  cancelled, or interrupted tools. `ctrl+o` collapse now removes the inline block
  instead of printing a duplicate collapsed row.
- Step 7 status/color verification capture: `/tmp/secops_v2_tool_status_ctrl_o_fix_tui.txt`
  and `/tmp/secops_v2_tool_status_ctrl_o_fix_tui.bin`.
- Step 7 duplicate-command fix: `ctrl+o` on a completed tool result no longer
  prints a second `● Tool(args)` command row. It appends only the expandable
  output detail (`⎿ ...`) and clears that detail on the next `ctrl+o`.
- Step 7 duplicate-command verification capture:
  `/tmp/secops_v2_ctrl_o_no_duplicate_tool_tui.txt` and
  `/tmp/secops_v2_ctrl_o_no_duplicate_tool_tui.bin`.
- Step 7 no-transcript-append fix: in a real TTY after a completed response,
  `ctrl+o` no longer appends a separate artifact block under the answer and no
  longer opens `/trajectory` as a fallback when no local transcript cache exists.
- Step 7 no-transcript-append verification capture:
  `/tmp/secops_v2_ctrl_o_no_transcript_append_tui.txt` and
  `/tmp/secops_v2_ctrl_o_no_transcript_append_tui.bin`.
- Step 7 local-redraw fix: `ctrl+o` in a real TTY now uses the cached
  collapsed/expanded rendering from the latest tool block onward, clears the
  currently rendered local transcript lines, and redraws the opposite state in
  place.
- Step 7 local-redraw verification capture:
  `/tmp/secops_v2_ctrl_o_redraw_tui.txt` and
  `/tmp/secops_v2_ctrl_o_redraw_tui.bin`.
- Step 7 thought/format cleanup: the `ctrl+o` redraw cache now starts at the
  latest tool block instead of the beginning of the assistant turn, preserving
  the pre-tool `Thought` block and matching the existing tool/result markup more
  closely during expand/collapse.
- Step 7 thought/format verification capture:
  `/tmp/secops_v2_ctrl_o_thought_cleanup_tui.txt` and
  `/tmp/secops_v2_ctrl_o_thought_cleanup_tui.bin`.
- Step 8 permissions fallback pass: non-interactive `/permissions` now uses the
  same `Active Permissions` list grammar as the captured AGY surface instead of
  the older policy-summary overlay.
- Step 8 AGY prompt-mode capture: `scratch/agy_permission_prompt_capture.py`
  temporarily set AGY `toolPermission` to `request-review`, waited for the idle
  TUI, captured a `pwd` approval prompt, and restored the original local setting
  (`always-proceed` in that capture). Evidence paths:
  `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review.txt`,
  `.bin`, and `_frame.txt`.
- Step 8 capture-harness cleanup: `scratch/agy_permission_prompt_capture.py`
  now accepts `--mode request-review|proceed-in-sandbox|always-proceed|strict`,
  writes mode-specific capture filenames, and restores the original AGY
  settings payload byte-for-byte after capture.
- Step 8 strict-mode capture attempts:
  `/tmp/secops_agy_permission_prompt_strict` and
  `/tmp/secops_agy_permission_prompt_strict_fresh` reached upstream quota before
  tool planning, so they are retained only as evidence of the capture limit. No
  strict-mode permission behavior is inferred from them.
- Step 8 direct-shell capture note: fresh `strict` captures with `!pwd` and
  `!touch /tmp/secops_agy_write_probe_strict` avoided LLM quota and showed AGY
  1.0.4's direct bash mode rendering `○ ! ...` followed by `● ! ...`, without
  a permission prompt. Evidence paths:
  `/tmp/secops_agy_permission_prompt_strict_bang_pwd/` and
  `/tmp/secops_agy_permission_prompt_strict_bang_touch/`. SecOps does not add a
  `!` shell shortcut here because that would be a new command surface outside
  the current user-approved parity scope.
- Step 8 approval-prompt pass: command approvals now use the captured AGY copy
  shape (`Requesting permission for: pwd`), visible-only keyboard aliases, and
  `esc` interruption copy instead of treating `esc` as an explicit denial.
- Step 8 AGY prefix correction: command approval prompts now use AGY's captured
  `commands that start with '<command>'` copy and `command_prefix(...)` scope,
  instead of the earlier SecOps-only exact-command wording. The permission
  engine keeps a safety guard so a saved prefix does not cover later commands
  that append shell control chains such as `&&`, `;`, or pipes.
- Step 8 approval-prompt verification capture:
  `/tmp/secops_v2_p8_permission_prompt_tui.txt` and
  `/tmp/secops_v2_p8_permission_prompt_tui.bin`.
- Step 8 previous exact-command verification capture:
  `/tmp/secops_v2_exact_command_permission_tui.txt` and
  `/tmp/secops_v2_exact_command_permission_tui.bin`.
- Step 8 AGY prefix smoke-guard pass: `scratch/tui_smoke.py` now asserts
  compact adjacent approval options, AGY `commands that start with ...`
  wording, and absence of the earlier SecOps-only `this exact command` label in
  shell command approval prompts.
- Step 8 exact-command residue cleanup: the approval UI no longer exposes the
  old `this exact command` option text even if a backward-compatible
  `command_exact(...)` resource reaches the prompt path; current command prompts
  are coerced to AGY-style `command_prefix(...)` wording.
- Step 8 hidden-alias cleanup: the approval picker no longer treats left/right
  arrows as hidden up/down aliases. Its accepted controls now match the captured
  permission footer: up/down navigation, `tab` amend, `e` edit command, `enter`,
  and `esc` interruption.
- Step 8 tool-spacing cleanup: agent-stream tool rows now render compactly after
  `▸ Thought for ...` instead of adding an extra blank line before `●`/`○`.
- Step 8 tool-spacing verification capture:
  `/tmp/secops_v2_tool_spacing_tui.txt` and
  `/tmp/secops_v2_tool_spacing_tui.bin`.
- Diff fallback pass: `/diff` in a non-Git directory now matches the captured
  AGY tab header and Git warning shape (`Diff (git)  All Changes  Per Turn
  Commit Tree`) instead of the older generic `No Git workspace` overlay.
- Step 9 settings-panel pass: `/config` and `/settings` now render an AGY-like
  `Settings` surface backed by real SecOps runtime settings: profile, model,
  tool permission mode, sandbox mode, tool timeout, output token limit,
  rendering mode, workspace access, log file, and config source. The panel is
  navigable and exits with `esc`.
- Step 9 settings-search pass: the `Search:` field in `/config` is now backed
  by real local filtering over setting name, value, and description. Typing
  filters rows, backspace edits the query, and `esc` clears search before
  closing.
- Step 9 settings-search input cleanup: settings search no longer treats `j`,
  `k`, or `q` as hidden navigation aliases, so those letters can be typed into
  the search field. Navigation follows the visible footer grammar.
- Step 9 settings-edit pass: `/config` now advertises the captured
  `enter Edit` footer and edits only backed runtime rows: response profile,
  model, tool permission mode, and sandbox mode. Environment-backed rows such as
  tool timeout, max output tokens, log file, and config source remain read-only
  in the session.
- Step 9 settings-panel verification capture:
  `/tmp/secops_v2_settings_panel_tui.txt` and
  `/tmp/secops_v2_settings_panel_tui.bin`.
- Step 9 settings-edit verification capture:
  `/tmp/secops_v2_p9_settings_edit_tui.txt` and
  `/tmp/secops_v2_p9_settings_edit_tui.bin`.
- Step 9 context-budget pass: `/context` now renders an AGY-like context usage
  surface with a square usage grid, model budget line, estimated role split
  for user/agent/tool messages, free-space line, and related SecOps actions.
  The surface is transient in a real TTY and exits with `esc`.
- Step 9 hooks hidden-alias cleanup: `/hooks` no longer accepts unadvertised
  `home/end` navigation. Its interactive controls now match the captured AGY
  hooks footer: `↑/↓ Navigate`, `enter Select`, plus `esc` from the statusline.
- Captured action-panel hidden-page cleanup: `/artifact`, `/settings`,
  `/agents`, `/skills`, `/hooks`, and `/mcp` no longer accept unadvertised
  `pgup/pgdn/home/end` accelerators. Arrow navigation and advertised actions
  remain; deep pagination keys stay limited to help/tools-style long lists.
- Step 9 context-budget verification capture:
  `/tmp/secops_v2_context_budget_tui.txt` and
  `/tmp/secops_v2_context_budget_tui.bin`.
- Step 9 context-text cleanup: `/context` now keeps AGY's shorter related line
  shape and removes approximate `~` markers from the role token rows while
  preserving SecOps' real `/skills` command name.
- Step 9 context-hidden-alias cleanup: transient `/context` now closes only on
  `esc`, matching its visible `esc to cancel` statusline. The previous hidden
  `enter` close path was removed because no context footer advertises it.
- Step 9 action-panel hidden-close cleanup: `/artifact`, `/skills`, `/hooks`,
  and `/mcp` no longer use `enter` as a hidden close shortcut. `enter` is kept
  only for advertised actions when backing content exists; `esc` remains the
  close path.
- Dormant inline-surface footer cleanup: the generic `_view_inline_lines`
  helper no longer advertises `↑/↓ Navigate` because it only supports `esc`
  close. Active scrollable surfaces keep their own backed navigation footers.
- Step 9 hooks-panel pass: `/hooks` now renders an inline AGY-like hook type
  selector backed by SecOps hook events (`PreToolUse`, `PostToolUse`, `OnError`),
  shows configured/enabled counts when hooks exist, supports arrow navigation,
  and exits with `esc`.
- Step 9 hooks-text cleanup: `/hooks` no longer advertises a `Related:
  /hooks reload` line inside the inline panel because the captured AGY surface
  only shows hook rows plus navigation help. The typed `/hooks reload` command
  remains supported.
- Step 9 hooks-panel verification capture:
  `/tmp/secops_v2_hooks_panel_tui.txt` and
  `/tmp/secops_v2_hooks_panel_tui.bin`.
- Step 9 MCP-panel pass: `/mcp` now renders an inline AGY-like `MCP Servers`
  surface backed by SecOps MCP config/runtime state, keeps real config source
  paths visible, shows configured/enabled/running/tool counts when present,
  paginates long server/tool lists, supports arrow navigation, and exits with
  `esc`.
- Step 9 MCP-empty cleanup: the empty `/mcp` panel now follows the captured AGY
  shape more closely by showing one selected workspace config source plus
  `No MCP servers configured.` instead of listing every candidate config path.
  Configured servers, errors, runtime state, and remote tools still render as
  real SecOps-backed rows when present.
- Step 9 MCP-panel verification capture:
  `/tmp/secops_v2_mcp_panel_tui.txt` and
  `/tmp/secops_v2_mcp_panel_tui.bin`.
- Step 9 skills-panel pass: `/skills` now renders an inline AGY-like `Skills`
  surface backed by active SecOps Markdown skills, shows a sparse workspace
  source in the empty state, paginates long skill lists, supports arrow
  navigation, and exits with `esc`.
- Step 9 skills-empty cleanup: the empty `/skills` panel now follows the same
  sparse empty-state rule as `/mcp`: one selected workspace source plus the
  empty message. It no longer exposes `Antigravity skills` or every candidate
  global directory when no SecOps skill is loaded.
- Step 9 skills-panel verification capture:
  `/tmp/secops_v2_skills_panel_tui.txt` and
  `/tmp/secops_v2_skills_panel_tui.bin`.
- Step 10 artifact-review pass: `/artifact` now renders an inline AGY-like
  `Artifacts` surface with `p preview`, `enter open`, and `esc dismiss`
  keyboard grammar. Empty state wording now matches AGY (`No artifacts`), and
  preview/open modes stay inside the terminal transcript without switching to
  an alternate screen.
- Step 10 artifact-review verification capture:
  `/tmp/secops_v2_artifact_review_tui.txt` and
  `/tmp/secops_v2_artifact_review_tui.bin`.
- Step 10 ctrl-r artifact shortcut pass: `ctrl+r` now opens the same inline
  `Artifacts` review surface as `/artifact`, including the AGY empty state and
  `p preview` / `enter open` / `esc dismiss` footer. It no longer emits the old
  one-line missing-artifact warning when the session has no artifacts.
- Step 10 ctrl-r verification capture:
  `/tmp/secops_v2_ctrl_r_artifacts_tui.txt` and
  `/tmp/secops_v2_ctrl_r_artifacts_tui.bin`.
- Step 10 attachments-review pass: `/attachments` and `/attach` without an
  argument now use the same inline evidence review grammar as `/artifact`
  (`p preview`, `enter open`, `esc dismiss`). `/attachments list` remains a
  non-interactive listing path for scripts and smoke checks.
- Step 10 attachments-review verification capture:
  `/tmp/secops_v2_attachments_review_tui.txt` and
  `/tmp/secops_v2_attachments_review_tui.bin`.
- Step 11 pre-TUI entrypoint pass: root CLI help now exposes backed AGY-like
  flags for non-interactive print mode, prompt-interactive startup, sandbox,
  permission mode, workspace directories, and log-file override. A real
  `doctor` command reports local diagnostics without starting the TUI.
- Step 11 CLI verification captures:
  `/tmp/secops_v2_cli_help.txt`, `/tmp/secops_v2_cli_doctor.txt`, and
  `/tmp/secops_v2_print_helper.txt`.
- P11 agents/tasks follow-up pass: `/agents` now follows the AGY
  `Create New Agents` / `Available Agents` surface shape while staying backed
  by SecOps concepts: workspace/user JSON profile paths, the foreground primary
  agent, running `/btw` side-question tasks, and `k` cancellation for active
  background tasks.
- P11 agents-text cleanup: the create-agent path block now matches the captured
  AGY shape more closely by keeping `Workspace:` on the first template path and
  rendering the user template path as a plain second line, without adding a
  separate `User:` label.
- P11 agents-instruction cleanup: `/agents` no longer adds a `Use /btw <query>`
  instruction line inside the panel; `/btw` remains available as a real slash
  command, but the AGY-captured agents surface only shows creation paths,
  available-agent rows, and keyboard grammar.
- P11 agents-collapse cleanup: `/agents` now opens with `> ▸ Available Agents`
  collapsed, matching the captured AGY default. Pressing `enter` still toggles
  the existing SecOps-backed rows for the primary session, background tasks, and
  configured profiles.
- P11 agents verification capture:
  `/tmp/secops_v2_agents_panel_tui.txt` and
  `/tmp/secops_v2_agents_panel_tui.bin`.
- Trajectory empty-state cleanup: `/trajectory` keeps the full pager for real
  session history, but an empty session now renders a compact inline summary
  instead of opening a blank pager with scroll controls.
- Attachment success cleanup: `/attach <path>` now emits only the success row;
  the evidence preview remains available through `/attachments` and the artifact
  review surface instead of printing a redundant `Attachment` result line.
- Attachment list-detail cleanup: attachment rows no longer repeat the generic
  preview token `Attachment` in list metadata; preview/open modes still expose
  the stored evidence details.
- Attachment preview/open cleanup: `/attachments` preview and open modes no
  longer repeat the generic one-word `Attachment` placeholder; the full `open`
  view still shows useful evidence metadata and body.
- Statusline copy cleanup: `/statusline` now shows only the inspectable runtime
  fields and no longer adds an explanatory footer sentence.
- Hooks empty-message cleanup: `/hooks` now matches `agy_hooks_command_frame.txt`
  by listing hook types and keyboard grammar without adding a `No hooks
  configured` line when no hooks are configured.
- Tool-status correction: the central tool card indicator now follows the
  effective visible result status. Text-signaled failures such as `❌ Command
  timed out...` render the `● Tool(...)` row as an error even when the backend
  result object is marked `success=True`, and stored tool-result artifacts use
  the same error status for `ctrl+o` fallback paths.
- Running-spinner correction: tool execution without a structured phase now
  cycles `Running`, `Running.`, `Running..`, and `Running...`, matching the
  AGY long-tool captures instead of keeping a fixed `Running...` label.
- Running `ctrl+o` cleanup: expanding a still-running tool no longer adds a
  redundant `⎿ Running...` result row. The tool card switches to
  `(ctrl+o to collapse)` while the spinner remains responsible for the running
  state, matching AGY long-tool captures. The full PTY smoke now covers this
  `ctrl+o`-during-running path explicitly.
- Running-result continuity cleanup: when a tool finishes after being expanded
  with `ctrl+o`, the final result stays expanded with `(ctrl+o to collapse)`
  instead of reverting to the collapsed `N lines` summary.
- Pending-tool row cleanup: `ToolCallEvent` no longer renders a transient
  pending `● Tool(...) (ctrl+o to expand)` row before execution starts. The
  first visible running state is now `○ Tool(...)`, matching the AGY `pwd` and
  long-running tool captures; `● Tool(...)` remains the completed/result state.
- Final-screen smoke guard: the PTY smoke now validates the terminal screen
  after ANSI erasure for the critical long-running paths. `ctrl+o` during a
  running tool must leave only the completed expanded result on screen, normal
  streaming must clear `Generating...`, and interrupted streaming must clear
  generation frames while keeping the interruption follow-up.
- Marker-color evidence pass: AGY raw captures for long-running tools show the
  tool name rendered in bold but do not contain a captured color SGR around the
  `●`/`○` marker or `Running...` spinner text. SecOps therefore keeps the
  state-derived marker color mapping to preserve execution-state clarity without
  claiming an unproven exact AGY color.
- Regression baseline refresh on 2026-06-02: compilation, the full `197` test
  suite, and the full `34x120` PTY smoke all passed. The current smoke captures
  were regenerated at `/tmp/secops_tui_smoke.txt` and
  `/tmp/secops_tui_smoke.bin`.
- Public-doc command inventory cleanup: `README.md` now lists every existing
  slash command from `secops_agent.ui.commands.COMMANDS` without adding new
  runtime commands or shortcuts. The README/code command inventory check reports
  no README-only or code-only command rows.
- Public-doc CLI/model inventory cleanup: `README.md` now documents all
  application CLI options declared in `secops_agent/main.py` and all accepted
  model aliases from `secops_agent.core.model_catalog.MODEL_ALIASES`, excluding
  framework-generated completion/help options.
- Public-doc tools/safety inventory check: the README dangerous-action list is
  aligned with the current `dangerous=True` registry set:
  `dir_brute`, `generate_payload`, `nikto_scan`, `nmap_scan`, `run_shell`,
  `sql_injection_test`, and `xss_test`. No runtime command or shortcut was
  added for this documentation check.
- Residue-audit refresh: the current PTY smoke text was checked for old
  SecOps-only residues such as `this exact command`, `ctrl+k` approval copy,
  hidden `j/k` or `q quit` aliases, secondary command recommendations, and
  uncaptured extension action hints. No targeted residue was found, and the
  full `197` test suite plus `34x120` PTY smoke passed again.
- Static CLI capture refresh: `/tmp/secops_v2_cli_help.txt` and
  `/tmp/secops_v2_cli_doctor.txt` were regenerated. The main CLI help exposes
  the backed `doctor` subcommand and relevant prompt/sandbox/permission flags;
  it does not expose AGY-only plugin, update, install, or changelog subcommands.
  The only `install` text is Typer's built-in shell-completion option.
- Keybinding-customization exclusion check: SecOps still presents
  `/keybindings` as a shortcuts view only. Runtime help, README text, and the
  current PTY smoke do not advertise AGY's `/keybindings to customize` promise;
  `tests/test_tui_polish.py` already guards this with `assertNotIn("to customize",
  rendered)`.
- Direct-shell shortcut exclusion check: AGY `!pwd` / `!touch` captures remain
  documented as supplemental shell-mode evidence only. SecOps source, README,
  and current help surfaces do not expose a `!` shell shortcut; shell execution
  stays routed through the backed `run_shell` tool and permission flow.
- Version-consistency refresh: public surfaces and source references were
  checked for the old `0.1.0` residue. `pyproject.toml`, `secops_agent.__version__`,
  `doctor`, `/help`, startup metadata, and MCP client metadata remain aligned on
  `1.0.3`.
- AGY-only slash-command exclusion guard: `/changelog`, `/credits`, `/install`,
  `/memory`, `/plugin`, `/plugins`, and `/update` remain absent from SecOps
  slash commands, completions, README command lists, and the current PTY smoke.
  `tests/test_tui_polish.py` now guards the full excluded set.
- Surface-copy recommendation recheck: runtime panels and the current PTY smoke
  do not reintroduce old secondary slash-command hints such as `Use /...`,
  `/artifact list`, `/task <id>`, `/cancel <id>`, or `/tool <name>` in panel
  footers/status copy. The remaining `/tasks` and `/attachments list` strings
  in the smoke are typed scenario inputs, not recommendations.
- Command-prefix safety guard expansion: the AGY-style
  `commands that start with ...` approval wording remains paired with a SecOps
  guard against appended shell-control extensions. Tests now cover `&&`, `||`,
  `;`, pipes, redirections, command substitutions, backticks, and newline
  extensions while still allowing benign argument extension such as `-sV`.
- Slash-handler completeness guard: every command in
  `secops_agent.ui.commands.COMMANDS` remains backed by a `main.py` handler, and
  no visible command is marked `implemented=False`. The legacy
  `render_planned_command()` fallback is therefore not reachable from the
  current slash registry.
- README dangerous-tool inventory guard: the documented `Tools And Safety`
  dangerous-action list is now tested against the actual decorator-backed tool
  registry after importing all SecOps tool modules, so new `dangerous=True`
  tools must be reflected in public safety documentation.
- README slash-command inventory guard: the README `Slash Commands` section is
  now tested against `secops_agent.ui.commands.COMMANDS` by canonical command
  name, so public documentation cannot drift by omitting a supported slash
  command or listing an unsupported one.
- README model-alias inventory guard: the README `Accepted model aliases`
  section is now tested against `secops_agent.core.model_catalog.MODEL_ALIASES`,
  excluding documented target model IDs from the alias set, so new or removed
  aliases must stay reflected in public documentation.
- Current verification capture: `/tmp/secops_tui_smoke.txt` and
  `/tmp/secops_tui_smoke.bin`.

## Execution Status

Legend:

- Done: implemented for the captured AGY behavior and current SecOps scope.
- Partial: visible parity is implemented, but a bounded piece is intentionally
  deferred.
- Deferred: blocked by missing AGY evidence or intentionally outside the
  pentest-agent scope.

| ID | Status | Current state | Remaining work |
| --- | --- | --- | --- |
| P1 | Done | Startup and idle prompt rhythm keep the SecOps logo, remove account/login metadata, and preserve model/workspace context. | None unless a fresh AGY capture changes the target frame. |
| P2 | Done | Slash palette uses five visible rows, compact command labels, backed `/tool <name>` entries, and no invented extension/task action rows. | None. Keep rejecting uncaptured action variants. |
| P3 | Done | `/help`, `?`, and `/keybindings` use tabbed flat-list grammar, selected rows, item counters, and restrained shortcut coloring. | Do not advertise keybinding customization unless it becomes real. |
| P4 | Done | `/model` is an AGY-like picker over SecOps-supported model profiles, with stable current-selection alignment. | None. |
| P5 | Done | Long generation shows `Generating...`, delayed tips, `esc to cancel`, and the AGY-like interruption follow-up. | None. |
| P6 | Done | Tool execution now has running/final state rows, collapsed/expanded output summaries, and execution-state marker colors. | Captured AGY raw files do not prove colored tool markers; SecOps keeps state-derived colors for execution clarity. |
| P7 | Done | `ctrl+o` toggles the latest local thought/tool transcript in place instead of opening `/trajectory`, with duplicate/pollution fixes. | None. |
| P8 | Done | `/permissions` panel fallback matches the captured active-permissions list shape; command approval prompts use captured picker copy, compact option spacing, `esc` interruption, and AGY-style `command_prefix(...)` wording with a SecOps guard against appended shell-control chains. | Strict/write-specific approval prompts remain uncaptured; AGY direct `!` shell-mode read/write is captured but intentionally out of SecOps scope unless explicitly requested. |
| P9 | Done | `/config` and `/settings` render a searchable settings panel with captured `enter Edit` grammar; backed runtime rows edit response profile, model, tool permission mode, and sandbox mode. | Env/config-source rows stay read-only until real runtime editors exist. |
| P10 | Done | `/context` renders the AGY-like token/context budget visualization with SecOps-related actions. | None. |
| P11 | Done | `/agents` opens collapsed on `Available Agents`, shows AGY-like creation paths, foreground agent, tasks, profiles, and visible `k` cancellation. | Keep task-specific details SecOps-backed. |
| P12 | Done | `/artifact`, `ctrl+r`, and attachment review use the AGY review grammar: `p preview`, `enter open`, `esc dismiss`. | None. |
| P13 | Done | `/hooks`, `/mcp`, `/skills`, and `/tools` are navigable, paginated, backed by real SecOps state, and cleaned of uncaptured action hints. | Plugin/update/install mutation flows stay out of scope unless backed and relevant. |
| P14 | Done | CLI pre-TUI entrypoints now cover relevant AGY-like flags, non-interactive print flow, sandbox/permission options, and `doctor`. | Fake update/plugin/changelog commands remain out of scope. |

Current verification snapshot:

- Syntax/import check: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall secops_agent`
- Unit suite: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'` (`197` tests)
- Fresh full TTY smoke: `/tmp/secops_tui_smoke.txt`
- Fresh full TTY smoke raw ANSI: `/tmp/secops_tui_smoke.bin`
- Previous shortcut-wording full TTY smoke: `/tmp/secops_v2_shortcut_wording_full_tui.txt`
- Previous shortcut-wording full TTY smoke raw ANSI: `/tmp/secops_v2_shortcut_wording_full_tui.bin`
- Previous shortcut-regression full TTY smoke: `/tmp/secops_v2_shortcut_regression_tui.txt`
- Previous shortcut-regression full TTY smoke raw ANSI: `/tmp/secops_v2_shortcut_regression_tui.bin`
- Previous AGY-prefix full TTY smoke: `/tmp/secops_v2_agy_prefix_permission_tui.txt`
- Previous AGY-prefix full TTY smoke raw ANSI: `/tmp/secops_v2_agy_prefix_permission_tui.bin`
- Previous exact-command guard full TTY smoke: `/tmp/secops_v2_exact_command_permission_guard_tui.txt`
- Previous exact-command guard full TTY smoke raw ANSI: `/tmp/secops_v2_exact_command_permission_guard_tui.bin`
- Previous exact-command full TTY smoke: `/tmp/secops_v2_exact_command_permission_tui.txt`
- Previous exact-command full TTY smoke raw ANSI: `/tmp/secops_v2_exact_command_permission_tui.bin`
- Previous tool-spacing full TTY smoke: `/tmp/secops_v2_tool_spacing_tui.txt`
- Previous tool-spacing full TTY smoke raw ANSI: `/tmp/secops_v2_tool_spacing_tui.bin`
- Superseded command-prefix full TTY smoke: `/tmp/secops_v2_command_prefix_permission_tui.txt`
- Superseded command-prefix full TTY smoke raw ANSI: `/tmp/secops_v2_command_prefix_permission_tui.bin`
- Previous P9 full TTY smoke: `/tmp/secops_v2_p9_settings_edit_tui.txt`
- Previous P9 full TTY smoke raw ANSI: `/tmp/secops_v2_p9_settings_edit_tui.bin`
- Previous P8 full TTY smoke: `/tmp/secops_v2_p8_permission_prompt_tui.txt`
- Previous P8 full TTY smoke raw ANSI: `/tmp/secops_v2_p8_permission_prompt_tui.bin`
- Previous full TTY re-baseline: `/tmp/secops_v2_rebaseline_34x120.txt`
- Previous full TTY re-baseline raw ANSI: `/tmp/secops_v2_rebaseline_34x120.bin`

Next work queue:

1. No new command or shortcut work is queued. Continue only with evidence
   refreshes, regression passes, and cleanup of captured-surface discrepancies.

## Objective

Use observed Antigravity CLI (`agy`) behavior as the source of truth for
improving the SecOps_v2 terminal user interface and terminal user experience.

The goal is terminal interaction parity, not feature cloning. SecOps must keep
its pentest-agent functional scope.

## Fixed Constraints

- Keep the current SecOps logo.
- Do not add account/login ceremony.
- Do not copy AGY coding or browser-development features unless there is a
  SecOps/pentest equivalent.
- Do not implement a TUI behavior unless it is backed by an AGY capture, AGY
  static help output, or an official public AGY source.
- Keep raw AGY captures out of committed docs because they can contain account
  identity.

## Capture Inventory

Note: `/tmp` captures are ephemeral by design. The current authoritative SecOps
smoke is `/tmp/secops_tui_smoke.*`; older `/tmp/secops_v2_*` and AGY capture
entries below are historical verification references and may no longer exist
after temp cleanup. Regenerate the named capture before making exact visual
spacing decisions from a missing `/tmp` artifact.

R3 refresh note: `/tmp/secops_agy_full` was regenerated on 2026-06-02 against
AGY `1.0.4`. The original central parity work remains based on the earlier AGY
`1.0.3` full capture, but the live `/tmp/secops_agy_full` path now points to
the `1.0.4` refresh. See `docs/evidence/agy_refresh_2026-06-02/`.

AGY full capture:

- Root: `/tmp/secops_agy_full`
- Historical central-parity AGY version: `1.0.3`
- Current regenerated `/tmp/secops_agy_full` AGY version: `1.0.4`
- Manifest: `/tmp/secops_agy_full/manifest.txt`
- Size: about `1.3M`
- Files: `216`
- Interactive frame captures: `69`
- Static CLI help files: `/tmp/secops_agy_full/static_cli/*.txt`
- Capture harness: `scratch/agy_capture.py`

SecOps comparison captures:

- Current full TTY smoke: `/tmp/secops_tui_smoke.txt`
- Current full TTY smoke raw ANSI: `/tmp/secops_tui_smoke.bin`
- Idle frame: `/tmp/secops_v2_full_idle_frame.txt`
- Settled idle frame: `/tmp/secops_v2_idle_quiet_frame.txt`
- Main smoke capture: `/tmp/secops_v2_full_tui.txt`
- Extra panels: `/tmp/secops_v2_extra_tui.txt`
- Raw smoke: `/tmp/secops_v2_full_tui.bin`
- Previous full re-baseline: `/tmp/secops_v2_rebaseline_34x120.txt`
- Previous full re-baseline raw ANSI: `/tmp/secops_v2_rebaseline_34x120.bin`
- Previous P8 verification smoke: `/tmp/secops_v2_p8_permission_prompt_tui.txt`
- Previous P8 verification smoke raw ANSI:
  `/tmp/secops_v2_p8_permission_prompt_tui.bin`
- Previous P9 settings-edit smoke: `/tmp/secops_v2_p9_settings_edit_tui.txt`
- Previous P9 settings-edit smoke raw ANSI:
  `/tmp/secops_v2_p9_settings_edit_tui.bin`
- Previous exact-command permission smoke:
  `/tmp/secops_v2_exact_command_permission_tui.txt`
- Previous exact-command permission smoke raw ANSI:
  `/tmp/secops_v2_exact_command_permission_tui.bin`
- Previous exact-command guard permission smoke:
  `/tmp/secops_v2_exact_command_permission_guard_tui.txt`
- Previous exact-command guard permission smoke raw ANSI:
  `/tmp/secops_v2_exact_command_permission_guard_tui.bin`
- Previous AGY-prefix permission smoke:
  `/tmp/secops_v2_agy_prefix_permission_tui.txt`
- Previous AGY-prefix permission smoke raw ANSI:
  `/tmp/secops_v2_agy_prefix_permission_tui.bin`
- Previous shortcut-regression smoke:
  `/tmp/secops_v2_shortcut_regression_tui.txt`
- Previous shortcut-regression smoke raw ANSI:
  `/tmp/secops_v2_shortcut_regression_tui.bin`
- Previous shortcut-wording full smoke:
  `/tmp/secops_v2_shortcut_wording_full_tui.txt`
- Previous shortcut-wording full smoke raw ANSI:
  `/tmp/secops_v2_shortcut_wording_full_tui.bin`
- Previous tool-spacing smoke: `/tmp/secops_v2_tool_spacing_tui.txt`
- Previous tool-spacing smoke raw ANSI: `/tmp/secops_v2_tool_spacing_tui.bin`
- Capture harness: `scratch/tui_smoke.py`

AGY prompting-mode approval capture:

- Root: `/tmp/secops_agy_permission_prompt`
- Captured AGY version: `1.0.3`
- Redacted inspection source:
  `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review.txt`
- Raw ANSI:
  `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review.bin`
- Final frame:
  `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review_frame.txt`
- Capture harness: `scratch/agy_permission_prompt_capture.py`

AGY direct shell-mode capture:

- Captured AGY version: `1.0.4`
- Read-command root: `/tmp/secops_agy_permission_prompt_strict_bang_pwd`
- Read-command redacted inspection source:
  `/tmp/secops_agy_permission_prompt_strict_bang_pwd/agy_permission_prompt_strict.txt`
- Read-command raw ANSI:
  `/tmp/secops_agy_permission_prompt_strict_bang_pwd/agy_permission_prompt_strict.bin`
- Read-command final frame:
  `/tmp/secops_agy_permission_prompt_strict_bang_pwd/agy_permission_prompt_strict_frame.txt`
- Write-command root: `/tmp/secops_agy_permission_prompt_strict_bang_touch`
- Write-command redacted inspection source:
  `/tmp/secops_agy_permission_prompt_strict_bang_touch/agy_permission_prompt_strict.txt`
- Write-command raw ANSI:
  `/tmp/secops_agy_permission_prompt_strict_bang_touch/agy_permission_prompt_strict.bin`
- Write-command final frame:
  `/tmp/secops_agy_permission_prompt_strict_bang_touch/agy_permission_prompt_strict_frame.txt`
- Capture harness: `scratch/agy_permission_prompt_capture.py`

Terminal dimensions used for the full comparison:

- AGY: `34x120`
- SecOps: `34x120`

## AGY Surfaces Captured And Used

- Startup and idle prompt frame
- `?` shortcuts surface
- `/help` general, commands, and shortcuts tabs
- Deep command and shortcut scrolling
- Slash palette initial view, navigation, page navigation, and filters `a-z`
- `/model` picker and navigation
- `/agents`
- `/artifact`
- `/keybindings`
- `/context`
- `/config` / `/settings`
- `/hooks`
- `/mcp`
- `/diff`
- `/permissions`
- Long generation
- Generation interrupted with `esc`
- Shell/tool execution with `pwd`
- Slow local shell execution
- Direct AGY bash-mode execution with `!pwd` and
  `!touch /tmp/secops_agy_write_probe_strict` was captured separately on
  2026-06-02 against AGY `1.0.4`. It shows the `○ ! ...` / `● ! ...`
  transcript grammar and no approval prompt.
- `request-review` approval prompt for `pwd`
- `ctrl+o` after and during tool execution
- `ctrl+r` artifact review
- Static CLI help for the main command

Captured only to exclude from SecOps scope unless backed later:

- `/changelog`
- `/credits` account/model-credit surface
- `/memory`, which AGY returned as an unknown command in this capture
- Static CLI help for plugin/update/install subcommands

## Known Capture Limits

- Central parity work is based on the AGY `1.0.3` full capture. The AGY `1.0.4`
  direct-shell captures are supplemental evidence only and do not expand the
  SecOps implementation scope.
- AGY approval prompt evidence currently covers `request-review` for a harmless
  `pwd` shell command. Strict-mode and write-specific prompt variants were not
  captured as usable permission-prompt evidence.
- AGY strict-mode approval captures on 2026-06-01 and 2026-06-02 reached quota
  before tool planning, so they do not provide permission-prompt evidence. The
  2026-06-02 fresh attempt is stored in
  `/tmp/secops_agy_permission_prompt_strict_fresh/`.
- AGY `strict` + `!pwd` direct bash-mode capture on 2026-06-02 did execute
  without LLM quota and without a permission prompt. It is shell-mode evidence,
  not approval-prompt evidence, and remains out of SecOps implementation scope
  unless the user explicitly asks for a new direct shell shortcut.
- AGY `strict` + `!touch /tmp/secops_agy_write_probe_strict` direct bash-mode
  capture on 2026-06-02 also executed without LLM quota and without a permission
  prompt, creating an empty file in `/tmp`. It is write-command shell-mode
  evidence, not approval-prompt evidence, and remains out of SecOps
  implementation scope unless the user explicitly asks for a new direct shell
  shortcut.
- AGY compound-command approval capture attempts on 2026-05-31 returned the
  upstream high-traffic message before tool planning. SecOps therefore uses the
  captured AGY `commands that start with ...` prefix wording from the `pwd`
  request-review prompt, while adding a SecOps guard so a saved prefix does not
  cover later commands that append shell-control chains such as `&&`, `;`, or
  pipes.
- Install/update/plugin/changelog mutation flows were intentionally not
  executed and are not SecOps implementation targets without backed content.
- Some deep slash-scroll final frames contain ANSI redraw artifacts. Use the
  corresponding `.txt` and `.bin` files as supporting evidence before making
  exact spacing decisions on those deep-scroll states.

## Baseline Comparison Matrix

This matrix preserves the original verified gaps and implementation plan from
the comparative study. For the current implementation state, use the
`Execution Status` section above; all rows P1-P14 are currently marked `Done`
for captured AGY behavior within SecOps scope.

| ID | Surface | AGY evidence | SecOps evidence | Verified gap | Plan |
| --- | --- | --- | --- | --- | --- |
| P1 | Startup / idle frame | `agy_idle_frame.txt` | `secops_v2_idle_quiet_frame.txt` | When captured after redraw settles, SecOps already has the top separator, prompt line, lower separator, and footer. The remaining verified gap is metadata: SecOps showed an account-like `user@host` line even though the product constraint is no account/login ceremony. | Keep the SecOps logo and prompt rhythm; remove account-like metadata from startup and keep model/path context. |
| P2 | Slash palette | `agy_slash_palette_frame.txt`, filters `a-z` | `secops_v2_full_tui.txt` `/` section | AGY shows five visible rows, compact command names, `↓ N more`, and a stable footer. SecOps showed six rows, usage-heavy command labels, and a separate `/tools` discovery island. | Keep the AGY palette rhythm and expose only backed SecOps command rows, such as real `/tool <name>` entries; do not invent skills, MCP, hooks, task-id, or workflow action rows. |
| P3 | Help / shortcuts | `agy_help_command_frame.txt`, `agy_help_shortcuts_scroll_deep.*` | `secops_v2_full_tui.txt` help views | Shape is close, but AGY has tighter list grammar, clearer selected rows, item counts, and `/keybindings to customize`. SecOps has `/keybindings` as a shortcuts tab, not real customization. | Polish the help surface and only advertise keybinding customization after it exists. |
| P4 | Model picker | `agy_model_command_frame.txt` | `secops_v2_full_tui.txt` `/model overlay` | SecOps is close, but row spacing and current-selection alignment should be matched exactly. | Minor alignment pass; do not add unsupported models. |
| P5 | Long generation / interruption | `agy_long_generation*.txt`, `agy_long_generation_cancel_esc_frame.txt` | `secops_v2_full_tui.txt` streaming display | AGY uses spinner states, `esc to cancel`, delayed second-line tips, and an interruption follow-up: `Interrupted · What should Antigravity CLI do instead?`. SecOps uses inline `Generating... · Tip: ...` and no captured equivalent interruption follow-up. | Implement AGY-style long-running generation UX with `esc` interruption and follow-up prompt. |
| P6 | Tool running and transcript | `agy_tool_sleep_long.txt`, `agy_permission_probe_pwd.txt` | `secops_v2_full_tui.txt` tool display | AGY differentiates collapsed and expanded tool cards, uses `▸/▾ Thought`, `● Bash(...)`, `○ Bash(...)` during running, `Running...`, and `ctrl+o` expand/collapse labels. SecOps has the basic tool/result grammar but less stateful expansion. | Add transcript state for thought/tool collapse, running state, and `ctrl+o` inline expansion. |
| P7 | `ctrl+o` trajectory behavior | `agy_tool_pwd_ctrl_o_after_frame.txt`, `agy_tool_sleep_ctrl_o_during.*` | `secops_v2_full_tui.txt` `/trajectory` | AGY `ctrl+o` expands/collapses the active transcript in place. SecOps `ctrl+o` opens a broader trajectory-style surface. | Make `ctrl+o` first toggle the latest relevant thought/tool transcript; keep full `/trajectory` as the detailed view. |
| P8 | Permissions | `agy_permissions_command_frame.txt`, `agy_config_command_frame.txt`, `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review.txt` | `secops_v2_extra_tui.txt` `/permissions`, `/tmp/secops_v2_agy_prefix_permission_tui.txt`, `/tmp/secops_v2_shortcut_wording_full_tui.txt` | AGY permission modes and the `request-review` `pwd` picker are captured. SecOps previously used internal command-resource labels, treated `esc` like a denial, over-broadened command approvals, and left too much vertical space between picker options. Later AGY `strict` direct-shell captures prove `!pwd` and `!touch` shell-mode transcript behavior but not approval prompts. | Keep the mode panel aligned, use captured command approval copy, compact option spacing, treat `esc` as interruption, and use AGY-style `commands that start with ...` approvals with a SecOps guard against appended shell-control chains. Defer strict/write-specific approval-prompt variants until captured; do not add AGY `!` shell mode without an explicit SecOps request. |
| P9 | Settings / config | `agy_config_command_frame.txt`, `agy_settings_command_frame.txt` | `secops_v2_extra_tui.txt` `/config`, `/tmp/secops_v2_p9_settings_edit_tui.txt` | AGY uses a searchable settings panel with editable rows and descriptions. SecOps now matches the searchable panel and `enter Edit` grammar for runtime-backed settings, while env/config-source rows remain read-only. | Keep settings edits limited to real SecOps runtime state: profile, model, permissions, and sandbox. Do not add fake editors for env-only values. |
| P10 | Context usage | `agy_context_command_frame.txt` | `secops_v2_extra_tui.txt` `/context` | AGY renders a token budget visualization with related actions. SecOps shows a compact static table. | Add a compact token/context usage bar with SecOps-relevant related actions. |
| P11 | Agents / tasks | `agy_agents_command_frame.txt` | `secops_v2_full_tui.txt` `/agents`, `/tasks` | AGY has a stronger creation/discovery frame and explicit agent paths. SecOps currently shows only the primary foreground session when empty. | Rework SecOps agents/tasks into an AGY-like orchestration panel, but use pentest profiles/subagents only. |
| P12 | Artifacts / review | `agy_artifact_command_frame.txt`, `agy_ctrl_r_idle_frame.txt` | `secops_v2_full_tui.txt` `/artifact`, attachments | AGY artifact review uses `p preview`, `enter open`, `esc dismiss`. SecOps artifact view is simpler and attachment-focused. | Add preview/open keyboard grammar to SecOps artifacts and evidence. |
| P13 | MCP / hooks / extensions | `agy_mcp_command_frame.txt`, `agy_hooks_command_frame.txt` | `secops_v2_extra_tui.txt` `/mcp`, `/hooks`, `/skills`, `/tools` | AGY presents extension surfaces as navigable action panels. SecOps shows mostly static empty-state overlays. Plugin mutation help was captured only as exclusion evidence. | Rebuild extension panels as navigable action surfaces, backed by real SecOps MCP, hooks, skills, and tool registry data. |
| P14 | CLI before TUI | `static_cli/help.txt`; plugin/update/install/changelog help captured only as exclusion evidence | `secops_agent/main.py` Typer options | AGY has `--print`, `--prompt-interactive`, `--sandbox`, permission skip, plugin, changelog, update. SecOps CLI is thinner. | Add only relevant entrypoints: non-interactive prompt, prompt-interactive, sandbox/permission flags, and real diagnostics. Keep plugin, update, install, and changelog commands out unless SecOps has backed content for them. |

## Completed Implementation Sequence

This section is retained as the historical execution recipe used for P1-P14.
It is not the active backlog. The current backlog is the `Next work queue`
above: evidence refreshes, regression passes, and cleanup only.

### Step 1: Evidence Harness Hardening

Source files:

- `scratch/agy_capture.py`
- `scratch/tui_smoke.py`

Work:

- Keep `full` capture mode available.
- Add optional redacted summary output for AGY captures so docs can cite stable
  snippets without account identity.
- Add targeted capture modes for one surface at a time.

Acceptance:

- `python -m py_compile scratch/agy_capture.py scratch/tui_smoke.py`
- Re-run one AGY targeted capture and one SecOps targeted capture.

### Step 2: Startup / Idle Frame

Source files:

- `secops_agent/main.py`
- `secops_agent/ui/theme.py`
- `secops_agent/ui/renderer.py`
- `secops_agent/ui/input_handler.py`

Work:

- Create a single reusable idle prompt-frame path.
- Preserve SecOps logo.
- Remove account/login concepts.
- Ensure startup and `/clear` land on the same final prompt/footer rhythm.

Acceptance:

- Compare against `/tmp/secops_agy_full/agy_idle_frame.txt`.
- SecOps capture must show logo, metadata, top separator, `>`, lower separator,
  and footer `? for shortcuts` with model on the right.

### Step 3: Slash Palette Grammar

Source files:

- `secops_agent/ui/input_handler.py`
- `secops_agent/ui/commands.py`
- `secops_agent/ui/renderer.py`

Work:

- Show five command rows by default.
- Keep labels compact; move usage details out of the command label.
- Preserve `↓ N more` and `↑/↓ Navigate · enter Select · tab Complete`.
- Keep dynamic slash rows limited to backed SecOps entries already visible in
  captures, such as real `/tool <name>` rows; do not add skills, MCP, hooks,
  agent-profile, task-id, or workflow action rows without fresh AGY evidence.
- Keep non-pentest AGY plugin/browser commands out.

Acceptance:

- Compare against `/tmp/secops_agy_full/agy_slash_palette_frame.txt`.
- Re-run SecOps slash smoke with `34x120`.

### Step 4: Help And Keybindings

Source files:

- `secops_agent/ui/renderer.py`
- `secops_agent/ui/commands.py`
- `secops_agent/ui/input_handler.py`

Work:

- Tighten tabbed help rows and selected-row behavior.
- Add item counts where lists scroll.
- Keep `/keybindings` as a shortcuts surface unless real customization is
  implemented.

Acceptance:

- Compare against AGY help and shortcuts captures.
- Help tabs must render without redraw fragments.

### Step 5: Model Picker Alignment

Source files:

- `secops_agent/ui/menu.py`
- `secops_agent/ui/renderer.py`
- `secops_agent/core/model_catalog.py`

Work:

- Align row spacing, current marker, and footer grammar with AGY.
- Keep only SecOps-supported model profiles.

Acceptance:

- Compare against `/tmp/secops_agy_full/agy_model_command_frame.txt`.

### Step 6: Long-Running Generation UX

Source files:

- `secops_agent/ui/animations.py`
- `secops_agent/ui/renderer.py`
- `secops_agent/main.py`

Work:

- Render `Generating...` as the primary spinner line.
- Move wait tips to a secondary `└ Tip: ...` line after the AGY-like delay.
- Show `esc to cancel`.
- On interrupt, show an AGY-like follow-up asking what to do instead.

Acceptance:

- Compare against `agy_long_generation*.txt`.
- Add a synthetic streaming cancellation smoke test.

### Step 7: Tool Transcript And `ctrl+o`

Source files:

- `secops_agent/ui/tool_display.py`
- `secops_agent/ui/renderer.py`
- `secops_agent/ui/input_handler.py`
- `secops_agent/ui/runtime.py`
- `secops_agent/core/agent.py`

Work:

- Track latest thought/tool call/result as expandable transcript state.
- Use `▸ Thought` collapsed and `▾ Thought` expanded grammar.
- Use `● Tool(args) (ctrl+o to expand)` collapsed and `⎿ result (ctrl+o to collapse)` expanded.
- Use `○ Tool(args) (ctrl+o to expand)` plus `Running...` while a tool is active.
- Make `ctrl+o` toggle latest transcript first; keep `/trajectory` for full timeline.
- Preserve pentest tool names and risk labels.

Acceptance:

- Compare against `agy_tool_pwd_ctrl_o_after_frame.txt` and `agy_tool_sleep_ctrl_o_during.*`.
- SecOps smoke must include collapsed and expanded tool transcript states.

### Step 8: Permissions And Sandbox

Source files:

- `secops_agent/core/permissions.py`
- `secops_agent/core/sandbox.py`
- `secops_agent/ui/tool_display.py`
- `secops_agent/ui/renderer.py`

Work:

- Align permission mode panel with AGY-like mode selector.
- Keep SecOps safer defaults if required by pentest risk.
- Align the approval picker only against captured `request-review` evidence:
  command text, compact option spacing, visible keyboard grammar, and
  interruption on `esc`.
- Use the captured AGY `commands that start with ...` prefix wording for shell
  command approvals, while keeping the SecOps guard that blocks saved prefixes
  from covering later commands with appended shell-control chains.

Acceptance:

- Compare mode panel against `agy_permissions_command_frame.txt`.
- Compare approval prompt against
  `/tmp/secops_agy_permission_prompt/agy_permission_prompt_request_review.txt`.
- Approval prompt tests must still pass.

### Step 9: Settings, Context, Extensions

Source files:

- `secops_agent/ui/renderer.py`
- `secops_agent/ui/runtime.py`
- `secops_agent/core/extensions.py`
- `secops_agent/core/mcp.py`

Work:

- Convert `/config` into a searchable settings/action panel.
- Keep `enter Edit` limited to backed runtime settings: profile, model,
  permissions, and sandbox.
- Convert `/context` into a token/context budget visualization.
- Convert `/hooks`, `/mcp`, `/skills`, and `/tools` into navigable action panels.

Acceptance:

- Compare against AGY settings, context, MCP, hooks, and tools-related captures.
- Settings smoke must cover search plus `enter Edit` opening a backed editor.
- Empty states must remain useful and pentest-specific.

### Step 10: Artifacts, Evidence, And Review

Source files:

- `secops_agent/ui/renderer.py`
- `secops_agent/ui/attachments.py`
- `secops_agent/ui/session_review.py`

Work:

- Add `p preview`, `enter open`, and `esc dismiss` grammar.
- Make `ctrl+r` open latest evidence/artifact review.
- Preserve SecOps evidence semantics: findings, attachments, reports, tool outputs.

Acceptance:

- Compare against `agy_artifact_command_frame.txt` and `agy_ctrl_r_idle_frame.txt`.

### Step 11: Pre-TUI CLI Entrypoints

Source files:

- `secops_agent/main.py`
- `README.md`

Work:

- Add relevant AGY-like entrypoints: `--print`, `--prompt-interactive`,
  `--sandbox`, permission mode flags, and a backed `doctor` diagnostic command.
- Do not add fake update/install/plugin/changelog commands without real backing
  behavior.

Acceptance:

- `secops --help` should expose the relevant entrypoints.
- Non-interactive prompt mode must be testable without entering the TUI.

## Regression Verification Baseline

Use this baseline for future evidence refreshes, regression passes, or any
explicitly requested implementation change:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

For any future TUI-parity change, also produce a fresh targeted SecOps PTY
capture and compare it against the named AGY capture path before treating the
change as complete.
