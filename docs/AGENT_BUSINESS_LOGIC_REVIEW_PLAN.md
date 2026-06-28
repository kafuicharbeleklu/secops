# Agent Business Logic Review Plan

Date: 2026-06-03

## Objective

Move SecOps CLI from autonomous follow-up execution to a proposal-first pentest
workflow. The agent should still understand mission state and generate good next
steps, but it should not start additional tools after a result unless the user
clearly requested a broad phase or explicitly approved the next action.

This is not an AGY visual parity ticket. It is a core agent behavior correction
based on the recent TryHackMe lab run where chained tools made the terminal feel
blocked and produced late, hard-to-follow output.

## Review Findings

### F1 - The Planner Proposes, But The Agent Executes

`MissionPlanner` is written as a proposal engine. Its prompt summary explicitly
says candidate actions should not be executed without user intent and permission.
However, `SecOpsAgent.stream_response()` currently turns parser changes into
real chained tool calls through `_build_chained_tool_calls()`.

Impact:

- A single successful scan can trigger multiple follow-up tools.
- The user does not regain control between steps.
- Permission protects sensitive tools, but it does not solve unwanted autonomy
  when a tool is already allowed for the session.

Target behavior:

- Parser integration should update mission state and produce suggested next
  actions.
- Suggested next actions should be surfaced to the user.
- The agent should wait for the user to choose or confirm before executing them.

### F2 - Chaining Must Be Controlled By User Intent

The chain budget and dedupe rules prevent runaway loops, but they do not decide
whether the user wanted autonomous execution in the first place. P22.5-P22.10
replace the older guided-lab heuristic with a first-class request decision:
technical goal, user intent, risk, scope status, and environment metadata.

Impact:

- The same prompt shape appears in CTFs, private VM labs, and authorized
  organization assessments.
- Environment labels alone are not reliable enough to decide tool behavior.
- Broad vs narrow user intent must be represented as a first-class policy.

Target behavior:

- Introduce an explicit intent policy:
  - `answer_only`: answer from known facts or one requested tool.
  - `single_tool`: run the explicitly requested tool only.
  - `propose_next`: default after new evidence; do not execute follow-ups.
  - `approved_batch`: execute multiple steps only after explicit broad user
    intent such as "run full recon", "continue the enumeration", or an approval
    of proposed actions.
- Treat CTF, private lab, and authorized organization labels as metadata for
  setup, reporting, and context, not as the main orchestration driver.

### F3 - Long-Running Feedback Exists, But It Is Not Granular Enough

The TUI supports `ToolProgressEvent`, and long-running tools emit progress
events. But wrappers such as Nmap, GoBuster, Nikto, and SQLMap mostly report
before starting the subprocess and after it exits. During the actual subprocess,
the user sees activity but not enough live output or intermediate state.

Impact:

- The terminal can feel blocked even when the process is running correctly.
- If multiple chained tools run, the lack of intermediate output compounds the
  confusion.
- The user may interrupt because the agent appears to have taken over.

Target behavior:

- Proposal-first orchestration reduces surprise.
- For approved long-running tools, stream lightweight progress from subprocess
  output when practical.
- Keep collapsed AGY-like output by default, but make live status truthful and
  frequent enough to show what is happening.

### F4 - Permission Is Not An Intent Confirmation

The approval prompt answers "may this tool run?" It does not answer "should the
agent keep running more tools after this result?" A session or persistent allow
rule can make future chained actions technically permitted while still being
unexpected.

Impact:

- "Allowed for session" can become broader than the user's operational intent.
- The agent can appear to continue because permission is available, not because
  the user asked for the next step.

Target behavior:

- Permission remains a safety gate.
- Intent remains an orchestration gate.
- Both must pass before a follow-up tool executes.

### F5 - LLM Follow-Up Can Bypass Planner Restraint

Disabling parser-driven planner chaining is not enough if the agent calls the
LLM again after a tool result with the full tool schema still available. In that
case, the planner is proposal-first, but the model can still request additional
tools in the same user turn.

Impact:

- A single user request can still become a hidden multi-tool sequence.
- Long-running tools can appear after the previous tool completed, making the
  terminal feel blocked or surprising.
- Permission prompts may protect individual tools, but they do not prove the
  user intended a new step.

Target behavior:

- After a tool result, allow one natural-language summary pass.
- Do not expose tools to that summary pass unless explicit automatic
  orchestration is enabled.
- Ignore any tool call emitted during the text-only summary pass.

## Proposed Business Logic

### Default Rule

After every tool result, SecOps CLI should:

1. parse the output,
2. update mission state,
3. calculate candidate next actions,
4. display a concise "Suggested next actions" section,
5. wait for the next user instruction.

It should not enqueue and run candidate tools automatically by default.

### Execution Rules

| User intent | Example | Agent behavior |
| --- | --- | --- |
| Specific question | "How many ports are open?" | Run at most the needed tool, answer, stop. |
| Explicit tool request | "Run GoBuster on the web server." | Run that tool only, with permission if needed, then stop. |
| Broad phase request | "Do full recon on this target." | Ask for a proposed action set or execute an approved bounded batch, depending on policy. |
| Continue request | "Continue with the next step." | Execute the top suggested action only, with permission if needed. |
| Batch approval | "Run the first three suggested actions." | Execute only the selected bounded actions. |

### Suggested Action Surface

The agent should produce a short plain response after a result, for example:

```text
Suggested next actions:
1. Analyze HTTP headers on http://10.129.153.73
2. Detect web technology on http://10.129.153.73
3. Discover web content on http://10.129.153.73

Reply with the number or describe what to do next.
```

This should be generated from `MissionPlanner`, not improvised by the model.

## Implementation Plan

### P16 - Disable Automatic Planner Execution By Default

Status: Done

Work:

- Change `SecOpsAgent` so parser-driven planner actions are recorded as
  suggestions, not appended to `tool_calls_to_run`.
- Keep structured memory, phase updates, findings, evidence, and report state.
- Preserve P14/P15 local preflights for explicit single-tool requests.

Acceptance:

- After an Nmap result discovers HTTP, the agent does not automatically execute
  `http_headers`, `tech_detect`, `dir_brute`, or `nikto_scan`.
- Tests prove no chained `ToolStartEvent` is emitted after parser integration.
- Existing permission and scope tests still pass.

Implementation notes:

- `SecOpsAgent` now defaults `max_chained_actions_per_turn` to `0`.
- Existing explicit opt-in chaining remains available for future approved batch
  semantics, but it is no longer the normal CLI behavior.
- P14/P15 single-tool preflights remain intact for explicit lab/tool requests.

### P17 - Add Deterministic Suggested Next Action Events

Status: Done

Work:

- Add a lightweight event or text block for planner suggestions.
- Render the top actions after tool results when mission state changes.
- Include action number, title, tool name, target, and risk.
- Avoid adding a new slash command or shortcut.

Acceptance:

- Tool results are followed by concise suggestions.
- Suggestions are derived from `MissionPlanner`.
- The UI stays sparse and does not become a dashboard.

Implementation notes:

- `SuggestedActionsEvent` carries deterministic `MissionPlanner` candidates.
- The renderer prints a compact proposal block after the related tool result.
- Focused answer turns remain quiet and do not show follow-up suggestions.
- `--print` and background side-task consumers convert the event to plain text
  or log entries instead of dropping it silently.

### P18 - Add One-Step Continuation Semantics

Status: Done

Work:

- Interpret "continue", "next", "run the next step", and numbered choices
  against the last suggested action set.
- Execute only the selected action by default.
- Treat multiple numbers as a multiple selection, and support `all` / `tout` /
  `tous` for the full suggestion set.

Acceptance:

- "continue" runs only the top suggestion.
- "1 2" and "run 1 and 2" run only those two suggestions.
- "all", "tout", and "tous" run all available suggestions.
- Dangerous tools still ask for approval.
- Scope guard still blocks out-of-scope actions.

Implementation notes:

- The agent stores the last deterministic suggestion set.
- `continue`, `next`, `suivant`, or `run the next step` select the first
  available suggestion.
- A bare number selects exactly that suggestion.
- Multiple numbers such as `1 2`, `1,2`, or `1 et 2` select those suggestions.
- `all`, `tout`, `tous`, and `toutes` select all suggestions; `all except 3`
  and `tout sauf 3` select all except the numbered exclusions.
- Selected suggestions are converted into normal tool calls, so tool permission
  prompts, command permission prompts, scope guardrails, and result parsing all
  remain active.

### P19 - Separate Permission Scope From Orchestration Scope

Status: Done

Work:

- Keep existing tool/command permissions as safety decisions.
- Add an orchestration decision for automatic batches.
- Do not let "allow for session" imply "continue running future planner actions".

Acceptance:

- A session-level allow for `dir_brute` does not cause automatic `dir_brute`
  execution unless user intent selects that action.
- Permission tests and new orchestration tests demonstrate the separation.

Implementation notes:

- `SecOpsAgent` now has an explicit `allow_automatic_planner_execution` flag.
- `max_chained_actions_per_turn` is only a budget; it no longer authorizes
  automatic planner execution by itself.
- Session or persistent permission rules remain safety decisions only.
- Suggested-action selection from P18 remains the normal way to express user
  orchestration intent.

### P20 - Improve Long-Running Tool Feedback

Status: Done

Work:

- Add streaming subprocess helpers for tools where stdout/stderr can be read
  progressively.
- Prioritize `nmap_scan`, `dir_brute`, `nikto_scan`, and `sql_injection_test`.
- Keep collapsed result summaries and `ctrl+o` expansion unchanged.

Acceptance:

- Long-running tools update progress at least every few seconds when output is
  available or when elapsed time changes.
- Interrupt behavior remains clean.
- PTY smoke tests show the terminal does not appear frozen.

Implementation notes:

- `run_cmd_streaming()` centralizes progressive subprocess execution with
  stdout/stderr readers, idle elapsed-time updates, timeout cleanup, and
  cancellation cleanup.
- `nmap_scan`, `dir_brute`, `nikto_scan`, and `sql_injection_test` now use the
  streaming helper for the actual subprocess window.
- Collapsed result summaries and `ctrl+o` expansion remain unchanged because
  final tool output still flows through the existing tool-result renderer.
- Tests cover output-driven progress, idle elapsed progress, web-tool fallback
  routing, and structured TUI progress percentages.
- The P20-relevant PTY smoke paths passed: `tool running`, `tool running
  ctrl+o`, `streaming display`, and `streaming cancel`. The later R0 rebaseline
  fixed the unrelated `/model overlay` harness assumption, so the full PTY
  smoke is green again.

### P22.5-P22.10 - Add Request Decision Engine

Status: Done

Work:

- Add `RequestDecision` with technical goal, user intent, risk, scope status,
  target, environment hint, and explanatory reasons.
- Feed request-decision context into model routing and system behavior.
- Replace CTF-specific follow-up suppression with focused-answer suppression.
- Keep lab readiness checks isolated to setup/readiness prompts.
- Update the system prompt so it says environment labels are metadata and
  behavior is decided from objective, intent, risk, and scope.

Acceptance:

- TryHackMe/CTF and private VM port questions receive the same technical
  `port_scan` and `answer_question` decision while retaining different
  environment metadata.
- A private VM question such as "combien de ports sont ouverts ?" stops after
  the needed scan and answer.
- A private VM request such as "fais un scan des ports ouverts" can still show
  proposed next actions without executing them.
- Directory enumeration, exploitation, and privilege escalation prompts are
  classified by technical risk, not by assumed platform.
- Tests cover French and English phrasing, explicit target scope, inferred
  session scope, and non-CTF lab wording.

### P23 - Controlled Exploitation Workflow

Status: Done

Work:

- Extend `NextAction` with exploitation-specific method, prerequisites, and
  evidence fields.
- Convert upload/panel paths, SQLi findings, XSS findings, command-execution
  findings, high-impact known vulnerabilities, and unusual SUID binaries into
  bounded candidate actions.
- Keep payload generation behind the existing dangerous-tool permission flow.
- Keep upload/panel and SUID escalation as manual review candidates unless the
  user explicitly selects and scopes the next step.
- Parse SUID enumeration output from `run_shell` into `suid_binary` findings
  while ignoring common expected SUID binaries.

Acceptance:

- Discovery of `/panel` or `/uploads` produces a bounded upload-surface review
  suggestion with prerequisites and evidence.
- SQLi/XSS/command-execution findings can propose `generate_payload`, but only
  as a selected, dangerous action.
- Unusual SUID binaries produce privilege-escalation review suggestions.
- No upload, payload, shell, or privilege-escalation step is auto-started after
  discovery, even when automatic planner execution is enabled for tests.

### P31.6 - Constrain Post-Tool LLM Follow-Up To Text Only

Status: Done

Work:

- Keep the useful second LLM pass after a tool result so the agent can summarize
  findings naturally.
- Remove the tool schema from that post-tool pass unless explicit automatic
  planner execution is enabled.
- Ignore any defensive-test tool call emitted during that text-only follow-up.
- Keep parser integration, mission updates, deterministic suggestions, and
  selected-action execution unchanged.

Acceptance:

- After a scan result, the agent can summarize and show deterministic suggested
  actions.
- The LLM cannot start `http_headers`, `tech_detect`, `dir_brute`, or similar
  follow-up tools during the same user turn unless orchestration is explicitly
  enabled.
- Tests prove a fake LLM that tries to request a second tool in the follow-up
  pass does not produce a second `ToolCallEvent` or `ToolStartEvent`.
- Parser failures remain non-fatal and no Python traceback is printed to the
  user by default.

## Recommended Order

1. P16 first: stop unexpected autonomous execution.
2. P17 second: replace hidden autonomy with visible suggestions.
3. P18 third: make "continue" and numbered choices actionable.
4. P19 fourth: harden the distinction between permission and intent.
5. P20 fifth: improve live feedback for approved long-running commands.
6. P22.5-P22.10 sixth: classify request intent consistently across CTF,
   private VM labs, and authorized assessments.
7. P23 seventh: keep exploitation workflows bounded, evidence-backed, and
   selected step by step.
8. P31.6 eighth: prevent post-tool LLM summaries from reintroducing hidden
   same-turn tool chaining.

## Non-Goals

- Do not add new slash commands or shortcuts for this plan.
- Do not copy coding-agent features that are not relevant to SecOps.
- Do not remove mission planning, structured memory, evidence, or reporting.
- Do not weaken permission prompts or scope guardrails.

## Verification Baseline

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall secops_agent tests -q
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
```

For P20, also run a PTY smoke test with a long-running mocked tool that emits
progress over time.
