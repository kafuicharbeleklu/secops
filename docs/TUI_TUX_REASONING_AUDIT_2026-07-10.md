# TUI / TUX / Reasoning Audit — SecOps Agent (2026-07-10)

> **Nature.** Diagnosis-only pass over three layers *in order*: terminal UI, terminal UX,
> reasoning/business-logic. No source file was modified. Deliverable is this report; we
> decide implementation together afterward.
>
> **Benchmark.** Phases 1–2 weighed against **Antigravity CLI (`agy`)** conventions;
> Phase 3 against **Claude Code / Codex CLI** agentic behavior. Two cross-cutting
> yardsticks applied throughout, above personal taste:
> **(A)** autonomy is opt-in and shown as a visible spectrum, never a hidden default;
> **(B)** trust is built through a **reviewable artifact** (diff / plan / report), never by
> making the operator reconstruct events from a raw transcript.
>
> **Security overlay** applied inline: OWASP Top 10 for Agentic Applications **2026**
> (ASI01/05/06 are high-severity regardless of diff size) + MITRE ATT&CK/ATLAS tags where
> they fit.
>
> **Evidence level.** Every claim below was re-verified against current code (`core/`,
> `ui/`, `cli/`, `tests/`) and, where useful, against **live introspection through the venv**
> (tool registry vs parser registry, default permission decisions, persisted settings).
> The finding format is:
> `[KEEP|CHANGE|ADD] <file:line> — <finding> — <why it matters> — <severity>`.

---

## Corrections to prior audits (re-verified, not repeated)

The repo's most recent audit (`UX_AUDIT_2026-07-09.md`, yesterday) covers much of this brief
and is **mostly accurate on re-verification**. Three of its claims are now **stale or wrong**
and are corrected here rather than repeated:

1. **STALE — UX_AUDIT F4.1 "ASI01: no explicit guard against indirect injection via tool
   output."** False as of current code. `core/output_sanitizer.py::sanitize_tool_output` is
   **wired into `core/memory.py:64` `add_tool_result`**: it strips 16 injection patterns and
   wraps every tool result in `── TOOL DATA [tool] ── … ── END TOOL DATA ──` boundary markers
   before the output enters conversation memory. A real ASI01/ASI04 defense exists. (Its
   *limits* are a separate finding — see R3.4.)

2. **STALE — UX_AUDIT F1.3 "below 90 cols, posture/permissions/phase all disappear."**
   Re-reading `input_handler.py:1099-1106`: in the 60–90 col band the statusline keeps
   `permissions` **and** `posture` (`auto:{level}`); only `phase` and `~tokens` drop. The
   safety-relevant fields survive down to **60** cols, not 90. (The real gap is different —
   no cost, no iteration counter; see T1.3.)

3. **STALE — ARCHITECTURE.md §8 cites `test_exploit_request_sends_no_function_tools_by_default`.**
   That test name no longer exists. The design evolved from "send no tools" to
   "expose the **safe-baseline floor**, withhold offensive primitives"
   (`tests/test_request_routing.py::test_unapproved_exploit_exposes_safe_baseline_not_offensive_primitives`).
   The doc reference is dead; the behavior it describes is inverted.

Also refreshed against live introspection: the registry now holds **39 tools** (prior audits
said 38), the parser registry has **19 dedicated parsers + 1 generic-mapped key** (`xss_test`),
and the risk taxonomy is **r0–r8 (9 classes)**, of which **r7 and r8 have zero tools assigned**.

---

## Phase 1 — Terminal UI (benchmark: Antigravity `agy`)

### T1.1 — Reviewable diff is rendered *after* execution, not at the approval gate
`[CHANGE] ui/tool_display.py:672 (ToolResultBox) vs :799 (ApprovalPrompt)` — For `write_file`
the "agy-verified diff" (`⎿ Added N lines` + numbered `+` content) renders in
`ToolResultBox.render`, which runs on the **result** — i.e. *after* the write already
happened. The pre-execution `ApprovalPrompt` shows prose only: `Requesting permission for:
write_file(...)` + `Resource: … · Risk: R…`. `run_shell` is the one exception — command
resources show the exact command and let the operator edit it (`e`), which *is* a reviewable
artifact. `write_file` and `webshell_exec` (tool resources) get no content/diff preview
before approval. — **Directly violates yardstick (B):** the operator grants the write on a
one-line summary and only sees what changed once it's irreversible. This is the single
clearest UI gap against agy's "verify at a glance before it happens." **ASI09 (Human-Agent
Trust Exploitation); ATLAS AML.T0051.** — **important**

### T1.2 — Risk is binary on the live tool card; r0–r8 gradation only shows in the approval prompt
`[CHANGE] ui/tool_display.py:287 (_tool_status_color)` — The live card color is binary:
`is_dangerous → warning (yellow)`, else `accent`. A `dir_brute` (r3), a `webshell_exec` (r6)
and a `generate_payload` (r6) all render the same yellow `●`. The rich `_RISK_LABELS`
(`:401`, "R0…R8") appear **only** inside the approval prompt — and an auto-allowed dangerous
tool (`nmap_scan`, r3) never triggers that prompt, so it shows **no** risk label anywhere.
`ui/theme.py:20` has `danger/warning/success` but **no r0–r8 severity palette**, so recon
findings, permission prompts, and diffs each speak a different color dialect. — The brief's
"one consistent color/severity language across surfaces" is unmet; the taxonomy exists and is
even labelled, it's just not shown where the eye lives. — **nice-to-have** (borderline
important for an offensive tool where risk legibility is the product)

### T1.3 — Statusline has no cost and no iteration budget indicator
`[CHANGE] ui/input_handler.py:1083 (_build_statusline)` — The live toolbar is rich
(model · state · phase · cwd · sandbox · permissions · `auto:{posture}` · tokens · tasks ·
dirs · tools) and degrades sensibly by width. But it carries **no cost/$**, no `/cost` or
`/status` command, and — despite `max_iterations=14` bounding every turn — **no
`iteration N/14` counter**. The operator cannot see how close a turn is to exhausting its
loop budget, which is exactly the moment autonomy feels like a hidden default. — Yardstick
(A): the autonomy *spectrum* is shown (`auto:semi-auto`), but its *consumption* (how many of
the 14 steps are spent) is invisible. — **nice-to-have**

### T1.4 — Slash completion shows descriptions and dynamic values, but not usage syntax or the active permission mode
`[CHANGE] ui/input_handler.py:760 (SlashCommandCompleter)` — Root completion yields
`display_meta = description` and dynamic value-completion for `/model`, `/permissions`,
`/tool`, `/sandbox`, `/load`. It does **not** surface the per-command `usage=` string that
already exists in `ui/commands.py` (e.g. `/btw <query>`, `/permissions [allow|ask|deny|clear]
<resource>`), and it never shows the **active permission mode** (`request-review` /
`always-proceed` / `strict`) at the point of typing a command that changes safety posture. —
Discoverability win is half-built: the data (`usage`) is one field away. — **nice-to-have**

### T1.5 — Structured scan progress is a transient spinner, not a persisted structured surface
`[CHANGE] ui/animations.py (ToolExecutionSpinner) + core/tools.py:192 (ToolProgress)` — Live
scans show a spinner + elapsed timer, which is visually distinct from prose (good). But
`report_progress`/`ToolProgress` structured updates are **not** rendered as a progress bar or
persisted panel; the collapsed `⎿` result + `ctrl+o` is the only durable trace. There is no
always-on artifact/task surface a large scan writes into. — agy's "Artifacts" model
(large output verifiable at a glance, annotatable without interrupting) is unmet; connects to
T2.2. — **nice-to-have**

### T1.6 — Degraded terminals handled by `isatty` gating; no theme/NO_COLOR affordance
`[KEEP] ui/renderer.py (isatty guards throughout) + :347 force_terminal=False` — Overlays and
panels are gated behind `sys.stdin.isatty() and sys.stdout.isatty()`, so SSH/tmux/CI/pipe
runs degrade to plain output; `ApprovalPrompt` hard-**denies** dangerous tools when stdin
isn't a TTY (`tool_display.py:817`) — a safe non-interactive default (pair with
`--permission-mode always-proceed` for `--print`). Rich auto-strips ANSI on non-TTY, so CI
capture is clean. `ui/theme.py` is a single hardcoded dark palette (`code_theme="ansi_dark"`);
no `NO_COLOR`/`--no-color`/theme switch, relying on Rich's built-in `NO_COLOR` handling. Solid
baseline; the only gap is a selectable theme (Codex parity), which is cosmetic. — **KEEP**
(theme selection: nice-to-have)

---

## Phase 2 — Terminal UX (benchmark: Antigravity `agy`)

### T2.1 — Approval is per-tool at ACT time; no "approve the plan once" path and no plan preview
`[ADD] core/planner.py (plan recomputed each turn, discarded) + no /plan command` — Low-risk
recon/enum chains autonomously (good), but every high-risk step raises its own prompt at the
instant of execution; there is **no** surface that shows the *candidate trajectory* before it
starts and **no** "approve this plan, then run the low-risk chain unattended" path. The `Plan`
is not a first-class persisted object on the blackboard (ARCHITECTURE §4/§8 chantier 5, still
open) and there is no `/plan`. — This is the largest agentic-parity gap vs **Codex** (inline
per-step plan approval) and **Claude Code** (plan mode as a zero-cost exploration space).
Yardstick (B): the reviewable artifact for a *multi-step* mission (the plan) doesn't exist.
**ASI09.** — **important**

### T2.2 — `/artifact` is secondary to scrollback; findings live in the transcript
`[CHANGE] ui/renderer.py:render_artifacts + main.py:1298 (/artifact)` — `/artifact` exists and
lists artifacts, but artifacts are created only at a few export/report points, **not**
auto-generated from scans/findings. The primary way results surface is the tool-call
scrollback + collapsed `⎿`. — Yardstick (B) again: trust should build from a durable artifact,
but here the operator reconstructs the mission from transcript. Making `/artifact` (or a
report) the primary finding surface is the highest-leverage TUX change. — **important**

### T2.3 — `/btw` correctly runs off the main loop budget
`[KEEP] main.py:1218 (/btw)` — `/btw` spawns a **separate** `SecOpsAgent` over a **copied**
memory (`_copy_memory`) as an `asyncio` background task, with its own `max_iterations`. It
genuinely does not consume the main loop's iteration budget, and side answers don't mutate the
main blackboard. Matches the intent exactly. — **KEEP**

### T2.4 — `/rewind` is a last-turn undo mislabeled as "restore an earlier checkpoint"; no restore-vs-summarize disambiguation
`[CHANGE] main.py:1466 (/rewind) → _rewind_last_turn + ui/commands.py:50` — The handler removes
the last turn's messages and rebuilds artifacts. Its help says "Restore an earlier
**checkpoint**" (implying selection among checkpoints) but it only ever pops the most recent
turn, and there is **no** summarize path (Claude Code's `/rewind` disambiguates restoring
code/conversation vs summarizing). — Overclaimed affordance; a user expecting checkpoint
selection gets a silent single-step undo. — **nice-to-have**

### T2.5 — Convergence guardrails: the repeated-call stop explains itself; the max-iterations stop does not
`[CHANGE] core/agent.py:1904 (repeat stall, good) vs :2555 (max-iter, bare)` — The
repeated-identical-call guard emits a real explanation ("I repeated the same tool call without
making progress, so I stopped to avoid a loop… a different approach or input is needed"), and
the announced-but-unexecuted guard nudges the model to actually call the tool (`:1860`). Both
are good. **But** hitting `max_iterations` yields a bare `ErrorEvent("Max iterations (14)
reached. Stopping to prevent infinite loop.")` with **no** summary of what was accomplished or
what to do next. — The brief asks that a fired guardrail explain *why*, not just *that* it
stopped; two of three do, the budget-exhaustion path (the most likely one on a flaky Gemma
tier) doesn't. — **nice-to-have**

### T2.6 — No vim/emacs editing-mode decision; custom keybindings exist but the mode is a silent gap
`[ADD] ui/input_handler.py:874 (KeyBindings) — no EditingMode/vi_mode` — Custom key bindings
are defined, but prompt_toolkit's `editing_mode` is left at default (emacs); there is no
`vi_mode` and no documented decision either way. — The brief wants keybinding/vim support to be
an **explicit** decision, not an accidental omission. Cheapest resolution is a one-line
`editing_mode` toggle in config or a documented "emacs-only, by design" note. — **nice-to-have**

### T2.7 — Active-enumeration scans hit real targets with no approval by default; README says the opposite
`[CHANGE] core/permissions.py:34 (TOOL_TIERS) + README.md:175` — Live-verified defaults:
`nmap_scan → allow`, `subdomain_enum → allow`, `tech_detect/port_check/ping_host → allow`.
These are `ActionTier.PASSIVE` in the permission table **despite** carrying
`risk_class=ACTIVE_ENUMERATION` (r3, `dangerous=True`) — two taxonomies disagree and the
permission gate follows the laxer one. Meanwhile `README.md:175` states `nmap_scan … require
approval unless a session rule allows them`, which is **factually false** by default. — This
is the "does the operator know what will hit a real target *before* it does?" question, and
the answer for active enumeration is **no**; compounded by a doc that claims otherwise.
**Least-agency / ASI02; ATT&CK T1046, T1595 (ATLAS reconnaissance).** — **important**

### T2.8 — `/permissions allow tool(<r5/r6>)` persists an allow with no risk guard — live-proven
`[CHANGE] cli/permissions.py:34-58 (parse/plan) vs ui/tool_display.py:344 (_SHELL_TOOL_SESSION_ONLY)`
— The approval UI deliberately withholds "Persist to settings.json" for shell/scan tools
(R11 divergence). But `/permissions allow tool(run_shell)` goes through
`PERMISSION_RULE_ACTIONS` with **no** risk check and writes a persistent allow. **Live proof:**
`~/.secops_agent/settings.json` on this machine contains `"tool(run_shell)": "allow"` (r5
shell) **and** a persisted `"command_prefix(whoami && id)": "allow"` (a compound command that
the R11 policy says must never get an always-allow scope). Both could only arrive via the
unguarded CLI/persist path. — Two permission-granting paths with opposite policies; the CLI
silently annuls the UI's intentional safety divergence. **ASI03-adjacent; ATT&CK T1059.** —
**important**

---

## Phase 3 — Reasoning / business logic (benchmark: Claude Code / Codex)

### R3.1 — `max_iterations = 14` is an unjustified constant
`[CHANGE] core/agent.py:228` — The bound is a bare default with no comment, ADR, or eval
grounding; surrounding comments only reference it as "the bound." Nothing ties 14 to observed
mission depth or a cost/latency budget. — Not dangerous, but it's an ungrounded governor on
every mission and the natural thing an eval harness (R3.6) should *calibrate* rather than
assume. — **nice-to-have**

### R3.2 — Schema-exposure vs permission separation is tested in parts, not as one "exposed-yet-gated" invariant
`[KEEP] core/autonomy.py:52 (exposes_tool_schemas) + tests/test_autonomy.py, test_request_routing.py`
— The separation CLAUDE.md calls critical (model *sees* a tool ≠ engine *runs* it) is real and
mostly covered: `test_autonomy.py` asserts high-risk schemas are withheld by default / exposed
in sandbox; `test_request_routing.py` asserts the **safe-baseline floor is always exposed**
(never an empty schema — `test_unapproved_exploit_exposes_safe_baseline_not_offensive_primitives`,
`test_vague_request_exposes_safe_baseline_instead_of_nothing`); and
`test_agent_evaluation_harness.py::test_permission_denial_scenario_blocks_tool_before_execution`
proves the engine blocks execution before it starts. **Gap:** there is no single test that
holds *both* ends at once — a high-risk tool whose schema is exposed **and** whose execution is
still denied by `PermissionEngine` — so the invariant is asserted by comment (`agent.py:870`)
plus two separate tests rather than one focused property. — Solid; add one conjunction test to
make the invariant regression-proof. — **KEEP** (add-a-test: nice-to-have)

### R3.3 — 19 of 39 tools have no dedicated parser → OBSERVE blind spots (verified by registry diff)
`[CHANGE] core/result_parser.py:48 (_PARSERS) — live diff` — Registry introspection: **39
tools, 19 dedicated parsers + `xss_test`→generic**. The 19 without a dedicated parser fall to
`parse_generic_output`, which produces a text summary but **does not populate**
`hosts_discovered`/`services_discovered`/findings. True mission blind spots among them:
`subdomain_enum` (r3, discovers hosts), `tech_detect` (r2, tech/services), `waf_detect` (r3,
WAF = finding), `port_check`/`ping_host`/`traceroute` (r2, hosts/ports/liveness), plus
`file_analyze`/`log_analyze`/`find_files` (r4, forensic evidence). A `subdomain_enum` that
finds 8 subdomains adds **zero** hosts to the blackboard. — CLAUDE.md/ARCHITECTURE §6: "a tool
with no parser is an OBSERVE blind spot." The parser *split* (chantier 6) is done; *coverage*
was never extended. Directly degrades multi-turn reasoning. — **important**

### R3.4 — Unreviewed CaseLessons influence the LLM via briefing text; the prompt-injection sanitizer doesn't cover that channel
`[CHANGE] core/experience.py:558/1162 + core/agent.py:842 (_relevant_lessons_briefing)` — The
**deterministic** re-rank effect (boost/downrank of a `NextAction`) is correctly quarantined:
`evaluate_lesson_match` only reaches `status="applied"` when `lesson.is_reviewed`
(`:1162`); an unreviewed lesson becomes `"explanation-only"` (text-only effect). **But**
`can_influence` (`:558`) is `status in {applied, explanation-only}`, so `store.retrieve()`
returns unreviewed lessons and `_relevant_lessons_briefing` injects their `lesson.reason()`
text into the LLM context (tagged "(unreviewed, explanation only)" + "Treat these as hints
only"). Lessons are **auto-written from tool output** (`build_lesson_from_tool_result`), and —
critically — the injection sanitizer (`output_sanitizer`, wired only at `memory.py:64`
`add_tool_result`) does **not** run over lesson text or the KnowledgeBase-derived context. So
a hostile tool response can become an unreviewed lesson that softly steers a later turn, on a
channel the ASI01 filter never sees. — Quarantine holds for *authority* and *ranking*, not for
*prompt influence*. **ASI06 (Memory & Context Poisoning) — the most direct exposure; ATLAS
AML.T0051.001 (indirect prompt injection) feeding a memory-poisoning loop.** — **important**

### R3.5 — `write_file` system-path DENY is dead code (unreachable `return`)
`[CHANGE] core/permissions.py:384-397` — `evaluate_tool_arguments` executes
`decision = self.evaluate_tool(tool_name); return decision, self.tool_resource(tool_name)`
at `:384-385`, making the file read/write heuristics at `:387-397` (which call
`check_write_permission`) **unreachable**. And `tool_argument_resource` (`:423-439`) maps only
`file_analyze`/`log_analyze`/`find_files` → `read_file`, **never** `write_file`. Net effect
(verified): the `rules["write_file"]` hard-DENY on `/etc`, `/bin`, `/usr` is never consulted;
`write_file` falls back to its ACTIVE tier → **ASK**. So `write_file /etc/passwd` gets an
approvable ASK, not a categorical refusal. — Not an open door (still gated to ASK), but a
verified defense-in-depth regression from a literal return-before-branch bug. **ASI02; ATT&CK
T1565.** — **important**

### R3.6 — `_local_preflight_answer` + guided-task tool injection paper over model tool-selection
`[CHANGE] core/agent.py:951/989 + core/preflight.py:589 (local_answer)` — For a fixed set of
recon phrasings ("how many ports", "what version of apache", "hidden directory/directories",
CTF "answer the questions below", `user.txt`/`root.txt`), the harness detects the wording,
runs the tool deterministically, and formats a canned answer **bypassing the LLM**;
`_guided_task_preflight_tool_calls` even force-injects a `dir_brute` call on keyword match.
This exists because the flash/Gemma tier doesn't reliably (a) pick the right tool or (b) phrase
the recon answer — a harness workaround for a model weakness (consistent with
`BACKEND_REVIEW`'s "the bottleneck is the harness"). The cost: it is **phrasing-brittle**
(locked to specific French+English substrings), covers only the canned questions, and diverges
runtime behavior from "the model choosing well unaided." — For any benchmark (R3.6/eval), these
templates inflate scores on the exact phrasings they match while the underlying tool-selection
capability stays untested. — **nice-to-have** (important as an eval-integrity caveat)

### R3.7 — No AutoPenBench-style harness: replay scores planner proposals on frozen fixtures, without rate/autonomy/error-mode
`[ADD] core/replay_evaluation.py + tests/test_lab_replay_harness.py` — What exists:
`score_replay_plan`/`ReplayScore` grade whether the **deterministic planner** proposes expected
`NextAction`s against **recorded** tool-output fixtures (rootme/htb/thm/portswigger), and
`evaluate_learning_gate` gates lesson promotion on replay passing. It does **not** run the full
agent end-to-end against targets, and reports **no** success/progress rate, **no** autonomy-level
tag, **no** error-mode classification. — To answer "how good is the agent," a real harness would
need: end-to-end task execution against a lab set; a **success** metric *and* a **partial-progress**
(subgoals-reached) metric; every run tagged with the `AutonomyLevel` in force (COPILOT/RISK_BASED/
SUPERVISED/SANDBOX); and an **error-mode** breakdown (tool-missing, permission-denied,
convergence-stall, LLM-5xx, scope-block, wrong-tool). The building blocks are present
(`mission.action_trace` carries status/permission/error; findings carry timeout/missing-tool),
they're just not assembled into a rate-with-breakdown report. — **important** (strategic)

### R3.8 — Autonomy escalates on unauthenticated prompt substrings
`[CHANGE] core/request_context.py:287 (_environment_hint) → core/autonomy.py:46 (for_environment)`
— `EnvironmentHint` is derived from substrings in the **user prompt** ("ctf", "flag", "htb",
"room", "user.txt", "capture the flag", …). A match escalates autonomy to `SUPERVISED` (fewer
pauses). The signal is unverified free text: a hijacked goal or a sloppily-phrased client
engagement can inherit a more permissive posture just by containing "flag" or "lab". — Yardstick
(A): autonomy should be *earned* on a reliable signal, not granted by phrasing.
**ASI01 (Goal Hijack) / least-agency.** — **important**

---

## Security overlay — OWASP Agentic 2026 mapping (real implementation)

| ASI (2026) | Real coverage | Gap (this audit) |
|---|---|---|
| **ASI01 Agent Goal Hijack** | `output_sanitizer` wired at `memory.py:64` (strips 16 patterns + data-boundary markers); `scope_guard`; phase/scope-constrained planner | **R3.8** (keyword autonomy escalation); **R3.4** (lesson/KB channels bypass the sanitizer); sanitizer is regex-only → bypassable; **unnamed in CLAUDE.md** so easy to regress |
| **ASI02 Tool Misuse** | `risk_class` + `PermissionEngine` + `ActionTier` | **T2.7** (nmap/subdomain auto-allow, tier↔risk_class split); **R3.5** (write_file DENY dead code) |
| **ASI03 Identity/Privilege Abuse** | r5 privileged, `sudo.py`, ASK-on-sudo | r8 `CREDENTIALED_REMOTE_OR_IDENTITY_ACTION` defined but **assigned to zero tools**; **T2.8** (persistent r5 allow via CLI bypass) |
| **ASI04 Supply-Chain** | MCP `trust_status` + SHA256 `server_hash`; skills content-hash-gated | Well covered |
| **ASI05 Unexpected Code Execution** | `run_shell` default ASK (tier ACTIVE, verified); sandbox validation; scope_guard | Baseline sound; **T1.1** (webshell/write_file no pre-exec diff) is the surface the upcoming vibe-coding pass will stress |
| **ASI06 Memory & Context Poisoning** | lessons `unreviewed` by default; `/lessons` promotion; `is_reviewed` gates hard effect | **R3.4** — unreviewed lesson text still reaches the prompt, unsanitized |
| **ASI09 Human-Agent Trust** | per-tool approval, risk labels, editable commands | **T1.1** (diff post-hoc), **T2.1** (no plan preview): operator can't see the artifact/trajectory before committing |

**Least-agency verdict.** The `risk_based` default is sound, but autonomy is not always
*earned*: it can be granted by prompt phrasing (**R3.8**), active enumeration self-executes
against real targets (**T2.7**), and a persistent r5 allow was set through a guard-bypassing
path (**T2.8**).

---

## Top 10 — prioritized across all phases (impact × inverse-effort, security first)

1. **T2.7 / R3.5 — Fix the permission/risk taxonomy split and the dead `write_file` DENY.**
   `nmap_scan`/`subdomain_enum` auto-allow despite r3; `write_file /etc` DENY is unreachable;
   README says the opposite of the code. Reconcile `ActionTier` with `ToolRiskClass`, move the
   `return` in `permissions.py:384`, correct README. Small diffs, real ASI02 exposure.
   *(important)*
   → **CLOSED 2026-07-15.** `write_file(path)` resource mapping + categorical protected-path
   check (`core/agent.py:1986`); `nmap_scan`/`subdomain_enum` moved to the ACTIVE tier.
   Follow-on: mission-scoped scan-result cache for both (`core/mission.py` `ScanCacheEntry`,
   30 min TTL).

2. **R3.4 — Stop unreviewed lesson text from reaching the prompt (or route it through the
   sanitizer).** Filter `is_reviewed` in `_relevant_lessons_briefing`, or run lesson/KB context
   through `output_sanitizer`. Closes the most direct ASI06 channel. *(important)*
   → **CLOSED 2026-07-15.** `_relevant_lessons_briefing` (`core/agent.py:860`) excludes
   unreviewed lesson text from the assembled prompt.

3. **T2.8 — Add a risk guard to `/permissions allow tool(...)`.** Make the CLI honor the same
   `_SHELL_TOOL_SESSION_ONLY`/compound-command policy the approval UI enforces, so the two
   permission-granting paths can't disagree. Live-proven bypass. *(important)*
   → **CLOSED 2026-07-15.** `rule_requires_confirmation()` + helpers (`core/permissions.py:217`)
   give the CLI/persist path the same risk guard as the approval UI; the two live-proven
   over-broad `settings.json` auto-approval entries were removed.

4. **R3.8 — Stop escalating autonomy on unauthenticated prompt substrings.** Gate
   `for_environment` on a verified signal (explicit `--env`/CTF flag, scope config), not
   `"flag" in text`. ASI01/least-agency. *(important)*
   → **CLOSED 2026-07-15.** `core/request_context.py` now requires an explicit operator signal
   (`SECOPS_ENV` / `--env` / `set_operator_environment()`), never inferred from prompt or
   tool-output content.

5. **T1.1 — Render the diff/content *before* approval for `write_file` (and a command/preview
   for `webshell_exec`).** Move the reviewable artifact to the correct side of the gate. Highest
   UI-trust win against agy. *(important)*
   → **CLOSED 2026-07-15.** `write_file` preview renders at the approval step, before the
   write (`ui/tool_display.py:458`).

6. **R3.3 — Add dedicated parsers for the 6–9 real OBSERVE blind spots** (`subdomain_enum`,
   `tech_detect`, `waf_detect`, `port_check`, `ping_host`, `traceroute`; then the forensic
   trio). Discoveries that don't reach the blackboard starve multi-turn reasoning. *(important)*
   → **CLOSED 2026-07-15.** `core/result_parsers/observation.py` covers all six OBSERVE
   blind-spot tools, feeding the mission blackboard.

7. **T2.1 / T2.2 — First-class `Plan` object + `/plan` preview, and make `/artifact` (or a
   report) the primary finding surface.** The biggest agentic-parity gap vs Codex (plan
   approval) and Claude Code (plan mode); realizes yardstick (B) for whole missions. Larger
   effort — scope with `writing-plans`. *(important)*
   → **CLOSED 2026-07-15.** T2.1: `MissionPlan`/`PlanStep` on the blackboard
   (`core/mission.py`) + a plan-preview gate before the first active (≥ r2) step with a
   single acknowledgment (`PlanPreviewEvent`/`PlanDivergenceEvent`, `core/agent.py`),
   never replacing the PermissionEngine; `render_plan` + `/plan [scope <target>]`
   (`ui/renderer.py`, `main.py`, `ui/commands.py`). T2.2: `FindingEvent` emitted at OBSERVE
   → live `finding` artifacts, and `/artifact` now leads with a Findings section
   (`ui/views/panels.py`). All three `stream_response` consumers (TUI, `--print`, `/btw`)
   resolve the plan acknowledgment. Item 8 (eval harness) remains open.

8. **R3.7 — Build the eval harness that reports success/progress rate *with* autonomy level and
   error mode.** Assemble the existing `action_trace`/replay pieces into a
   rate-with-breakdown; this is what would let R3.1 (`max_iterations`) be *calibrated* instead
   of guessed. *(important, strategic)*

9. **T1.2 / T1.3 — One r0–r8 severity color language on the live card + an
   iteration/cost segment in the statusline.** Show risk where the eye lives and make the
   autonomy *budget* visible (yardstick A). *(nice-to-have)*

10. **Documentation truth-up.** Name ASI01 and the `output_sanitizer` defense in CLAUDE.md
    (so it can't silently regress); fix `r0–r6 → r0–r8` (CLAUDE.md:82); drop the dead
    `test_exploit_request_sends_no_function_tools_by_default` reference in ARCHITECTURE §8;
    either assign or retire r7/r8. Cheap, prevents the next stale-audit cycle. *(nice-to-have)*
    → **CLOSED 2026-07-15.** Doc truth-up landed in `CLAUDE.md`/`docs/ARCHITECTURE.md`; this
    reconciliation applies it to this document's own top-10 (the piece previously missed).

---

### Quick KEEPs (verified good, no action)
- `/btw` runs a separate agent off the main budget (**T2.3**).
- Repeated-call and announced-but-unexecuted convergence guards explain themselves (**T2.5**).
- `AutonomyPolicy` is a clean first-class object with an honest invariant docstring; the
  safe-baseline-floor is well tested (**R3.2**).
- `output_sanitizer` is real and wired for the primary tool-output channel (**overlay ASI01**).
- Non-TTY degradation + hard-deny on dangerous tools without a TTY (**T1.6**).
