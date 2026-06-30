# Agentic-Quality Improvement Plan (2026-06-29)

> **For agentic workers:** this is a **director plan** (programme level). Each
> Task below is a self-contained *chantier*; when you start one, expand it into a
> bite-sized plan with the `superpowers:writing-plans` skill, then execute it with
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the SecOps Agent from a single-step, narration-first chatbot into a
competent *plan → act → observe → reflect* autonomous pentest agent with wired
long-term memory — closing the gaps found in the 2026-06-29 audit.

**Architecture:** Keep the existing *Blackboard + CBR + LLM-executor* design and the
separation-of-powers invariant. This plan **rewires and splits** existing components
(≈80% present), it does not rebuild them. No layer ever bypasses the safety gate.

**Tech Stack:** Python 3.12+, Typer + rich + prompt_toolkit, google-genai (Gemini/Gemma),
pydantic, httpx. Tests: unittest (canonical) + pytest. Lint: ruff (E4/E7/E9/F, F401 off).

## Global Constraints

- Use `.venv/bin/python` and `PYTHONDONTWRITEBYTECODE=1` for every command.
- Canonical test run: `.venv/bin/python -m unittest discover -s tests`.
- Lint gate (CI-blocking): `.venv/bin/ruff check secops_agent tests`.
- **Mock LLM, network, and shell in every unit test** — never hit a real key/target.
- **Never violate separation of powers** (ARCHITECTURE.md §1): Planner proposes, LLM
  reasons, AutonomyPolicy exposes/pauses, Safety authorizes. Only path to exec = safety gate.
- One chantier at a time; **tests green + commit between each**; small, frequent commits.
- TDD: write the failing test first whenever the change is behavioural.
- Work on `feat/agent-autonomy-and-tooling` (or a worktree off it via
  `superpowers:using-git-worktrees` for the structural chantiers 2.2 / 4.1).
- Only run scan/exploit tooling against **authorized** targets.

## Sequencing rationale

Phase 0 lays a safety net (green baseline + fuzz/scan the attacker-facing code) and is
**independent — startable now, in parallel with everything**. Phase 1 is the highest
agentic leverage at low risk and does **not** depend on the structural refactors
(`BACKEND_REVIEW`: P1+P2 are the two changes that make conversations feel like agy/
Claude Code). Phase 2 makes the loop/autonomy explicit — a prerequisite for real
multi-step chaining and for memory's REFLECT/briefing hooks. Phase 3 wires long-term
memory (your reference-architecture gaps) on top of the now-explicit loop. Phase 4
splits the parsers (safer once Phase 0 fuzzing gives them a test corpus) and makes the
plan inspectable.

```
Phase 0  ──────────────────────────────────────────────►  (parallel, independent)
Phase 1 (P6→P1→P2→P4/P5) ─► Phase 2 (AutonomyPolicy→MissionLoop) ─► Phase 3 (memory) ─► Phase 4 (parsers, /plan)
```

---

## Status (2026-06-29) — most of this plan is already implemented

A re-map against the code on `feat/agent-autonomy-and-tooling` found the agentic
backlog **already done and tested**; the plan above predates the branch's state.

**Done & verified** (evidence in `BACKEND_REVIEW_2026-06-28.md` → Resolution):
Phase 0.1, 0.2; **P6** (1.1), **P1** (1.2), **P2** (1.3), **P4/P5** (1.4); **P3 chaining**
(2.1); mission **briefing** (3.1); **`/lessons`** human lesson validation (3.2 —
`cli/lessons.py` + `review_lesson`; renamed from `/memory`, a banned
Claude-Code-imitation command).

**Genuinely remaining:** `MissionLoop` extraction (2.2 — refactor, no behaviour gain),
**embeddings** (3.3), `result_parser` **split** (4.1), persistent `Plan` + `/plan` (4.2),
and the 3.2 **end-of-mission surfacing** hook (the command shipped; the post-mission
prompt listing new unreviewed lessons is not wired yet).

**Caveat for 2.1:** the migration is *functionally* complete (chaining works, `pauses_for`
gates it, `max_chained_actions_per_turn = 0` is the intended default with planner
auto-exec opt-in via `--autonomous`) but the legacy `allow_automatic_planner_execution`
flag still coexists with `AutonomyPolicy` as tech debt — absorbing it is optional cleanup.

---

## Architecture decision required BEFORE Phase 3.3 / MCP work

**MCP as a tool-permission substrate (your reference §"gate côté serveur MCP").**
Audit finding: `core/mcp.py` is a **client** only (consumes external stdio servers under
`mcp_`); the permission gate lives in-process (`PermissionEngine` + `ToolRiskClass`), and
native `readOnlyHint`/`destructiveHint` annotations are not used. **Recommendation: ratify
the divergence** — an in-process gate is stronger and simpler for a single-binary agent
than delegating authorization to an external MCP server. Action: record this as an
explicit ADR; do **not** schedule a rewrite. (If you later consume a third-party pentest
MCP server for tool breadth, it inherits the in-process gate — that is a feature.)

---

## Phase 0 — Safety net & hardening *(independent, start now)*

### Task 0.1: Confirm green baseline
**Files:** none (verification only). **Skill:** `verification-before-completion`.
**Done:** `unittest discover -s tests` all-green and `ruff check` clean recorded as the
reference point before any refactor. **Risk:** none. **Depends on:** —.
- [x] Run the full suite + ruff; capture pass count; if red, fix or quarantine before proceeding. — **done (2026-06-29): 589 tests green, ruff clean.**

### Task 0.2: Harden the attacker-facing code
**Files:** `core/result_parser.py` (1845 l, ingests attacker-controlled tool output),
`tools/exploitation.py` (`http_request`/`write_file`/`webshell_exec`), new
`tests/fuzz/` harnesses. **Skills:** `atheris` + `harness-writing` + `fuzzing-dictionary`
+ `fuzzing-obstacles` + `coverage-analysis` (fuzz the parsers), then `semgrep` + `codeql`
+ `insecure-defaults` (static + secrets/fail-open audit).
**Done:** an atheris harness fuzzes `ToolResultParser` against a corpus of malformed
nmap/sqlmap/ffuf output without uncaught exceptions; semgrep/codeql SARIF triaged
(`sarif-parsing`); insecure-defaults report on `.env`/scope/sudo paths reviewed.
**Risk:** low (adds tests/finds bugs; no behaviour change). **Depends on:** 0.1.
- [x] Build the fuzz harness for `result_parser` (this also becomes the test corpus for 4.1). — **done: `tests/fuzz/fuzz_result_parser.py`, pure-stdlib, 0 crash / 150k+ iters, 70.7% line cov.**
- [x] Run semgrep + length/ReDoS probe; file findings. — **done: found+fixed a ReDoS in `parse_whois_output` (whois e-mail regex `re.findall` O(n²); 200k chars 84s→20ms; fix = negative lookbehind). semgrep (200 rules, offline via uvx) → 0 ERROR, 3 WARNING all triaged as intentional FPs (0o755 executable drop; MD5/SHA1 forensic fingerprinting beside SHA256). Locked by `tests/test_result_parser_fuzz.py`.**

> **Status: Phase 0.2 COMPLETE.** Net: 1 real DoS vuln fixed, attacker-facing code otherwise clean, reusable fuzz harness + regression tests added. Not committed yet (user deferred).

---

## Phase 1 — Agentic competence *(highest leverage, low–moderate risk)*

### Task 1.1: P6 — stop the `Lesson:` line leaking telemetry
**Files:** `core/agent.py` (`_render_suggested_actions`), `core/experience.py`
(`review_status == "signal"`, ~l.682), `tests/test_experience_memory.py`.
**Done:** the `Lesson:` line renders **only** when `action.experience[0]` is a real
`CaseLesson` (not a `SuggestionSignal`/learning signal); a unit test asserts a signal-only
action renders no `Lesson:` line. **Risk:** low (undoes a regression). **Depends on:** —.
- [x] **Done** — `renderer.py` ~3419 filters `suggestion learning` telemetry from suggested actions; guarded by `test_tui_polish`.

### Task 1.2: P1 — broad safe tool exposure, demote the goal whitelist
**Files:** `core/request_context.py` (`_TOOLS_BY_GOAL` l.112, `ToolSchemaSelector.select`
l.185), `core/agent.py` (`_tools_schema_for_decision` l.855, `_safe_baseline_tool_names`
l.764), `tests/test_request_routing.py`.
**Done:** the model is offered the **broad safe-baseline toolset** for every non-exploit
request; `_technical_goal` only **ranks/orders** tools, it no longer hard-restricts them;
the AutonomyPolicy risk-gate still withholds exploit/destructive schemas until approved.
Tests: "ping"/"scan the target" expose ping/port tools (not `[]`); exploit-by-default
still sends no exploit schema. **Risk:** moderate (core routing). **Depends on:** 0.1.
- [x] **Done** — `agent._tools_schema_for_decision` offers the broad safe-baseline floor + goal-ranking; `_technical_goal` no longer hard-restricts.

### Task 1.3: P2 — rewrite `SECOPS_SYSTEM_INSTRUCTION` lean & action-first
**Files:** `core/llm.py` (`SECOPS_SYSTEM_INSTRUCTION` l.29, ~121 lines today; Gemma
contract), `tests/test_model_behavior.py`.
**Done:** prompt ≤ ~35 lines, action-first; **dropped**: "narrate before tool", "don't
request another tool in the same turn", Gemma "use tools sparingly", formatting bloat.
**Kept**: hard safety + scope + language-match. **Risk:** low–moderate (behavioural; verify
on `tui_smoke` + a live `--print` smoke). **Depends on:** 1.2 (tools must be available first).
- [x] **Done** — `SECOPS_SYSTEM_INSTRUCTION` is ~45 lines, action-first; the narrate-before-tool / don't-chain / Gemma-sparingly directives are gone.

### Task 1.4: P4/P5 — loop never ends empty; lead with the fact
**Files:** `core/agent.py` (follow-up suppression ~l.1428/1455/1625/1653,
`_announces_unexecuted_action`), result-trailer rendering (duplicate `n line(s)…`),
`tests/test_command_streaming.py`.
**Done:** if the model describes an action with no function-call, the loop forces the
proposed tool (preflight) or converts to a real answer — **no empty turns**; the duplicate
result trailer is gone and post-tool summaries lead with the extracted fact.
**Risk:** moderate. **Depends on:** 1.2, 1.3.
- [x] **Done** — `_announces_unexecuted_action` + announced-action retry guardrail (`agent.py` 304/1724); `parse_generic_output` (`result_parser.py:1317`) leads with the extracted fact.

---

## Phase 2 — Explicit loop & autonomy *(structural, moderate risk)*

### Task 2.1: Finish the AutonomyPolicy migration (P3 / chantier 2 slice 2)
**Files:** `core/autonomy.py` (`pauses_for` l.65, `for_environment`), `core/agent.py`
(absorb `allow_automatic_planner_execution` at l.1537/1625/1653/2313/2406;
`max_chained_actions_per_turn` l.222), `main.py` (l.599/620/1256-1264),
`tests/test_autonomy.py`.
**Done:** `AutonomyPolicy.pauses_for(risk)` is the **single** chaining authority;
`allow_automatic_planner_execution` is removed/absorbed; low-risk recon/enum chains
(`max_chained_actions_per_turn > 0`) while high-risk pauses for approval; CTF/LAB escalate
via `for_environment`. **Risk:** moderate (autonomy decisions). **Depends on:** 1.4.
- [x] **Done (functionally)** — `allow_llm_chaining` (`agent.py` ~1536) wired to `pauses_for`; `test_open_ended_request_chains_llm_tool_calls_multi_step`. Legacy `allow_automatic_planner_execution` still coexists (optional cleanup — see Status caveat).

### Task 2.2: Extract `MissionLoop` from `stream_response` (chantier 3)
**Files:** new `core/mission_loop.py`, `core/agent.py` (`stream_response`, 2465 l → thin
delegator), `tests/test_mission_phase.py` + new `tests/test_mission_loop.py`.
**Done:** a first-class `MissionLoop` runs plan→act→observe→reflect, bounded by
`AutonomyPolicy` + budget, emitting the same events; `stream_response` delegates to it;
both convergence guardrails preserved. **Risk:** moderate–high (large refactor — do it in a
worktree, behaviour-preserving, characterization tests first). **Depends on:** 2.1.
- [ ] Characterization tests pinning current event stream BEFORE moving code.

---

## Phase 3 — Long-term memory *(your reference gaps, moderate risk)*

### Task 3.1: Wire the mission briefing (chantier 4)
**Files:** `core/experience.py` (`retrieve_similar_lessons`), `core/agent.py` /
`core/mission_loop.py` (mission-start hook), `core/structured_memory.py` (inject once),
UI encart, `tests/test_experience_memory.py`.
**Done:** at mission start, similar past lessons are retrieved **once**, injected at the
top of context and shown in the TUI ("from N past missions on similar targets: prioritize
X, beware false-positive Y"). **Risk:** moderate. **Depends on:** 2.2.
- [x] **Done** — mission-start lesson briefing (chantier 4) implemented and tested.

### Task 3.2: Wire human validation of lessons (your "validation before commit" gap)
**Files:** `cli/lessons.py` (`/lessons review` to promote `unreviewed →
reviewed/blocked/deprecated`), `core/experience.py` (`review_lesson` l.1010,
`reviewed_copy`, `_rewrite` l.1045), end-of-mission hook, `tests/test_cli_lessons.py`.
**Done:** lessons stay `unreviewed` (explanation-only) until a human promotes them via
`/lessons review`; an end-of-mission prompt surfaces newly-written lessons for review; no
lesson ever authorizes execution. **Risk:** moderate. **Depends on:** 3.1.
- [x] **Done (command)** — `/lessons review` promotes via `ExperienceStore.review_lesson(dry_run=False)`; parsing/format in `cli/lessons.py`, covered by `tests/test_cli_lessons.py`. Renamed from `/memory` (banned imitation command).
- [ ] **Deferred:** end-of-mission surfacing hook that lists newly-written unreviewed lessons.

### Task 3.3: Hybrid similarity — add semantic recall on top of structural CBR
**Files:** `core/experience.py` (`CaseLesson` embedding field, secondary recall in
`retrieve_similar_lessons`), embedding provider (prefer **google-genai text-embedding** —
already a dependency — over a heavy local torch stack), `tests/test_experience_memory.py`.
**Done:** structural attribute match (service/endpoint/risk/access) stays **primary**;
embeddings add a **secondary** fuzzy recall over the free-text lesson body, guarded against
the semantic-vs-causal mismatch (never overrides a structural mismatch). **Risk:**
moderate–high (adds a provider call / dependency — keep optional & cached).
**Depends on:** 3.1, and the MCP/embeddings ADR above.
- [ ] Failing test: a semantically-similar but differently-worded lesson is recalled, while
      a structurally-incompatible one is still excluded.

---

## Phase 4 — Inspectable plan & parser split *(low–moderate risk)*

### Task 4.1: Split `result_parser.py` by tool family (chantier 6)
**Files:** `core/result_parser.py` (1845 l) → per-family parsers co-located in `tools/`
(nmap/ffuf/sqlmap/nuclei…), `tests/test_result_parser*.py` (reuse the 0.2 fuzz corpus).
**Done:** each tool has a guaranteed parser → no OBSERVE blind spots; the monolith is
gone; fuzz corpus from 0.2 passes against every split parser. **Risk:** low–moderate (the
0.2 harness is the safety net). **Depends on:** 0.2, 2.2.
- [ ] Move one family at a time, green tests + commit per family.

### Task 4.2: First-class persistent `Plan` + `/plan` (chantier 5)
**Files:** `core/mission.py` (persist `Plan` in `MissionContext`), `core/planner.py`
(`build_prompt_summary` already exists), `cli/` (`/plan`), UI, `tests/test_core.py`.
**Done:** the plan is an ordered `NextAction[]` + justification + budget stored on the
blackboard (not recomputed-and-thrown each turn) and inspectable via `/plan`.
**Risk:** low–moderate. **Depends on:** 2.2.
- [ ] Failing test: plan persists across turns and `/plan` renders it.

---

## Coverage check (audit gap → task)

| Audit gap / backlog item | Task |
|---|---|
| Embeddings absent (hybrid recall) | 3.3 |
| MCP client-only vs server-side gate | ADR (decision, no rewrite) |
| Human memory validation partial | 3.2 |
| Mission briefing not wired | 3.1 |
| P1 tool exposure (floor only) | 1.2 |
| P2 system prompt bloat | 1.3 |
| P3 / AutonomyPolicy migration incomplete | 2.1 |
| P4/P5 empty turns + trailer | 1.4 |
| P6 Lesson telemetry leak | 1.1 |
| MissionLoop not extracted | 2.2 |
| result_parser monolith | 4.1 |
| Plan object + /plan | 4.2 |
| Hardening attacker-facing parsers | 0.2 |
