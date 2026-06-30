# Backend Review — Conversation & Agentic Quality (2026-06-28)

> Goal: bring response/conversation quality to the level of agy, Claude Code,
> Codex. Triggered by a real transcript where the agent narrated tool intentions
> without executing them and gave shallow, templated answers. Confirmed by the
> user: behaviour is identical across models → the bottleneck is the **harness**,
> not the model.

> **Resolution (2026-06-29):** all of P1–P6 below are now implemented and tested on
> `feat/agent-autonomy-and-tooling`. The root-cause analysis is kept verbatim as a
> historical record of *why*; see the **Resolution** section at the end for per-item
> status and code/test evidence. Some statements below (e.g. RC2's
> `max_chained_actions_per_turn = 0`) are now intended behaviour — the Resolution
> clarifies which.

## Meta-finding

The agent behaves as a **single-step, tool-starved, narration-first chatbot** —
the opposite of an act→observe→act agent. Three independent layers each break
agentic competence; together they fully explain the transcript, on any model.

---

## Root cause 1 (most severe) — brittle tool-schema gating

Common requests are handed the **wrong tools or none at all**, so the model
literally cannot act:

| Request | Classified goal | Tools exposed to model |
|---|---|---|
| « fais un test de connectivité » | `lab_readiness` | lab_setup_check, vpn_status, connect_vpn_config… (**no ping/port_check**) |
| « ping the target » | `unknown` | **[]** |
| « scan the target » | `unknown` | **[]** |

`agent._tools_schema_for_decision` → `ToolSchemaSelector.select()` returns a
**narrow per-goal whitelist** (`_TOOLS_BY_GOAL`) driven by a brittle keyword
classifier (`request_context._technical_goal`). Any misclassification yields the
wrong or an empty schema → the model narrates an action it has no tool to
perform → it stops. **This alone explains "same result on any model."**

> Contrast: agy / Claude Code / Codex expose a **broad tool surface** and let the
> model choose. They do not hard-restrict tools by a guessed intent. Intent
> classification is fine for *ranking/suggestions*, harmful as a *hard gate*.

## Root cause 2 — single-step turn control

- `max_chained_actions_per_turn = 0` (never set in `main.py`).
- `allow_automatic_planner_execution = False` by default (`--autonomous` off).
- After a tool runs, tools are suppressed on the follow-up turn
  (`agent.py` ~1428/1455), so there is no recon→enum→exploit flow.

A competent agent observes a result and continues toward the goal in one turn.
This one is gated single-step by construction.

## Root cause 3 — over-prescriptive, tool-averse system prompt

`SECOPS_SYSTEM_INSTRUCTION` (`llm.py`) is ~130 lines of formatting rules that
crowd out reasoning and produce templated, shallow output. Several rules are
directly counter-productive:

- l.54 "Narrate your reasoning. **Before calling a tool, briefly explain why**".
- l.57 "**do not request another tool in the same turn**".
- Gemma contract l.320 "**Use tools only when they materially improve accuracy**".

These push the model to treat *narration as the deliverable* and to *avoid /
not chain* tools — exactly the transcript behaviour.

> Contrast: Claude Code / Codex system prompts are lean and action-first ("use
> tools proactively, keep going until the task is done, lead with the answer"),
> with only hard safety/scope constraints.

---

## Secondary issues (from the transcript)

- **Wrong tool pick**: "active le vpn" ran `lab_setup_check` instead of
  `connect_vpn_config` (prompt l.131 "prefer lab_setup_check" + all 5 tools
  offered at once).
- **Empty turns** rendered ("alors?" / "pfff" → nothing).
- **Duplicate result trailer**: `vpn_status: 8 line(s) of output First line: …`
  printed under the clean tool card.
- **"Lesson:" leaks telemetry**: shows `suggestion learning: local suggestion
  signals: selected=15…` — a regression introduced by the §5 concise-lesson
  change; `action.experience[0]` can hold internal learning signals, not a real
  `CaseLesson`.

---

## Improvement plan

Reframe the agent from *single-step narration chatbot* to *act→observe→act
agent*. Ordered by leverage / risk.

| # | Change | Fixes | Notes |
|---|---|---|---|
| **P6** | Filter telemetry from the `Lesson:` line (show only real `CaseLesson` reasons) | #5 | quick; undoes a regression |
| **P1** | **Tool exposure**: expose a broad, relevant **safe** toolset and let the model choose; keep ONLY the AutonomyPolicy risk-gate (withhold exploit until approved). Demote `_technical_goal` from hard gate to ranking hint. | RC1, wrong/empty tools | **biggest unlock**, moderate risk |
| **P2** | **System-prompt rewrite**: lean (~30 lines), action-first. Drop "narrate-before-tool", "don't chain", Gemma "use tools sparingly", and the formatting bloat. Keep hard safety + scope + language-match. | RC3, superficiality | high leverage, low risk |
| **P4** | **Loop robustness**: never end a turn empty; if the model describes an action with no function-call, force the proposed tool (preflight) or convert to a real answer. | empty turns, announce-without-execute residue | part of chantier 3 |
| **P5** | **Result handling**: drop the duplicate trailer; lead the post-tool summary with the extracted fact. | #4, shallow summaries | rendering + loop |
| **P3** | **Chaining/autonomy**: enable multi-step within `AutonomyPolicy` (low-risk recon/enum chains; pause on high-risk). Wire `pauses_for` into the loop. | RC2, single-step | chantier 2 slice 2 + chantier 3 |

**Recommended order:** P6 → P1 → P2 → P4/P5 → P3.

### Honest priority note

This **reorders the roadmap**: the backend (P1/P2) now outranks any further TUI
work. The TUI is agy-faithful; the *agent* is not yet competent. P1 + P2 are the
two changes most likely to make conversations feel like agy/Claude Code, and
both are low-to-moderate risk. P3 depends on the loop work (chantier 3) and the
already-started `AutonomyPolicy` (chantier 2).

---

## Resolution (2026-06-29)

All improvement-plan items are implemented and covered by the suite on
`feat/agent-autonomy-and-tooling`.

| # | Status | Evidence |
|---|---|---|
| P1 | ✅ done | `agent._tools_schema_for_decision` ranks by goal then appends the safe-baseline floor (`_SAFE_BASELINE_RISK_CLASSES`); `_technical_goal` is now a ranking hint, not a hard gate. The AutonomyPolicy risk-gate still withholds exploit until approved. |
| P2 | ✅ done | `SECOPS_SYSTEM_INSTRUCTION` (`llm.py`) is ~45 lines, action-first; the narrate-before-tool / don't-chain / Gemma "use sparingly" rules are gone. |
| P3 | ✅ done | `allow_llm_chaining` (`agent.py` ~1536) is wired to `AutonomyPolicy.pauses_for`: low-risk recon→enum chains within one turn, high-risk pauses. Verified by `tests/test_tool_chaining.py::test_open_ended_request_chains_llm_tool_calls_multi_step`. **`max_chained_actions_per_turn = 0` is the intended default** (planner auto-exec stays opt-in via `--autonomous`), locked by `test_planner_candidates_are_not_executed_by_default`. |
| P4 | ✅ done | `_announces_unexecuted_action` (`agent.py:304`) + the announced-action retry guardrail (`agent.py` ~1724) — a turn no longer ends having only narrated an action. |
| P5 | ✅ done | `parse_generic_output` (`result_parser.py:1317`) leads the summary with the extracted fact; the "N line(s) of output / First line:" trailer is gone. |
| P6 | ✅ done | `renderer.py` ~3419 filters `suggestion learning` telemetry out of suggested actions; guarded by `test_tui_polish`. |

**Remaining reference-architecture gaps** (tracked in `IMPROVEMENT_PLAN_2026-06-29.md`):
embeddings-based retrieval (3.3 — `experience.py` is token-overlap only) and the
`result_parser` monolith split (4.1). `/lessons` (3.2 — human lesson validation,
`cli/lessons.py` + `ExperienceStore.review_lesson`) shipped 2026-06-29.
