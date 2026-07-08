# Independent Live Re-Audit (2026-07-04, session 2)

> **Why this doc:** a fresh, from-scratch live re-audit that does **not** trust the
> prior report ([BEHAVIORAL_AUDIT_2026-07-03.md](BEHAVIORAL_AUDIT_2026-07-03.md)).
> The brief flags Examples **C** and **F** as "reported fixed but still observed" —
> to be treated as unresolved until re-proven by running. Everything below was
> obtained by **actually running** secops (and agy), then reading code only to trace
> a cause. New/still-open findings are prefixed **E** (engine) / **R** (rendering).

## 0. Method & environment (ground truth, re-established live)

| Anchor | Result |
|---|---|
| Test suite | `unittest discover` → **687 passed**, 19.5s |
| Lint | `ruff check secops_agent tests` → **clean** |
| API key | real 39-char key in `.env`; `doctor` → "configured" |
| Effective model (mission) | **Gemma 4 26B A4B IT** (banner + auto-route; `.env` says gemini-2.5-flash) |
| agy | **installed, v1.0.10/1.0.16**, model *Gemini 3.5 Flash (High)*; account quota **exhausted** (resets ~31h) |
| Stack | Typer entry; TUI = `ui/renderer.py` + `ui/input_handler.py` (`rich`+`prompt_toolkit`); loop `core/agent.py stream_response→_run_mission_loop`; deterministic `core/preflight.py`; synth `core/llm.py`; parse `core/result_parsers/` |

**Runners built/used this pass** (seed for regression tests):
`scratch/engine_probe.py` (28 live `--print` probes + leak scan), `scratch/repro_turn_duplication.py`
(full turn → PTY+scrollback emulator, counts every duplication class),
`scratch/repro_live_tui.py` (real TUI over PTY, live model), `scratch/agy_capture.py`
(agy over PTY), `scratch/repro_streaming_overflow.py` (Example F).

---

## 1. What genuinely holds (verified live, no action)

- **Deterministic preflight path is leak-free.** 20+ FR/EN probes (VPN, public IP, local IP,
  disk, CPU load, RAM, OS, nmap version, sqlmap-absent, tools installed, date) — **zero**
  `(+N more line(s))` / `CPU cores:` / raw-marker leaks. The RC-α leak class is closed for
  this path. (Prior P0-1/D10 hold.)
- **Timezone resolves for most countries/cities:** France, Japon/Japan, USA, Allemagne/Germany,
  Espagne, Italie, Canada, Australia, Chine, India, Brésil, Londres/London, New York, Berlin,
  Moscou, Tokyo, Los Angeles, Royaume-Uni, Angleterre. (Prior P0-2 mostly holds — see **E1**.)
- **Rendering, deterministic turn:** a full turn (thinking → `● VpnStatus()` card → tall 39-line
  streamed answer → done) renders with **exactly one** of each element; **5 turns back-to-back →
  5× each, no accumulation** (`repro_turn_duplication.py`). Example **C** does **not** reproduce
  synthetically; Example **F** cascade does **not** reproduce (`repro_streaming_overflow.py`:
  1 marker copy, 37/37 body lines).
- **Slash palette is high-fidelity to agy** (two-column cmd/description, `↓ N more`, footer
  `↑/↓ Navigate · enter Select · tab Complete`, model right-aligned). Our `/tools` even shows
  risk classes — richer than agy.

---

## 2. Engine-layer findings (live)

| # | Repro (live) | Observed | Expected | Sev | Cause |
|---|---|---|---|---|---|
| **E1** | `what time is it in the UK?` / `in the US` / `in the United Kingdom` | **host time** `…02:03:44 PM GMT` (also wrong: July = BST +1) | Europe/London / America/New_York | **Blocking** | code |
| **E2** | any turn hitting a 500 storm (`gw`, `hostname`, `iface`, `target`, `phase`, `uptime`, `user`) | ~25% of probes 500; 2 **timed out empty at 45s**; notices take ~9s; `--print` default timeout **300s** | fast bounded degrade + progress feedback | **Blocking** | code |
| **E3** | active interface / current target / phase / uptime / current user / hostname / default gateway | routed to the **flaky LLM** → 500/hang instead of a local fact | deterministic local answer | **Blocking** | code |
| **E4** | `donne moi mes informations systeme` (TUI); `est-ce que le VPN est actif ?` | transient notice in **English** for a French prompt (`prefers_french=False`) | French notice | Annoying | code |
| **E5** | real `bonjour → vpn_status` turn (§7.8) | VPN tool card rendered **twice** | one invocation, one card | Annoying | code + model |

### Root causes
- **E1 — missing map keys.** `_CITY_TIMEZONES` (`preflight.py:270`) substring-matches; it has
  `royaume-uni`/`angleterre`/`united states`/`etats-unis` but **not** `uk`/`united kingdom`/`us`.
  The two most common English names for two common countries fall through to host time. *Family
  lesson:* the fix is not "add UK" — it's a country/city **coverage test** (all common EN/FR names
  + abbreviations + a few US states) so the class is closed.
- **E2 — retry/timeout policy.** `agent.py` `_stream_llm_with_retries`: `max_attempts=3`,
  backoff `2·2^(n-1)` capped 8s → 2s+4s sleep + 3 round-trips **per LLM call**, and a turn makes
  several calls (select + synth), so a storm stacks to 45–90s+. In `--print`, retry `StatusEvent`s
  are the only progress and the default `--print-timeout` is 300s → looks like a hang. On this
  Gemma tier the 500 rate is ~25%, so this is frequent, not rare. Prior §7.6 called it "not a bug";
  live, it is the **Example I** blocker.
- **E3 — request routing.** `classify_request`/`preflight.local_answer` answer CPU/disk/RAM/OS/VPN
  deterministically but leave interface/target/phase/uptime/user/hostname/gateway → LLM. All are
  local facts. Prior doc called deterministic coverage "optional polish"; live, it is the
  difference between an instant answer and a 45s failure. (Overlaps E2 — same tier flakiness.)
- **E4 — weak French detector.** `preflight.prefers_french` is keyword/accent based and misses
  common constructions (`est-ce que`, `donne moi`, accent-less). It gates notice/answer language
  everywhere, so the miss is a whole-family parity bug, not one phrase.
- **E5 — double tool invocation (hypothesis).** A single `ToolResultEvent` renders exactly one
  card (proven). Two cards ⇒ the **engine emitted two** — preflight ran `vpn_status` *and* the LLM
  chose it, or a history-replay re-call (**Example G**: "referenced from history"). Confirmation
  needs a live trace/observability capture (blocked this pass by 500s/agy-quota). Likely
  code-orchestration amplified by a Gemma tool-calling quirk.

---

## 3. Rendering-layer findings (live)

| # | Repro | Observed | Sev | Cause |
|---|---|---|---|---|
| **R1** | Example **F** — synthetic tall stream over 28-row PTY | **fixed** (1 copy). Structure sound: live region tail-cropped (`_live_tail`→`_streaming_tail`), final `_flush_live_text` prints full answer once (no head-truncation). **Live re-confirm blocked** by 500-storms | — (fixed, caveat) | — |
| **R2** | Example **C** — 5 turns back-to-back | no dup, no accumulation | — (not repro'd) | — |
| **R3** | agy input framing | agy boxes input in **two** full-width `─` rules; ours uses one below | Cosmetic | code |
| **R4** | thought line | agy renders `▸ Thought for Xs … <summary>` inline (per our own code note `renderer.py:3473`); our synthetic turn put the summary on a separate line | Cosmetic | code (confirm) |
| **R5** | slash-palette filter transition (harness) | dropped/garbled chars mid-filter ("ttach", "u o", "autom ic"); **final filtered frames are clean** | Cosmetic / likely capture artifact | confirm |

**F/C verdict:** the *streaming-text cascade* and *animation accumulation* are fixed at the renderer
level. If the user still perceives "duplication," the live suspect is **E5** (double tool card =
engine double-invoke), which reads as duplication. That reframes C/F persistence from a render bug
to an **engine** bug — worth stating explicitly.

---

## 4. agy benchmark (fresh capture, this pass)

- **Banner:** triangular logo · `Antigravity CLI 1.0.10` · `account (Antigravity Starter Quota)` ·
  `Gemini 3.5 Flash (High)` · workspace. Input **boxed between two rules**. Bottom status bar
  `? for shortcuts` (L) · model (R).
- **Slash palette:** matches ours closely (see §1).
- **Tool card / collapsed content / chained commands (the #1 asked gap):** **live comparison
  blocked** — agy's account quota is exhausted (resets ~31h). Our current card:
  `● VpnStatus()` / `  ⎿ 30ms · 2 lines · 93 chars · passive (ctrl+o to expand)` / preview. The one
  candidate divergence to confirm on quota reset: our `⎿` **metadata** line vs agy showing the
  result directly. Renderer already encodes "verified agy behaviour" for `●`/ctrl+o placement.
- **Out of scope (confirmed N/A):** account + quota banner line (we are not Google-auth). Our status
  bar carries posture/phase/tokens — richer than agy, keep.

---

## 5. Prioritized plan (proposed — pending validation, no code yet)

Effort S ≤ ½d · M ≈ 1–2d. One family → whole-family test → shared-cause fix → **full suite green** →
next (Fix Discipline).

### P0 — coherence & reliability (blocking)
- **P0-A · Retry/timeout UX (E2, Example I).** Cap total per-turn retry budget; surface progress in
  `--print` (heartbeat) and a bounded, lower default timeout; guarantee a fast clean degrade. *Family:*
  all transient-5xx paths (select + synth + tool turns). **M.**
- **P0-B · Deterministic local facts (E3).** Add interface/target/phase/uptime/user/hostname/gateway
  to the classifier + `local_answer` (FR/EN), so local questions never depend on the flaky LLM.
  *Family:* the whole "system/network state" set. **M.**
- **P0-C · Timezone country coverage (E1).** Add missing names/abbdreviations + a coverage test over
  all common EN/FR countries/cities. *Family:* the whole time/timezone set. **S.**
- **P0-D · Double tool invocation (E5 / Example G).** Trace a live VPN turn; if preflight+LLM both
  run the tool (or a history re-call), dedupe at the loop. *Family:* all preflight-shortcut tools.
  **M** (needs a live capture first).

### P1 — parity & polish
- **P1-A · French detection (E4).** Strengthen `prefers_french` (function words + accent-less) or
  detect prompt language; unify across notice + answer. *Family:* all language selection. **S.**
- **P1-B · agy layout parity (R3/R4).** Two-rule input box; inline `▸ Thought for Xs … summary`. **S.**
- **P1-C · Confirm/clear R5** (palette filter redraw): reproduce deterministically; fix only if real. **S.**

### P2 — when agy quota resets
- **P2-A · Tool-card exact diff (§4).** Capture agy tool card live; align our `⎿` line if it diverges. **S.**

**Sequencing:** P0-A and P0-B remove most live failures (they attack the 500-storm surface directly);
P0-C is quick and closes E1's family; P0-D needs a live trace. P1 is parity polish. Nothing ships
without the full suite green + a new regression test per family.

---

## 6. Implementation results (2026-07-04, family-by-family)

Baseline before this pass: **687 tests**. After: **695 tests**, all green, ruff clean, TUI smoke
at the documented baseline (29 PASS / 4 pre-existing FAIL; `renderer.py` untouched). Each family
shipped with a whole-family regression test that was **red before / green after**, then the full
suite was rerun before the next family (Fix Discipline).

| Family | Fix (shared cause) | Files | Test (red→green) | Suite | Live proof |
|---|---|---|---|---|---|
| **E1** timezone | added `uk`/`us`/`united kingdom`/`england`/`britain`/`america`/`mexico`/`netherlands` to `_CITY_TIMEZONES`; render `UK`/`US` as acronyms | `preflight.py` | `test_resolve_country_family_coverage`, `test_uk_time_answer_uses_london_zone_not_host` | 689 | `UK→BST`, `US→EDT`, `Mexique→CST` (was host GMT) |
| **E4** FR detection | replaced the keyword list with a high-precision, space-padded marker set (`est-ce`, `donne`, elisions, pronouns, accent-distinct nouns) | `preflight.py` | `test_prefers_french_covers_common_constructions` (11 FR true, 7 EN false incl. "comment out"/"balance") | 690 | — (unit-proven) |
| **E3** local facts | classifier markers (EN+FR) + `local_answer` branches for current user / uptime / active interface / default gateway; FR hostname; helpers `current_user`/`system_uptime_seconds`/`default_route` | `request_context.py`, `preflight.py` | `LocalFactRoutingTests` (classify + answer, leak-scanned) | 692 | 5 facts now instant & deterministic (were 45s hangs) |
| **E2** retry UX | `--print` consumer now surfaces `StatusEvent` (stderr heartbeat / JSON `status[]`); stdout stays the clean answer | `main.py` | `PrintModeRetryHeartbeatTests` (text + json) | 694 | — (unit-proven; heartbeat opportunistic on a live 500) |
| **E5** double card | dedupe identical tool calls **within one iteration** (Gemma emits the same call twice → one exec, one card) | `agent.py` | `test_duplicate_in_iteration_tool_call_runs_once` | 695 | — (deterministic repro in test) |

### agy visual parity — settled against a LIVE agy card (quota reset 2026-07-05)
Captured agy's real tool card via `scratch/agy_capture.py --mode full` (`Bash(pwd)` + ctrl+o):
```
▸ Thought for 2s
  The user wants me to run only the pwd command.
● Bash(pwd)
  ⎿  /home/administrator/Documents/secops_v2 (ctrl+o to collapse)
```
This overturned **two** of my earlier (capture-based) conclusions — a concrete argument for the
brief's insistence on running agy, not trusting notes:

- **R4 (thought line) — proposed inline, then REVERTED.** I first changed the collapsed thought to
  the inline `▸ Thought for Xs … summary` the code comment claimed agy used. The **live** card
  shows agy renders it as **two lines** (`▸ Thought for Xs` then `  <content>`) — which is what we
  already had. Reverted to the original; fixed the misleading comment. Net: no behavioural change,
  now provably agy-correct.
- **P2-A (tool-card `⎿` line) — FIXED (the real divergence).** agy shows a successful command's
  output *directly* on the `⎿` line (`⎿ /home/…/project`). Ours matched for single-line output and
  for parsed-summary tools, **but** the `[Exit Code: 0]` trailer our tools append counted as a 2nd
  line and pushed single-line commands into the metadata branch (`⎿ 30ms · 2 lines · …`). Fix:
  drop a trailing zero-exit trailer in the *collapsed summary only* (non-zero stays — diagnostic).
  Now `pwd` → `⎿ /home/…/secops_v2`, matching agy. *[test: `CollapsedToolCardExitCodeTests`;
  697 green; F repro PASS; smoke 29/4 baseline]*
- **R3 (two-rule input box) — ALREADY CORRECT (false positive).** The full idle screen is
  `─── / > / ─── / ? for shortcuts … model`; the input is already bracketed by two rules. The "one
  rule" note was a capture artifact (`wait_for_prompt` returns at `>`, before the bottom toolbar
  renders). No change.
- **R5 (palette filter char-drop) — not a product bug** (harness mid-filter frame overlap; settled
  frames clean).

Everything else on the card already matches agy: `● ToolName(args)`, solid `●`, two-space `⎿  `,
2-col indent, and the `(ctrl+o to expand/collapse)` tag on the `⎿` line.
- **F / C** — confirmed fixed at the renderer level and re-proven (repros PASS); the residual
  "duplication" the brief flagged is explained by **E5** (engine double-invoke), now fixed.

### Model vs. code attribution
All five fixes are **code-side orchestration** (routing, preflight coverage, retry surfacing,
loop dedupe). E5 is amplified by a **mission-model quirk** (Gemma emitting a duplicate tool call),
but the fix is code-side and model-agnostic. None required prompt changes.
