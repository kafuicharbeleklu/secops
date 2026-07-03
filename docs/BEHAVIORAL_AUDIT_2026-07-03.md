# Behavioral & TUI/UX Audit (2026-07-03)

> **Method:** the agent was **actually run** — 25 engine one-shots through the real
> `--print --output-format json` entry point, 12 in-process turns with real Gemini
> synthesis over **mocked** offensive-tool fixtures, and 5 rendering scenarios driven
> through a real PTY (`scratch/tui_smoke.TUISmokeHarness`). Code was read **afterwards**,
> per discrepancy, to trace root cause. Effective model observed: `gemma-4-26b-a4b-it`
> (auto-routed; `.env` says `gemini-2.5-flash`). Harnesses live in
> `scratch/` (audit drivers) and are the seed for the regression suite (§6).

> **Status of the 5 seed examples:** **A, B confirmed still broken; D partially fixed
> (one phrasing) but its root-cause class is still live; E confirmed; C not
> reproduced** (recent spinner-consolidation commits appear to have fixed it — one latent
> inconsistency remains). The audit found **9 engine + 4 rendering** discrepancies total.

---

## 1. Stack & the input → processing → output loop

| Layer | Where | Notes |
|---|---|---|
| Entry | `main.py` (Typer) | `--print` (one-shot) and `run_chat_loop` (TUI) |
| TUI | `ui/renderer.py` (3.9k l), `ui/input_handler.py` (1.3k l), `ui/animations.py` | `rich` + `prompt_toolkit`; **serial** `while True` read→process→render loop |
| Loop | `core/agent.py` `stream_response` → `_run_mission_loop` | ReAct; emits `TextEvent`/`ToolCallEvent`/`ToolResultEvent`/… |
| Preflight | `core/preflight.py` | deterministic **local answers** + **shortcut tool routing** that bypass the LLM |
| Synthesis | `core/llm.py` (Gemini/Gemma) | post-tool natural-language pass |
| Parse | `core/result_parsers/` | tool output → `ParsedResult.summary` (feeds memory + collapsed view) |

The two seed layers behave differently and are audited separately, as the brief asked.

---

## 2. Engine-layer discrepancies

| # | Input (repro via `--print … --output-format json`) | Observed | Expected | Severity |
|---|---|---|---|---|
| **D1** (Ex. A) | `est-ce que le VPN est actif ?` | `VPN status: disconnected  (+5 more line(s))` | NL answer: "Non, aucun VPN actif (aucune interface tun / process OpenVPN)." | **Blocking** |
| **D1b** | `quels outils offensifs sont installés ?` | `Local Lab Setup: Authorized lab  (+32 more line(s))` | "Installés : nmap, nikto… ; manquants : ffuf, sqlmap, searchsploit." | **Blocking** |
| **D2** (Ex. B) | `quelle heure est-il en France ?` / `au Japon ?` / EN `in France` | `… 17:14 GMT` (host time) | Europe/Paris (CEST 19:14) / Asia/Tokyo | **Blocking** |
| **D3** (Ex. D) | `donne-moi les informations système` | *(now synthesizes correctly — A4 fix)* | — | fixed (class still live via D1/D5) |
| **D4** | `quelle est mon adresse IP publique ?` | `Vos adresses IP locales sont: 192.168.6.149.` | actual **public** IP, or "je récupère l'IP publique via un service externe" | **Blocking** (coherence) |
| **D5** | `teste l'injection SQL …` / `version de sqlmap` (any turn hitting a transient 500) | **empty answer** (no text); or, if a tool ran, the raw `(+N more line(s))` summary re-leaks | never end empty; degrade to a clean fact or a clear transient-error notice | **Blocking** (robustness) |
| **D6** | `quelle est la prochaine étape ?` (and any 2-chunk turn) | `… RECONNAISSANCE.**Je n'ai pas d'action…**` (run-on, no space) | fragments joined with a separator | Annoying |
| **D7** | `quelle est la charge CPU actuelle ?` | `CPU cores: 8` (static spec) | actual load average / % utilisation | Annoying |
| **D8** | `quelle version de sqlmap est installée ?` | ran `sysinfo` (wrong), then empty | "sqlmap n'est pas installé." (deterministic) | Annoying |
| **D9** *(meta)* | French phrasings of §2/§3 categories | fall through the **English-keyed** matchers into a worse path | francophone parity with the clean deterministic answers | **Blocking** (root pattern) |

**Verified-good (no action):** active-interface, disk-space, OS, nmap-version, date, Tokyo
time, current target (honest "aucune cible"), suggested-next-step, bare `42`, out-of-scope
capital-of-Australia, mission-memory trends, elapsed-time (honest, minor wiring gap).

### Category 5 (offensive tools, mocked fixtures) — synthesis does **not** echo the raw stream
`nmap_scan` and `nuclei_scan` synthesized clean answers; the distinctive raw-output markers
(`MARKER_NMAP_RAW_…`, `MARKER_NUCLEI_RAW_…`) **never** appeared in the user answer. The
raw-leak is **not** a general synthesis failure — it is specific to the preflight/fallback
paths (D1/D5). *(Side note: "fuzzing avec **ffuf**" ran `dir_brute`, not `ffuf_scan` — minor
tool-pick drift.)*

---

## 3. Root-cause diagnosis (clusters)

### RC-α — Preflight/fallback presents the parser's **internal collapse string** as the answer  → D1, D1b, D5-leak
`preflight.route()` shortcut-routes well-known intents (VPN → `vpn_status`, lab/tools →
`lab_setup_check`) to a **local-preflight turn**. That turn **breaks before any LLM synthesis**
(`agent.py:2441`) and emits `_format_tool_answer_summary(...)` (`agent.py:2427`). That helper
has bespoke formatters only for `nmap_scan`/`dir_brute`; **everything else falls to
`return parsed_result.summary` (`agent.py:1109`)**, and that `summary` is the parser's
**collapse string** — first line + `"  (+N more line(s))"` (`core/result_parsers/system.py:144`),
a *display hint for the Ctrl+O view*, not a user answer. The A5 synthesis-failure fallback
(`agent.py:2419-2424`) uses the same helper, so a transient 500 **re-leaks** it (seq test:
`…Authorized lab (+36 more line(s))`). → **This is exactly the brief's A/D hypothesis:
log/summary channel leaking into the user channel, synthesis short-circuited.**

### RC-β — The deterministic layer is **English-keyed**, but the agent is **French-first**  → D2, D4, D9
- `_CITY_TIMEZONES` (`preflight.py:179`) is a curated **English city** map: no countries, no
  French names. `resolve_requested_timezone` finds no match for `France`/`Japon`/`in France`
  → returns `None` → `local_answer` falls to **host local time** (`preflight.py:441`). Tokyo
  works *only* because "tokyo" is a map key. (Root of D2.)
- `local_ip_intent` (`preflight.py:466`) matches `"mon adresse ip"` as a substring of
  `"mon adresse ip publique"` and has no `public/publique` disambiguation → returns local
  interfaces (D4). English `public IP` misses the marker entirely and diverges to the LLM.
- `local_answer`'s "tools installed" branch (`preflight.py:498`) is English-only, so the
  French "outils installés" misses it and falls to the `lab_setup_check` leak (D1b) — one
  bug (D9) causing another (D1b).

### RC-γ — Loop robustness on transient `500`  → D5
The transient-500 retry (`llm.py`, commit `9ceb5f8`) and the "no empty turn" guard (P4) do
**not** cover a 500 on the **first** (tool-selection) call: no tool ran, so there is no fact
to fall back on, and the turn yields **empty text** (`--print` then raises; TUI shows an error
line). 5 of ~33 audited turns hit a 500 on this flash/gemma tier → this is frequent, not rare.

### RC-δ — Text fragments concatenated without a separator  → D6
Two `TextEvent`s (e.g. a synthesized answer + an appended directive/suffix, or two stream
chunks across a boundary) are joined with no `\n`/space, producing run-ons like
`…VPN ?**Je vous prie…`. Exact join site to be pinpointed during the fix.

---

## 4. Rendering-layer discrepancies

| # | Scenario (real PTY) | Observed | Root cause | Severity |
|---|---|---|---|---|
| **R1** (Ex. E) | 3 instructions typed back-to-back during a turn | **1/3 processed**; 2 silently dropped, no response, no queue indicator | serial `while True` loop (`main.py run_chat_loop`), **no input queue**; bytes typed during processing are discarded at the next `get_input()` | **Blocking** |
| **R2** (Ex. C) | real thinking+tool turn; 25× repeat | **not reproduced** — exactly 1 "Thought for", 1 "Generating", **no `LiveError`** | recent commits (single running indicator; ctrl+o replace-not-stack) fixed it. **Latent:** `_start_thinking` (`renderer.py:3247`) lacks the defensive stop that `_start_tool_feedback` has (`:3301`) | Cosmetic / latent |
| **R3** | 25× `/tasks`, 400-char line, emoji, resize 100→60→140 cols | **no tracebacks**, clean frames, no accumulation | — (robust) | Good |
| **R4** | nmap summary in TTY | `1 Ports ouverts` (bad French plural) | pluralization not applied | Cosmetic |

The good three-way separation *does* work where a bespoke formatter exists (nmap turn:
tool card with collapsed raw output **above**, synthesized "Résultat Nmap…" **below**) — which
is exactly what RC-α breaks for VPN/lab/fallback.

---

## 5. TUI gap analysis vs Antigravity CLI (`agy`)

Confirmed current (July 2026): agy is Go/Bubble-Tea-v2, successor to Gemini CLI, shares the
Antigravity agent harness across surfaces; status bar shows **model + token/context usage +
session metadata**; **four permission levels** `request-review / proceed-in-sandbox /
always-proceed / strict`; searchable `/config`; discoverable slash commands w/ autocomplete;
thought-process rendered separately from the answer and from raw tool output.

| agy pattern (pentest-relevant) | Our state | Gap |
|---|---|---|
| 4 permission levels | **Already implemented** (`normalize_permission_mode`) | — (matched) |
| Searchable settings `/config` | Present (`/config` w/ search) | — (matched) |
| Slash palette + autocomplete | Present | — (matched) |
| Thought / **answer** / **raw tool output** = 3 separate channels | thought line ✓; **answer vs raw-tool-output leaks** (RC-α) | **G1 — the #1 gap; it is the D1/D5 coherence bug** |
| Queued input while agent works | none | **G3 — the R1/Example-E bug** |
| Status bar: model **+ tokens/context + session** | model only (`/context` is separate) | G2 (low) |
| Permission level tied to **mission phase** (recon=broad, exploit=review) | risk-class gating (arguably stronger) but **phase→posture not surfaced** | G4 (medium) |

---

## 6. Prioritized improvement plan

Effort S ≤ ½ day · M ≈ 1–2 days · L > 2 days. Each item ships with its regression test green
before the next (existing suites to extend named in *[brackets]*).

### P0 — blocking coherence & robustness
- **P0-1 · Kill the raw-summary leak (RC-α → D1, D1b, D5-leak / gap G1).** Separate a clean
  user-facing `ParsedResult` sentence from the internal collapse trailer; give `vpn_status`
  & `lab_setup_check` bespoke `_format_tool_answer_summary` branches; guarantee neither the
  preflight-turn presentation nor the A5 fallback ever emits `(+N more line(s))`.
  **M · high.** *[test_local_system_answers, test_synthesis_error_fallback]*
- **P0-2 · Timezone: countries + French/localized names (RC-β → D2).** Extend the resolver
  (France→Europe/Paris, Japon→Asia/Tokyo, Royaume-Uni, États-Unis, Allemagne…, plus FR city
  spellings); keep the city map. **S · high.** *[test_local_time_answer]*
- **P0-3 · Public vs local IP (RC-β → D4).** Disambiguate `public/publique` (fetch real
  public IP via an external service, gated) vs `locale`; unify FR/EN. **S · medium.**
  *[test_local_system_answers]*
- **P0-4 · Transient-500 never ends empty (RC-γ → D5).** On a first-call 500, surface a clean
  "service momentanément indisponible, réessayez" instead of empty; ensure any fallback uses
  the clean summary from P0-1. **M · high.** *[test_synthesis_error_fallback]*
- **P0-5 · Input queue (R1 / Example E / gap G3).** Capture instructions entered during a
  turn and process them sequentially (or show "N en file"). **M–L · high.** *[new
  test_input_queue via TUISmokeHarness]*
- **P0-6 · Francophone matcher parity (RC-β / D9).** As each matcher above is touched, add
  the FR keys so French never falls through to a worse path. **(folded into P0-1..3.)**

### P1 — structure & coherence polish
- **P1-1 · TextEvent separator (RC-δ → D6).** S. *[test_command_streaming]*
- **P1-2 · CPU load in `sysinfo` (D7) + deterministic missing-tool/version answer (D8).**
  S–M. *[test_sysinfo_resources, test_local_tool_version]*
- **P1-3 · Harden `_start_thinking` with a defensive stop (R2 latent).** S. *[test_tui_polish]*
- **P1-4 · Surface phase→autonomy posture (gap G4)** — show the active permission posture and
  tie the default to mission phase (recon broad / exploitation review). M.

### P2 — polish
- **P2-1 · Status bar: token/context/session metadata (gap G2).** M.
- **P2-2 · French pluralization + trim verbosity (R4).** S.
- **P2-3 · Wire elapsed-time from `MissionContext`.** S.

**Sequencing:** P0-1 and P0-2 first (they clear the two seed examples and gap G1); P0-4 rides
on P0-1's clean summary; P0-5 is independent (TUI). One bug → one green regression test →
commit, before the next.
