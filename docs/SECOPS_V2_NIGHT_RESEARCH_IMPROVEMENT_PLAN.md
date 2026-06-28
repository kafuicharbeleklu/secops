# SecOps v2 Night Research Improvement Plan

Date: 2026-06-05

## Purpose

This document consolidates a fresh technology watch and a local codebase audit
for SecOps v2. It is intended to give a clear view of what remains useful after
the AGY-style TUI parity pass and the recent pentest-agent business-logic work.

The goal is not to restart old work. The goal is to identify the next high-value
improvements for a terminal pentest agent that can be used in authorized CTF
labs, private virtual labs, and authorized assessments.

## Deep Research Addendum

Follow-up research and subagent audits on 2026-06-05 found immediate security
work that should precede the TTY rebaseline:

- `ssl_audit` shell injection risk in its OpenSSL fallback.
- Shell substitution and sudo detection mismatch, especially backticks.
- File permission policy exists but is not enforced by the agent execution
  path for file-reading tools.
- Hooks, skills, and MCP startup need trust/approval governance before further
  extension work.
- VPN ownership and `ctrl+o`/resume issues remain important, but should follow
  the P0 local execution fixes.

Detailed source mapping and the reprioritized P43-P52 queue are documented in:

`docs/SECOPS_V2_DEEP_RESEARCH_AND_CODE_AUDIT_2026-06-05.md`

The short execution queue for the next implementation sprint is:

`docs/SECOPS_V2_NEXT_SPRINT_QUEUE_2026-06-05.md`

The source-to-ticket index for the extended night research is:

`docs/SECOPS_V2_RESEARCH_SOURCE_INDEX_2026-06-05.md`

The tool risk inventory derived from source review is:

`docs/SECOPS_V2_TOOL_RISK_INVENTORY_2026-06-05.md`

The short French executive plan is:

`docs/SECOPS_V2_PLAN_EXECUTIF_2026-06-05.md`

## Sources Reviewed

Primary external sources:

- NIST SP 800-115, Technical Guide to Information Security Testing and
  Assessment: https://csrc.nist.gov/pubs/sp/800/115/final
- OWASP Web Security Testing Guide:
  https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP Top 10 for Large Language Model Applications:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Agentic Skills Top 10:
  https://owasp.org/www-project-agentic-skills-top-10/
- NIST AI Risk Management Framework:
  https://www.nist.gov/itl/ai-risk-management-framework
- NCSC/CISA Guidelines for Secure AI System Development:
  https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development/introduction
- Command Line Interface Guidelines: https://clig.dev/
- Rich progress display documentation:
  https://rich.readthedocs.io/en/latest/progress.html
- FIRST EPSS: https://www.first.org/epss/
- NVD CVE API documentation:
  https://nvd.nist.gov/developers/vulnerabilities
- OpenVPN 2.6 manual:
  https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html

Local project material reviewed:

- `docs/AGY_REMAINING_WORK_PLAN.md`
- `docs/AGY_PARITY_STATUS_DASHBOARD.md`
- `docs/AGENT_BUSINESS_LOGIC_REVIEW_PLAN.md`
- `docs/PENTEST_AGENT_CAPABILITY_PLAN.md`
- `docs/EXTERNAL_REVIEW_SYNTHESIS.md`
- `docs/BUSINESS_LOGIC_HANDOFF_REPORT.md`
- `secops_agent/core/agent.py`
- `secops_agent/core/execution.py`
- `secops_agent/core/observability.py`
- `secops_agent/core/request_context.py`
- `secops_agent/core/planner.py`
- `secops_agent/core/permissions.py`
- `secops_agent/main.py`
- `secops_agent/ui/renderer.py`
- `secops_agent/ui/runtime.py`
- Current test suite layout under `tests/`

## Current Local Baseline

The current project is not at the old "missing core agent behavior" stage
anymore.

Confirmed current strengths:

- AGY-style TUI/TUX parity is documented as frozen for the current SecOps scope.
- The proposal-first business logic is implemented: planner suggestions do not
  auto-execute by default.
- Request classification separates technical goal, user intent, risk, scope,
  and environment metadata.
- Long-running execution has an `ExecutionSupervisor` with spool files,
  progress, cancellation, runtime limits, and process-group termination.
- Sudo handling now has local password prompting and non-interactive preflight
  paths.
- VPN setup/status/disconnect tools exist and are routed through permission and
  sudo handling.
- Sessions persist runtime artifacts, model state, structured memory, and
  loaded-session autosave behavior.
- Experience memory exists with governance controls: audit, export,
  anonymization, pruning, and no automatic raw `run_shell` lesson capture.
- Optional JSONL observability and LLM exponential backoff are already present.
- The test suite is broad: agent behavior, permissions, execution supervisor,
  lab replay, local lab setup, request context, result parsers, runtime
  persistence, sudo auth, TUI polish, and smoke capture are covered.

Latest verification observed during this pass:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
```

Result observed: 434 tests passed.

## Main Finding

The next work should not be another broad AGY parity or "add more commands"
cycle.

The useful next work is:

1. make the current behavior reproducible in real TTY sessions;
2. harden long-running and resumed-session UX with evidence;
3. continue reducing the large orchestration/rendering files without changing
   user behavior;
4. add vulnerability intelligence as a safe enrichment layer, not as an
   exploitation trigger;
5. mature the experience memory into reviewed playbooks and measurable replay
   outcomes;
6. add governance for any future skill/MCP/tool extension path.

## External Lessons Mapped To SecOps

### Pentest Methodology

NIST SP 800-115 frames security testing around planning, conducting tests,
analyzing findings, and mitigation. For SecOps this means the mission model
should keep scope, evidence, findings, and report generation central rather
than treating a lab label as the main decision point.

OWASP WSTG is useful as a web-testing coverage vocabulary. SecOps should map
web findings and reports to WSTG-style categories and stable references where
possible, but it should not fake WSTG coverage when the evidence does not exist.

MITRE ATT&CK is useful as a TTP vocabulary and reporting aid. SecOps should use
ATT&CK only where observed evidence supports the mapping; it should not infer
techniques from a platform name or a generic CTF prompt.

### Agentic Security

OWASP LLM and Agentic Skills guidance points to the same direction already
chosen locally: least privilege, schema validation, approval workflows, audit
logging, isolation, and governance for reusable agent behaviors.

For SecOps, that means:

- keep proposal-first execution;
- keep tool permissions separate from orchestration intent;
- treat tools, MCP servers, skills, hooks, and future extensions as privileged
  execution surfaces;
- avoid hidden background chains unless explicitly selected;
- preserve audit traces without dumping secrets or full private outputs.

### Terminal UX

The CLI Guidelines emphasize signal-to-noise ratio, useful human errors, and
pagers for large output only when the terminal is interactive. Rich's progress
model confirms that long-running tasks should have continuously updated
progress, multiple task support, and clean start/stop behavior.

For SecOps, that means:

- collapsed tool output by default remains correct;
- `ctrl+o`, `/tasks`, artifact open, and spool review are the right detail
  surfaces;
- large text must not flood the prompt;
- errors should become next-action guidance, not raw SDK or shell noise;
- TTY smoke tests are mandatory for TUI changes.

### Vulnerability Intelligence

EPSS provides probability-oriented exploit likelihood signals for CVEs. NVD
provides CVE API data. These are useful for prioritization, not for confirming
that a target is vulnerable.

For SecOps, vulnerability intelligence should enrich confirmed services and
findings with:

- CVE metadata;
- EPSS probability/percentile;
- CPE/service matching confidence;
- known-exploited flags if a trusted feed is added;
- explanation of uncertainty.

It must not auto-start exploitation.

### VPN And Long-Running Setup

OpenVPN supports operational status files and logging. SecOps already writes
logs and parses status, but the UX should treat VPN as a supervised local
process with explicit status states: disconnected, starting, connected, stale,
failed, and blocked-by-network.

The user's recent VPN experience showed this matters: the first failure was a
network/firewall condition, not a tool logic failure. The agent should explain
that distinction clearly.

## Roadmap

### P33 - Fresh TTY Rebaseline And Evidence Pack

Priority: Immediate

Why:

The docs say AGY parity and current TUI behavior are stable, but the user still
found real TTY edge cases around `ctrl+o`, `/resume`, VPN, and duplicated tool
rows after long sessions. Unit tests are not enough for these surfaces.

Work:

- Regenerate a fresh SecOps PTY evidence pack after the current code state.
- Re-run the existing AGY capture only if AGY evidence is needed for a specific
  mismatch; do not reopen AGY parity broadly.
- Add scripted TTY scenarios for:
  - normal prompt and local question;
  - tool result then `ctrl+o`;
  - text answer after tool result then `ctrl+o`;
  - `/resume` with visible transcript replay;
  - long-running supervised command with progress;
  - sudo-authenticated command path;
  - VPN connect/status/disconnect states;
  - slash palette pagination and delete/backspace suggestion recovery.
- Store sanitized evidence under `docs/evidence/secops_tui_YYYY-MM-DD/`.

Acceptance:

- Multi-size PTY smoke passes at `80x24`, `120x34`, and `160x40`.
- `ctrl+o` expands at the right visible location or has a documented terminal
  limitation with a reproducible case.
- `/resume` visually replays the discussion thread, not only the structured
  context.
- VPN blocked-by-network, starting, connected, stale, and disconnected states
  render differently and truthfully.

### P34 - Request Decision Evaluation Matrix

Priority: Immediate

Why:

`request_context.py` is now central. It must be evaluated as a product contract,
not only as helper code.

Work:

- Build a table-driven corpus for French and English prompts across:
  - local system questions;
  - narrow CTF questions;
  - broad recon requests;
  - private VM scans;
  - authorized org assessment phrasing;
  - web directory enumeration;
  - exploit and privilege escalation requests;
  - "continue", numbered selections, and "tout/tous/all" selection.
- Assert technical goal, user intent, risk, scope status, and follow-up
  suppression.
- Add regression tests for ambiguous prompts where the agent should propose
  rather than execute.

Acceptance:

- Same technical request receives the same technical decision across CTF,
  private lab, and authorized assessment wording.
- Environment hint never becomes the primary orchestration driver.
- Narrow answer prompts do not show noisy suggestions.
- Broad requests can show suggestions but still wait for explicit execution
  intent unless the user selected a bounded batch.

### P35 - Long-Running Task UX Hardening

Priority: High

Why:

The execution supervisor exists, but real trust depends on live terminal
feedback: no frozen terminal, no duplicate rows, predictable cancel, and
reviewable logs.

Work:

- Audit every long-running tool path and confirm it uses supervised execution
  or a streaming helper:
  - `run_shell`;
  - `nmap_scan`;
  - `dir_brute`;
  - `nikto_scan`;
  - `sql_injection_test`;
  - VPN connect/disconnect;
  - future package install proposals.
- Standardize state colors and markers from execution status:
  - running: amber/yellow;
  - success: green;
  - failure: red;
  - cancelled/interrupted: red or warning;
  - waiting for permission/sudo: neutral or warning.
- Ensure `/tasks` retains only useful long, failed, cancelled, or interrupted
  tool executions.
- Make task log/spool review deterministic and testable.

Acceptance:

- A silent command emits periodic "still running" progress.
- A streaming command shows output-derived progress without flooding.
- `Esc` or cancellation stops the process group and updates the task status.
- `ctrl+o` and artifact open read supervisor metadata/spool content without
  creating duplicate transcript rows.

### P36 - Safe Vulnerability Intelligence Layer

Priority: High

Why:

The agent can parse services and findings, but prioritization will improve if
confirmed versions are enriched with public vulnerability intelligence.

Work:

- Add a dedicated `vuln_intel` service module, separate from exploitation.
- Support optional NVD CVE lookup with rate-limit handling and local cache.
- Support optional EPSS enrichment for CVE prioritization.
- Add confidence scoring for service-to-CVE matching.
- Add report fields for:
  - CVE ID;
  - EPSS probability/percentile;
  - source URL;
  - confidence;
  - reason why this is only a candidate until validated.
- Keep CISA KEV or other exploited-in-the-wild feeds optional and cached if
  added later.

Acceptance:

- A parsed Apache/OpenSSH/version finding can produce candidate CVEs with
  confidence, not confirmed vulnerabilities.
- Reports distinguish "candidate reference" from "validated finding".
- No exploit, payload, or active validation starts from intelligence alone.
- Offline mode works from cache or degrades cleanly.

### P37 - Reviewed Playbook And Experience Memory Maturity

Priority: High

Why:

The experience store already records sanitized lessons. The next level is not
more raw memory; it is reviewed, measurable reuse.

Work:

- Add a reviewed playbook layer derived from experience lessons.
- Keep raw lessons local, private, auditable, and purgeable.
- Promote lessons to playbooks only when they have:
  - stable trigger conditions;
  - evidence requirements;
  - known failure modes;
  - safe next-action boundaries;
  - human-readable rationale.
- Add replay metrics:
  - did the suggested action solve the blocker?
  - did it repeat a known dead path?
  - did it require user correction?
  - was the suggestion selected or ignored?
- Keep CTF flags, credentials, local paths, and shell output excluded unless
  explicitly marked safe.

Acceptance:

- A RootMe-like upload path, HTB-like source disclosure, or private VM service
  enumeration scenario can retrieve a relevant reviewed playbook.
- The planner can explain the lesson influence without claiming certainty.
- User denials are not treated as technical failure lessons.
- Privacy governance remains test-covered.

### P38 - Compatible Architecture Refactor

Priority: High

Why:

The codebase now has strong behavior, but maintainability risk is visible:

- `secops_agent/main.py`: about 1,588 lines;
- `secops_agent/core/agent.py`: about 1,560 lines;
- `secops_agent/ui/renderer.py`: about 4,840 lines;
- `secops_agent/core/planner.py`: about 900 lines;
- `secops_agent/core/experience.py`: about 875 lines.

Work:

- Continue P32.18 only through behavior-preserving seams.
- Keep `secops_agent.main.run_chat_loop` import-compatible.
- Extract pure helpers before moving stateful code.
- Candidate seams:
  - command dispatch metadata;
  - runtime state loaders/savers;
  - ctrl+o transcript building;
  - session transcript replay;
  - tool task tracking;
  - suggested-action rendering;
  - VPN status formatting;
  - report/evidence view builders.

Acceptance:

- Each extraction has focused tests.
- No visible TUI behavior changes unless explicitly selected.
- Full test suite and PTY smoke still pass after each slice.

### P39 - TUI Style Contract And Regression Harness

Priority: Medium

Why:

The user repeatedly caught small formatting drift: bold text, colored keywords,
enumeration shape, spacing, duplicate commands, and pagination. These should be
converted into a style contract and tests.

Work:

- Write a compact TUI style contract:
  - no logo/login changes;
  - sparse AGY-like terminal transcript;
  - no new shortcuts without approval;
  - color important values only;
  - bold only for structurally important headings;
  - consistent numbered enumeration as `1. Text`;
  - long lists use pagination or bounded visible rows;
  - suggestions are compact and not rendered for narrow answers;
  - permission prompts stay contextual and do not offer misleading broad
    approvals.
- Add snapshot-style tests for rendered snippets, not only individual helper
  strings.
- Keep AGY parity evidence separate from SecOps business rules.

Acceptance:

- The style contract becomes the first reference before UI changes.
- Common surfaces are snapshot-tested:
  - help;
  - slash palette;
  - permissions;
  - suggestions;
  - settings;
  - tool result collapsed/expanded;
  - resume transcript.

### P40 - Extension, MCP, Skill, And Hook Governance

Priority: Medium

Why:

OWASP agentic-skill guidance makes clear that reusable agent behaviors and
tool-extension surfaces become privileged execution layers. SecOps already has
MCP, hooks, and skills surfaces; lifecycle flows are currently deferred, which
is acceptable. If they are expanded, governance must come first.

Work:

- Define a minimal extension manifest schema:
  - name;
  - version;
  - source;
  - required binaries;
  - file access;
  - network access;
  - shell access;
  - risk tier;
  - approval requirements.
- Add local inventory rendering for installed/enabled extensions.
- Validate manifests before enabling extension behavior.
- Never auto-install or auto-enable untrusted external skills.
- Keep update/install/changelog product-lifecycle flows out of scope until a
  real SecOps extension lifecycle is specified.

Acceptance:

- Extensions cannot silently add broad shell/network/file capabilities.
- MCP/hook/skill inventory can be audited.
- Any future install flow has explicit provenance, permissions, and approval.

### P41 - Methodology-Aware Reporting And Evidence Quality

Priority: Medium

Why:

Reports already exist. The improvement is to make them more useful for labs and
authorized assessments without inventing evidence.

Work:

- Add methodology mapping fields where evidence supports it:
  - NIST phase;
  - OWASP WSTG category/test ID for web findings;
  - MITRE ATT&CK tactic/technique only when observed behavior supports it.
- Add evidence quality labels:
  - observed;
  - inferred;
  - candidate;
  - validated;
  - failed/blocked.
- Add report appendix sections for:
  - tool commands run;
  - permission decisions;
  - scope blocks;
  - failed retries and why they were stopped;
  - data sources used for vulnerability intelligence.

Acceptance:

- A report is useful for both CTF recap and professional assessment notes.
- Candidate vulnerabilities are never presented as validated.
- Failed or blocked steps are visible enough to explain the process.

### P42 - Live Lab Validation Protocol

Priority: Medium

Why:

Replay tests are valuable, but real usage still exposes gaps: network blocks,
missing wordlists, sudo prompts, VPN handshakes, model provider errors, and
terminal rendering state.

Work:

- Define a manual validation script for:
  - TryHackMe VPN setup;
  - HackTheBox target enumeration;
  - RootMe-like upload lab;
  - private VM/hypervisor lab scan;
  - local system maintenance command with sudo;
  - provider error/retry path;
  - offline/no-network path.
- For each scenario, record:
  - prompt;
  - expected tool;
  - expected permission;
  - expected progress;
  - expected final answer;
  - expected suggestions or no suggestions.

Acceptance:

- The project has a repeatable "pre-release terminal validation" runbook.
- Manual results are stored in `docs/evidence/`.
- Failures become selected tickets, not broad rework.

## Immediate Next Sprint

The next sprint should be small and measurable:

1. P33.1: regenerate SecOps TTY smoke/evidence pack from the current code.
2. P33.2: add a PTY scenario for `/resume` visible transcript replay.
3. P33.3: add a PTY scenario for `ctrl+o` after a tool result followed by a
   plain assistant answer.
4. P33.4: add VPN PTY/local-tool scenarios for blocked network, connected,
   stale, and disconnected.
5. P34.1: add a request-decision matrix test file with French and English
   prompts.
6. P35.1: audit all long-running tool paths and document which supervisor path
   they use.
7. P38.1: continue P32.18 by extracting one pure helper from `main.py`, with no
   visible behavior change.
8. P39.1: write the TUI style contract as a short doc and bind two snapshot
   tests to it.

## Non-Goals

- Do not change the logo.
- Do not add login/account ceremony.
- Do not add new commands or shortcuts without explicit selection.
- Do not reopen broad AGY parity unless a fresh AGY capture or manual row shows
  a concrete mismatch.
- Do not add direct shell shortcut `!` by default.
- Do not add keybinding customization by default.
- Do not implement plugin/update/install/changelog flows without a real SecOps
  lifecycle requirement.
- Do not allow vulnerability intelligence to trigger exploitation.
- Do not let permission approval imply orchestration intent.

## Verification Baseline

Run after each implementation slice:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent tests scratch
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python \
  scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

For any TUI change, also run at least one targeted PTY capture and store a
sanitized result under `docs/evidence/`.

## Recommended Decision

Proceed with P43 first, then return to P33/P45/P46/P47.

Reason: P33 still matters for the exact category of live terminal issues the
user observes, but the deep addendum found P0 local execution and permission
risks. Those should be corrected before freezing or baselining the visible TUI
behavior.
