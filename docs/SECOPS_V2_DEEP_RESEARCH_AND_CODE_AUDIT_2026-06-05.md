# SecOps v2 Deep Research And Code Audit Addendum

Date: 2026-06-05
Local time at start of addendum: 00:25 GMT

This addendum extends `SECOPS_V2_NIGHT_RESEARCH_IMPROVEMENT_PLAN.md` with
additional online research, subagent read-only audits, and fresh local source
checks.

The purpose is to avoid another vague "continue" cycle. The output is a
concrete implementation queue for a pentest terminal agent used across CTF
platforms, private virtual labs, and authorized assessments.

## Executive Decision

The next work should be reprioritized.

The earlier plan correctly recommended a fresh TTY baseline first. The deeper
audit found security issues that should now take precedence:

1. Fix local execution and permission P0 issues.
2. Then run the TTY/AGY rebaseline and resume/ctrl+o evidence pack.
3. Then continue business-logic, long-task UX, vulnerability-intelligence, and
   playbook-memory work.

Reason: a TUI baseline is useful, but it should not freeze behavior while
`ssl_audit`, file-reading tools, shell substitution parsing, hooks, skills, and
VPN process ownership still have clear governance gaps.

## Additional External Sources Reviewed

### Standards And Methodology

- NIST SP 800-115:
  https://csrc.nist.gov/pubs/sp/800/115/final
- OWASP Web Security Testing Guide:
  https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK:
  https://attack.mitre.org/
- NIST AI Risk Management Framework:
  https://www.nist.gov/itl/ai-risk-management-framework
- CISA Known Exploited Vulnerabilities catalog:
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD CVE API:
  https://nvd.nist.gov/developers/vulnerabilities
- FIRST EPSS:
  https://www.first.org/epss/

### Agentic AI Security

- OWASP AI Agent Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP LLM Prompt Injection Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- OWASP Agentic Skills Top 10:
  https://owasp.org/www-project-agentic-skills-top-10/
- OWASP Agentic Skills checklist:
  https://owasp.org/www-project-agentic-skills-top-10/checklist.html
- OWASP Autonomous Penetration Testing Standard (APTS):
  https://owasp.org/APTS/
- OWASP APTS Scope Enforcement:
  https://owasp.org/APTS/standard/1_Scope_Enforcement/
- NCSC/CISA secure AI system development guidance:
  https://www.cisa.gov/news-events/news/dhs-cisa-and-uk-ncsc-release-joint-guidelines-secure-ai-system-development

### CLI And Long-Running Task UX

- Command Line Interface Guidelines:
  https://clig.dev/
- Rich progress display:
  https://rich.readthedocs.io/en/latest/progress.html
- OpenVPN 2.6 manual:
  https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html

### Pentest Tools And Data Sources

- Nmap: https://nmap.org/
- OWASP ZAP: https://www.zaproxy.org/
- ProjectDiscovery nuclei:
  https://github.com/projectdiscovery/nuclei
- ProjectDiscovery nuclei templates:
  https://github.com/projectdiscovery/nuclei-templates
- ProjectDiscovery subfinder:
  https://github.com/projectdiscovery/subfinder
- ProjectDiscovery httpx:
  https://github.com/projectdiscovery/httpx
- ProjectDiscovery naabu:
  https://github.com/projectdiscovery/naabu
- ProjectDiscovery katana:
  https://github.com/projectdiscovery/katana
- ffuf: https://github.com/ffuf/ffuf
- gobuster: https://github.com/OJ/gobuster
- feroxbuster: https://github.com/epi052/feroxbuster
- SecLists: https://github.com/danielmiessler/SecLists
- PayloadsAllTheThings:
  https://github.com/swisskyrepo/PayloadsAllTheThings
- PEASS-ng / linPEAS / winPEAS:
  https://github.com/peass-ng/PEASS-ng
- GTFOBins: https://gtfobins.org/

### Training Platforms, Courses, And Video Sources

- PortSwigger Web Security Academy:
  https://portswigger.net/web-security/all-topics
- Hack The Box Academy FAQ:
  https://academy.hackthebox.com/faq
- TryHackMe paths:
  https://tryhackme.com/paths
- Root-Me:
  https://www.root-me.org/
- TCM Security Practical Ethical Hacking:
  https://tcm-sec.com/academy/practical-ethical-hacking/
- OffSec PEN-200 onboarding:
  https://help.offsec.com/hc/en-us/articles/4406841351316-PEN-200-Onboarding-A-Learner-Introduction-Guide-to-the-OSCP
- HackTricks Pentesting Methodology:
  https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-methodology.html
- IppSec search and walkthrough index:
  https://ippsec.rocks/
- IppSec YouTube:
  https://www.youtube.com/c/ippsec
- John Hammond:
  https://www.johnhammond.llc/
- John Hammond YouTube:
  https://www.youtube.com/@_JohnHammond
- LiveOverflow:
  https://liveoverflow.com/
- LiveOverflow YouTube:
  https://www.youtube.com/LiveOverflow
- NahamSec:
  https://www.nahamsec.com/
- NahamSec YouTube:
  https://www.youtube.com/@NahamSec

### Pentest Agent Research

- PentestGPT repository:
  https://github.com/GreyDGL/PentestGPT
- PentestGPT USENIX Security 2024 paper:
  https://www.usenix.org/conference/usenixsecurity24/presentation/deng
- ARACNE:
  https://arxiv.org/abs/2502.18528
- CRAKEN:
  https://arxiv.org/abs/2505.17107
- AutoPentester:
  https://arxiv.org/abs/2510.05605
- HackSynth:
  https://arxiv.org/abs/2412.01778
- Pentest-R1:
  https://arxiv.org/abs/2508.07382
- AutoMalTool / MCP tool poisoning:
  https://arxiv.org/abs/2509.21011
- PentAGI:
  https://github.com/vxcontrol/pentagi

## External Lessons Mapped To SecOps v2

### 1. Scope And Evidence Must Stay Central

NIST SP 800-115 frames testing around planning, conducting tests, analyzing
findings, and mitigation. OWASP WSTG gives a web-testing vocabulary. MITRE
ATT&CK gives a TTP vocabulary.

SecOps should therefore treat "CTF", "HTB", "RootMe", "private VM", and
"authorized assessment" as context hints, not as orchestration modes that
change the technical facts.

Required product rule:

- The agent should infer the technical task from the prompt and current
  evidence.
- The environment label should tune language, reporting, and stop conditions.
- The environment label should not silently authorize broader scans, brute
  force, exploitation, or post-exploitation.

### 2. Proposal-First Is Correct, But Needs Stronger Boundaries

The user's lived issue is not "the agent is too safe"; it is "the agent chains
too much, hides progress, and sometimes blocks the terminal". The correct
direction is still proposal-first.

Refinement:

- A narrow question should return a narrow answer.
- A broad request can propose a batch, but the user must choose it.
- A numbered reply like `1 2`, `1,2`, `all`, `tout`, or `tous` should be parsed
  as a selection intent, not as an ambiguous chat answer.
- A selected batch should run with bounded concurrency, visible progress, and
  cancellation.

### 3. Autonomous Pentest Standards Put Scope First

OWASP APTS is especially relevant because it targets autonomous penetration
testing platforms directly. Its scope-enforcement domain says scope is the
first line of defense: rules of engagement, IP/domain validation, temporal
boundaries, pre-action scope checks, deny-lists, rate limiting, and drift
detection must be enforced continuously.

Mapping to SecOps:

- `EngagementContext` is not optional for a pentest agent. It should be the
  persisted source of truth for RoE and scope.
- Every active network action needs a pre-action scope check.
- Scope decisions should be logged as evidence, not only used as internal
  gating.
- Rate limits and delays should be first-class tool adapter settings.
- Recurring labs or resumed sessions need scope refresh/revalidation before
  new active actions.

### 4. Training Sources Should Feed A Curriculum, Not Auto-Exploitation

PortSwigger, HTB Academy, TryHackMe, Root-Me, IppSec, John Hammond,
LiveOverflow, and NahamSec are useful for creating replay scenarios and
reviewed playbooks. They should not become hidden automatic chains.

Useful extraction model:

- platform or source;
- technique category;
- preconditions;
- safe evidence to collect;
- risky action boundary;
- expected failure modes;
- report mapping;
- replay fixture.

Example:

- IppSec/HTB walkthroughs are useful for multi-service reasoning and attack
  path linking.
- PortSwigger Academy is useful for web vulnerability taxonomy and small
  targeted labs.
- PEN-200/OSCP and TCM PEH are useful for full-assessment discipline:
  enumeration discipline, reporting, privilege escalation, Active Directory,
  and time-boxed decision making.
- HackTricks is useful as a technique lookup source, but must be treated as
  untrusted external content when injected into LLM context.
- LiveOverflow is useful for binary exploitation curriculum, but not a reason
  for SecOps to auto-run exploit payloads.
- NahamSec is useful for recon and bug bounty workflow patterns, especially
  rate limits and scope caution.

### 5. Pentest Agent Research Confirms The Same Failure Modes

PentestGPT, HackSynth, ARACNE, CRAKEN, AutoPentester, Pentest-R1, and PentAGI
all point to a similar pattern:

- iterative planning plus tool feedback improves results;
- context loss and over-weighting recent observations are common failures;
- knowledge retrieval and curated walkthrough/playbook data can help;
- autonomy improves task completion but increases governance risk;
- benchmark/replay harnesses are required to measure progress honestly.

Mapping to SecOps:

- Keep a planner and structured memory, but bind them to scope and objective.
- Add replay fixtures from labs instead of relying on anecdotal success.
- Track selected/ignored suggestions and failed retries as evaluation data.
- Do not copy "fully autonomous" behavior unless there is a user-selected
  autonomy level and bounded safety controls.

### 6. MCP Security Research Raises The Priority Of Extension Governance

AutoMalTool research on malicious MCP tools reinforces the local finding that
MCP server startup and tool definitions are privileged attack surfaces. It is
not enough for MCP tools to be `dangerous=True` at call time.

Mapping to SecOps:

- MCP server startup needs approval and provenance.
- Tool schema validation must preserve constraints, not only type/description.
- MCP tool names and descriptions should be treated as untrusted data.
- Cross-tool chains need exfiltration-aware review.

### 7. Tool Ecosystem Should Be Adapter-Based

The ProjectDiscovery ecosystem shows the value of composable tools with JSON
output. SecOps should not add endless bespoke commands first. It should build a
small adapter contract:

- command capability;
- required binary;
- risk tier;
- expected output modes;
- parser;
- timeout profile;
- rate-limit profile;
- scope constraints;
- install hint;
- evidence mapping.

Good next adapters:

- `ffuf` / `gobuster` / `feroxbuster` content discovery;
- `httpx` HTTP probing;
- `subfinder` passive subdomain enumeration;
- `naabu` fast port discovery;
- `nuclei` safe template scanning, with severity filters and explicit
  "candidate only" reporting;
- `zap` passive/baseline scanning;
- `linpeas` and `winpeas` only after shell/session context and explicit user
  selection.

### 8. Agentic Security Requires Governance Before Extension

OWASP agentic guidance points directly at SecOps surfaces:

- hooks;
- skills;
- MCP servers;
- external tools;
- persistent memory;
- session replay;
- file and network access.

For SecOps, this means:

- no trusted-by-default workspace hooks;
- no workspace skill Markdown promoted into privileged system instruction
  without explicit trust;
- MCP start must be permissioned, not only MCP tool calls;
- external tool adapters must declare permissions;
- memory and traces need value-based secret redaction, not only key-name
  redaction.

## Subagent Audit Consolidation

Four read-only subagents were used.

### TUI / Resume / Slash / Settings Audit

Key findings:

- `/resume`, `/load`, and `--session` replay transcript without a default
  message limit.
- `RuntimeState.load_session_dict()` calls `reset_ctrl_o_surface()` without
  clearing old anchors.
- `ctrl+o` has split idle/streaming state and can diverge.
- Slash palette rows are custom monkey-patched and not fully PTY-regressed.
- `/resume` accepts a target but has less completion support than `/load`.
- Pagination key support differs between help, overlays, settings, artifacts,
  and other lists.
- Sandbox and permission settings can become hard to explain when toggled
  independently.

Priority implication:

- P1 after security P0: fix stale `ctrl+o` anchors, bound resume transcript,
  and create PTY replay cases before further UI polish.

### Execution / Sudo / VPN / Spool Audit

Key findings:

- `ExecutionSupervisor` is strong for long tasks that use it.
- `run_cmd_streaming` propagates spool metadata and progress.
- `run_shell` has a good order: scope, tool permission, command permission,
  sudo precheck, execution.
- But shell substitution parsing has a sudo gap:
  - `echo $(sudo id)` is detected as `echo` and `sudo`;
  - `echo `sudo id`` is detected only as `echo`;
  - `command_uses_sudo()` misses nested forms.
- File permission policy exists but is bypassed by agent execution because
  `agent.py` uses `evaluate_tool()` instead of `check_tool_permission()`.
- `_run_cmd` does not guarantee process-group cleanup.
- Some web scan timeouts can be hidden when stdout exists.
- VPN connect can misread an old TUN interface as success.
- VPN disconnect kills all OpenVPN processes, not only SecOps-owned ones.
- Spools and artifacts have privacy/retention gaps.

Priority implication:

- P0: command substitution parsing, file policy enforcement, timeout semantics.
- P1: VPN ownership and supervised process behavior.

### Business Logic Audit

Key findings:

- Environment hints exist but mission persistence does not preserve platform,
  objective, authorization basis, stop conditions, or data sensitivity policy.
- `OUT_OF_SCOPE` exists but request classification rarely emits it early.
- No `in_scope` means permissive behavior today.
- Planner is technical-state based, not objective based.
- Parser `next_steps` can be too aggressive.
- Experience memory can mix CTF, private VM, and authorized audit lessons if
  technical tokens overlap.
- LLM context does not include enough scope constraints.

Priority implication:

- P1: create a persisted `EngagementContext`.
- P1: normalize parser next actions into bounded, reviewed suggestions.
- P1: add experience compatibility constraints.

### Agentic Security / Governance Audit

Key findings:

- `ssl_audit` is marked `dangerous=False`, but fallback OpenSSL path builds a
  `bash -c` command with unquoted target data.
- Hooks can run external commands around tool execution and are enabled by
  default.
- Skills from workspace/global Markdown are inserted as privileged
  instructions.
- Sandbox is not a true uniform OS isolation layer and is disabled in several
  common modes.
- File tools can read sensitive paths because argument-aware permissions are not
  enforced.
- MCP tools are dangerous at call time, but MCP server startup is a separate
  privileged surface.
- Traces redact by key name, not by secret-shaped values.
- Sensitive files are written without an explicit 0600/0700 policy everywhere.

Priority implication:

- P0: fix `ssl_audit`.
- P0: enforce file path policy.
- P1: disable or approval-gate hooks/skills/MCP startup by trust manifest.
- P1: add file permission hardening and value-based redaction.

## Local Code Findings Verified In This Pass

### Static Tool Inventory Snapshot

AST inventory command found 32 registered tools under `secops_agent/tools/`.

High-signal rows:

```text
tool,file,dangerous,run_cmd,streaming,shell_literals
ssl_audit,secops_agent/tools/crypto.py,False,2,0,2
file_analyze,secops_agent/tools/forensics.py,False,2,0,0
sysinfo,secops_agent/tools/forensics.py,False,1,0,2
lab_setup_check,secops_agent/tools/forensics.py,False,1,0,2
log_analyze,secops_agent/tools/forensics.py,False,1,0,2
find_files,secops_agent/tools/forensics.py,False,1,0,2
ping_host,secops_agent/tools/network.py,False,1,0,1
subdomain_enum,secops_agent/tools/recon.py,False,2,0,0
xss_test,secops_agent/tools/web.py,True,2,0,0
waf_detect,secops_agent/tools/web.py,True,2,0,0
connect_vpn_config,secops_agent/tools/forensics.py,True,3,0,6
disconnect_vpn,secops_agent/tools/forensics.py,True,2,0,4
```

Interpretation:

- `dangerous=False` must not mean "no argument policy needed".
- Non-dangerous tools that read local files or run shell commands still need
  path, target, and command validation.
- `run_cmd_streaming` already covers the biggest active scan tools, but P47
  should audit the remaining `_run_cmd` paths for process-group cleanup and
  timeout semantics.
- VPN is dangerous but still needs ownership, state, and process lifecycle
  hardening.

### Architecture Hotspot Snapshot

Largest local Python files observed:

```text
4840  secops_agent/ui/renderer.py
1588  secops_agent/main.py
1560  secops_agent/core/agent.py
1419  secops_agent/core/result_parser.py
1202  secops_agent/ui/input_handler.py
 990  secops_agent/tools/forensics.py
 900  secops_agent/core/planner.py
 875  secops_agent/core/experience.py
 767  secops_agent/ui/tool_display.py
 732  secops_agent/core/mission.py
 665  secops_agent/core/llm.py
 603  secops_agent/ui/overlay.py
 500  secops_agent/core/permissions.py
 486  secops_agent/core/tools.py
 481  secops_agent/core/mcp.py
 466  secops_agent/core/request_context.py
```

Interpretation:

- `renderer.py` is the main TUI risk. Future TUI work should extract pure
  render builders and controller state in small slices.
- `main.py` is still a command/session/runtime orchestrator hotspot. Preserve
  `run_chat_loop` compatibility while extracting command handlers.
- `agent.py` mixes LLM loop, approvals, sudo, scope, hooks, parsing,
  experience, and progress. P43 should touch the smallest possible permission
  path first, then later extract governance helpers.
- `result_parser.py` and `planner.py` are business-logic hotspots. P48/P49
  should avoid adding more string-only next-step behavior without a typed
  action model.

### Test Coverage Shape

Top test files by test count:

```text
186  tests/test_tui_polish.py
 26  tests/test_agent_permissions.py
 21  tests/test_model_behavior.py
 20  tests/test_cli_surfaces.py
 19  tests/test_planner.py
 19  tests/test_experience_memory.py
 18  tests/test_local_lab_setup.py
 16  tests/test_tool_chaining.py
 16  tests/test_result_parsers.py
 10  tests/test_lab_replay_harness.py
  9  tests/test_runtime_persistence.py
  8  tests/test_mission_phase.py
  6  tests/test_tool_argument_validation.py
  6  tests/test_scope_guardrails.py
  6  tests/test_request_context.py
  6  tests/test_execution_supervisor.py
```

Interpretation:

- TUI polish has broad regression coverage, but PTY evidence still matters.
- Security permission tests exist but need targeted additions for backticks,
  file path policy, and `ssl_audit`.
- Scope/business tests exist but are too small for the multi-environment
  behavior the user wants.
- Execution supervisor tests exist but should grow around timeout semantics,
  child-process cleanup, VPN lifecycle, and partial-output failure states.

### Silent Exception And Error-Handling Surface

Static grep found 130 matches across `except Exception`, `pass`, `TODO/FIXME`,
`dangerous=False`, shell literals, and persistence calls. Not all are defects.
The risky clusters are:

- UI clearing and input handling, where swallowed exceptions can hide `ctrl+o`
  or prompt redraw failures.
- `_run_cmd` cleanup paths, where swallowed cleanup exceptions can leave child
  processes.
- persistence and settings writes, where ignored `OSError` can make state
  appear saved when it is not.
- hooks/MCP/LLM generic exception paths, where operational errors can become
  vague model/provider messages.

Implementation rule:

- Do not broadly remove all `except Exception`.
- For P43-P47, convert only user-visible or security-relevant silent failures
  into structured errors, trace events, or deterministic fallbacks.

### Confirmed P0: `ssl_audit` Shell Injection Risk

File: `secops_agent/tools/crypto.py`

Observed:

- `ssl_audit` is declared `dangerous=False`.
- Fallback path builds:

```python
[
    "bash",
    "-c",
    "echo | openssl s_client ... 2>&1 | head -5",
]
```

Risk:

- A hostile target string can alter the local shell command.
- Because the tool is non-dangerous, the user may not see an approval prompt in
  default modes.

Required fix:

- Parse and validate `host:port` strictly.
- Replace `bash -c` pipeline with `asyncio.create_subprocess_exec` or a helper
  that does not shell-expand untrusted input.
- If `head -5` behavior is needed, trim output in Python.
- Add test: hostile `target` containing `;`, backticks, `$()`, newline, and
  redirection does not execute an extra command and returns validation error.

### Confirmed P0: Backtick Sudo Detection Gap

Files:

- `secops_agent/core/sudo.py`
- `secops_agent/core/permissions.py`

Observed safe import check:

```text
echo `sudo id` -> command_uses_sudo False, executables ['echo']
echo $(sudo id) -> command_uses_sudo False, executables ['echo', 'sudo']
sudo id -> command_uses_sudo True, executables ['sudo']
bash -lc "sudo id" -> command_uses_sudo False, executables ['sudo']
```

Risk:

- Sudo preflight and command approval can disagree.
- Backtick substitution is the clearest local bypass.

Required fix:

- Treat any command substitution marker as high-risk unless parsed safely.
- Add a shell parser helper that extracts nested commands from both `$()` and
  backticks or rejects commands containing command substitutions.
- Make sudo detection use the same resource extraction path as command
  permission.

### Confirmed P0: File Permission Policy Not Enforced By Agent Path

Files:

- `secops_agent/core/agent.py`
- `secops_agent/core/permissions.py`
- `secops_agent/tools/forensics.py`

Observed:

- `PermissionEngine.check_tool_permission()` can make argument-aware decisions.
- The agent execution path calls `evaluate_tool(tc.name, tool_def.dangerous)`.
- `file_analyze('/etc/shadow')` style tools are non-dangerous and can bypass
  argument-aware file policy.

Required fix:

- Replace or augment `evaluate_tool()` call with an argument-aware permission
  decision.
- Normalize tool names:
  - code currently checks `file_analysis`;
  - registered tool is `file_analyze`.
- Add tests for `/etc/shadow`, `~/.ssh/id_rsa`, `.env`, large logs, and
  workspace-allowed reads.

### Confirmed P1: Resume Transcript Is Unbounded

Files:

- `secops_agent/ui/renderer.py`
- `secops_agent/main.py`

Observed:

- `render_session_transcript(memory, max_messages=None)` supports a bound.
- `/resume`, `/load`, and `--session` call paths do not consistently pass a
  limit.

Risk:

- Long sessions can flood terminal output and make resumed sessions feel broken.

Required fix:

- Default visible replay to a bounded window.
- Render a compact line like:

```text
  ... 184 previous messages hidden. Use /history or /resume --full to review.
```

Only add a new command/flag if explicitly selected; otherwise use existing
history/artifact surfaces.

### Confirmed P1: `ctrl+o` Anchor Can Survive Session Load

Files:

- `secops_agent/ui/runtime.py`
- `secops_agent/ui/input_handler.py`
- `secops_agent/ui/renderer.py`

Observed:

- `reset_ctrl_o_surface(clear_anchor=False)` only clears anchor when requested.
- `load_session_dict()` calls it without `clear_anchor=True`.
- Idle and streaming `ctrl+o` use separate code paths.

Required fix:

- Clear anchor on session load/resume.
- Add PTY test:
  - run a tool;
  - expand/collapse;
  - resume another session;
  - press `ctrl+o`;
  - assert old tool output does not reappear.

### Confirmed P1: VPN Ownership And State Are Too Broad

File: `secops_agent/tools/forensics.py`

Observed:

- OpenVPN is launched through `bash -lc` background command and PID echo.
- Success may be inferred from any TUN interface.
- Disconnect can kill all OpenVPN processes.

Required fix:

- Capture pre-existing TUN interfaces before launch.
- Treat success as "new expected PID is running and expected TUN/log status
  appeared".
- Write PID/status files using OpenVPN `--writepid` and `--status` when
  possible.
- Disconnect only SecOps-owned PIDs/configs by default.
- Offer "disconnect all OpenVPN processes" only as explicit high-risk action.

### Confirmed P1: Hooks And Skills Need Trust Boundaries

Files:

- `secops_agent/core/hooks.py`
- `secops_agent/core/extensions.py`
- `secops_agent/core/llm.py`

Observed:

- Hook strings become `bash -lc`.
- Workspace/global hooks can be active.
- Skill Markdown can become system-level instruction text.

Required fix:

- Add manifest trust status: untrusted, trusted-workspace, trusted-global.
- Default: untrusted hooks disabled.
- Skill instructions from workspace should be wrapped as untrusted context
  until explicitly trusted.
- Add tests for malicious hook and malicious skill text.

## Reprioritized Implementation Queue

### P43 - Local Execution Security Hotfixes

Priority: P0

Scope:

- Fix `ssl_audit` shell injection.
- Fix command substitution and sudo detection consistency.
- Enforce argument-aware file permission policy.
- Normalize file tool names in policy.
- Add unit tests for all three issues.

Acceptance:

- `ssl_audit("example.com:443; id")` validates and rejects or treats the
  string as data without shell execution.
- `echo `sudo id`` and `echo $(sudo id)` both require sudo/command approval or
  are rejected as unsafe.
- `file_analyze('/etc/shadow')` and `log_analyze('/etc/shadow')` are ASK/DENY
  before any read.
- Full tests pass.

### P44 - Agentic Extension Governance

Priority: P1

Scope:

- Add a minimal extension trust model for hooks, skills, and MCP startup.
- Disable untrusted workspace hooks by default.
- Gate MCP server startup with permission and environment allowlist.
- Treat workspace skill instructions as untrusted until approved.
- Add value-based secret redaction for traces and persisted tool metadata.

Acceptance:

- A malicious `.agents/hooks.json` does not execute silently.
- A malicious skill cannot rewrite safety or permission instructions as
  privileged system policy.
- MCP startup has an approval record before launching external processes.
- Trace/session exports redact key-shaped and value-shaped secrets.

### P45 - Resume And `ctrl+o` State Hardening

Priority: P1

Scope:

- Clear `ctrl+o` anchor state on `/resume`, `/load`, `--session`, and `/clear`.
- Bound visible transcript replay.
- Add PTY scenarios for:
  - old anchor after resume;
  - no-session resume;
  - long transcript replay;
  - tool result followed by plain assistant answer then `ctrl+o`.

Acceptance:

- `ctrl+o` expands in place when possible, or falls back to a documented
  overlay without appending duplicate transcript rows.
- Old tools do not reappear after loading another session.
- Long sessions resume with a bounded visible transcript.

### P46 - VPN Supervisor And Ownership Model

Priority: P1

Scope:

- Replace background shell launch with a supervised or pidfile-based process
  path.
- Use OpenVPN `--writepid`, `--status`, and explicit log path when available.
- Record SecOps-owned VPN sessions in runtime/session metadata.
- Disconnect only owned VPN processes by default.
- Add stale, blocked-by-network, connected, disconnected, failed states.

Acceptance:

- A blocked UDP/1194 network is explained as network reachability, not as a
  sudo/tool failure.
- A pre-existing user VPN does not produce a false success for a new SecOps
  VPN connection.
- Disconnect does not kill unrelated OpenVPN processes unless explicitly
  selected.

### P47 - Long-Running Tool Consistency

Priority: P1

Scope:

- Migrate long `_run_cmd` paths to supervisor or supervisor-light behavior.
- Ensure partial stdout plus timeout is represented as incomplete/timeout.
- Standardize status marker color by execution status:
  - running: amber/yellow;
  - success: green;
  - failure: red;
  - canceled/interrupted: red/warning;
  - permission/sudo waiting: neutral/warning.
- Keep collapsed output by default with deterministic spool review.

Acceptance:

- Silent commands emit periodic progress.
- `Esc` cancels the process group.
- Timed-out tools are never parsed as complete success.
- `ctrl+o` reads the existing tool record, not a duplicate row.

### P48 - Engagement Context And Strict Scope

Priority: P1

Scope:

- Persist an `EngagementContext` in mission:
  - platform hint;
  - objective;
  - authorization basis;
  - in-scope and out-of-scope;
  - allowed techniques;
  - stop conditions;
  - data sensitivity policy.
- Make environment labels secondary to technical task classification.
- Make no-scope network actions ask for scope before active scanning.
- Include scope constraints in LLM context.

Acceptance:

- Same prompt shape works across CTF, private VM, and authorized assessment
  without confusing the technical step.
- Out-of-scope targets are blocked before execution.
- The agent can explain why it proposed, asked, or refused.

### P49 - Reviewed Playbook Curriculum

Priority: P2

Scope:

- Build a reviewed playbook layer from curated sources and experience memory.
- Inputs can include:
  - PortSwigger Academy topics;
  - HTB Academy module concepts;
  - TryHackMe/Root-Me replay prompts;
  - IppSec multi-service reasoning examples;
  - NahamSec recon workflow patterns;
  - LiveOverflow binary exploitation learning tracks.
- Each playbook must define:
  - preconditions;
  - evidence to collect;
  - safe next action;
  - risky boundary;
  - failure modes;
  - privacy redaction;
  - replay fixture.

Acceptance:

- A known pattern can influence suggestions without auto-running actions.
- The agent explains "why this resembles a known pattern" with confidence.
- Lab flags, credentials, and raw shell output are not stored as reusable
  playbook data.

### P50 - Tool Adapter Contract

Priority: P2

Scope:

- Define a `ToolAdapter` schema for installed and optional external tools.
- Start with read-only/supporting adapters before exploit-heavy paths:
  - `httpx`;
  - `ffuf`/`gobuster`/`feroxbuster`;
  - `subfinder`;
  - `naabu`;
  - `nuclei` safe templates;
  - `zap` baseline/passive.
- Tool absence should produce:
  - what is missing;
  - what it is useful for;
  - install command proposal;
  - risk and sudo requirement;
  - "install now?" only after user asks or selects install.

Acceptance:

- Missing wordlist/tool errors become useful next actions.
- The agent proposes installation when appropriate, but does not jump to `sudo`
  without user selection.
- Parsers consume structured JSON where available.

### P51 - Vulnerability Intelligence Enrichment

Priority: P2

Scope:

- Add a separate candidate-intel module for NVD, EPSS, and optional KEV.
- Cache results locally.
- Map service/version to candidate CVEs with confidence.
- Report candidate references separately from validated findings.

Acceptance:

- CVE/EPSS/KEV enriches prioritization only.
- No active exploit or payload starts from intel alone.
- Offline mode degrades cleanly.

### P52 - TUI Evidence Baseline

Priority: P2 after P43-P47

Scope:

- Re-run SecOps PTY captures at multiple sizes.
- Keep AGY comparison focused only on concrete mismatches.
- Cover:
  - slash palette backspace and pagination;
  - settings;
  - permission prompt;
  - resume;
  - `ctrl+o`;
  - long-running tools;
  - VPN.

Acceptance:

- Evidence is stored under `docs/evidence/`.
- Each TUI regression has a stable reproduction.

## What This Means For The Next Step

The next implementation step should be P43.

P43 is small enough to complete in slices and high enough risk to justify
interrupting the TUI baseline plan:

1. Patch `ssl_audit`.
2. Patch command substitution/sudo detection.
3. Patch file permission enforcement.
4. Add focused tests.
5. Run compileall and unittest.

After P43, return to P45/P46/P47, then P48.

## Verification Commands For Future Slices

Use these after each implementation slice:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent tests scratch
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
```

For TUI changes:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 .venv/bin/python \
  scratch/tui_smoke.py --timeout 10 --rows 34 --cols 120
```

For command permission changes, add targeted tests before broad runs:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_agent_permissions.py
```

## Night Pass 2 - Deeper Source/Research Findings

Timebox note: this pass continued after the first deep addendum and focused on
the exact regressions observed in live use: resume transcript, ctrl+o placement,
sudo/VPN, long-running progress, proposal-first behavior, and experience memory.

### Additional External Evidence Reviewed

Agent security and governance:

- OWASP AI Agent Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
  - It frames AI agents as systems that reason, plan, use tools, keep memory,
    and act; the key risks include tool abuse, memory poisoning, excessive
    autonomy, high-impact action abuse, and decision/approval manipulation.
  - It recommends least privilege, per-tool permission scoping, isolated tool
    sets by trust level, explicit authorization for sensitive operations,
    memory validation, memory expiry/size limits, human-in-the-loop controls,
    action previews, interruption, rollback, and audit trails.
- OWASP MCP Tool Poisoning:
  https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
  - Tool responses are untrusted runtime channels, not trusted instructions.
  - Prevention maps directly to SecOps: schema validation, isolate privileged
    tools, enforce restrictions in the execution layer, allowlist MCP servers,
    and require out-of-model confirmation for sensitive operations.
- OWASP Agentic Skills Top 10:
  https://owasp.org/www-project-agentic-skills-top-10/
  - Skills are the execution layer; governance requires verified publishers,
    permission manifests, isolation, network restrictions, monitoring, approval
    workflows, and incident response.
- OWASP APTS Scope Enforcement:
  https://owasp.org/APTS/standard/1_Scope_Enforcement/
  - APTS-SE-001 through APTS-SE-006 require machine-parseable Rules of
    Engagement, IP/domain/time validation, asset criticality, and pre-action
    scope validation. This supports an explicit EngagementContext rather than
    hidden environment modes.

CLI and long-running UX:

- CLI Guidelines: https://clig.dev/
  - Use color intentionally; if everything is colored, color loses meaning.
  - Use pagers for lots of text only in interactive terminals.
  - Keep Ctrl-C/escape paths clear for hung network operations.
  - Be careful with parallel progress because interleaved output confuses users.
- Rich progress: https://rich.readthedocs.io/en/latest/progress.html
  - Good long-running UX tracks task description, percentage/elapsed/remaining
    and supports multiple concurrent tasks. SecOps already has the supervisor
    foundation, but not every tool path uses it.

Research on pentest agents:

- PentestEval: https://arxiv.org/abs/2512.14233
  - End-to-end pentest agents are weak when treated as black-box autonomy;
    stage-level decomposition and modular evaluation are required.
- xOffense: https://arxiv.org/abs/2509.13021
  - Multi-agent orchestration by phase improves completion rates, but should be
    adapted carefully because SecOps is intentionally proposal-first.
- RapidPen: https://arxiv.org/abs/2502.16730
  - ReAct + retrieval of success cases can improve IP-to-shell performance;
    for SecOps this supports a reviewed playbook layer, not hidden autopilot.

Tools and source-compatible adapters:

- Nuclei:
  https://github.com/projectdiscovery/nuclei
  - Relevant because it supports YAML templates, JSONL output, SARIF/Markdown
    export, template protocol types, stats JSONL, and redaction flags.
- Nuclei Templates:
  https://github.com/projectdiscovery/nuclei-templates
  - Relevant because templates include severity, CVE, KEV-style coverage, and
    a community review workflow; useful only as candidate validation, not as
    automatic exploitation.
- httpx:
  https://github.com/projectdiscovery/httpx
  - Relevant because JSONL output can feed deterministic parsers.
- subfinder:
  https://github.com/projectdiscovery/subfinder
  - Passive subdomain enumeration, multiple output formats, STDIN/STDOUT
    workflow integration.
- naabu:
  https://github.com/projectdiscovery/naabu
  - Fast port discovery; should complement, not replace, Nmap versioning.
- katana:
  https://github.com/projectdiscovery/katana
  - Crawling/spidering with scope controls and JSON output; useful for web
    discovery only with strict scope.
- ffuf:
  https://github.com/ffuf/ffuf
  - Fast web fuzzing/content discovery; needs bounded profiles and progress.
- feroxbuster:
  https://github.com/epi052/feroxbuster
  - Recursive content discovery; high value but should be opt-in and bounded.

Training and playbook sources:

- PortSwigger Web Security Academy:
  https://portswigger.net/web-security/all-topics
  - Strong source for web vulnerability playbooks: SQLi, authentication, path
    traversal, command injection, access control, file upload, SSRF, XSS, API
    testing, request smuggling, JWT, OAuth, prototype pollution, and Web LLM
    attacks.
- HTB Academy FAQ:
  https://academy.hackthebox.com/faq
  - Confirms the guided/exploratory lab model, hands-on targets, VPN keys, and
    browser/Pwnbox workflows. This reinforces that SecOps should track lab
    readiness separately from exploit intent.
- TCM Practical Ethical Hacking:
  https://tcm-sec.com/academy/practical-ethical-hacking/
  - Good broad curriculum source for beginner-to-practical methodology mapping.
- YouTube source index:
  - IppSec: https://www.youtube.com/c/ippsec and https://ippsec.rocks/
  - John Hammond: https://www.youtube.com/@_JohnHammond
  - LiveOverflow: https://www.youtube.com/LiveOverflow
  - NahamSec: https://www.youtube.com/@NahamSec
  These should feed a curated learning/playbook index, not model context
  directly. Video-derived tactics must become reviewed deterministic playbooks
  with source, prerequisites, failure modes, and safe stop conditions.

Vulnerability intelligence:

- NVD CVE API:
  https://nvd.nist.gov/developers/vulnerabilities
  - Supports CVE lookup, CPE-based search, pagination, KEV filters, CVSS
    severity filters, date windows, and keyword search.
- FIRST EPSS:
  https://www.first.org/epss/
  - Provides a daily 0-1 probability and percentile for exploitation in the
    wild; use it as prioritization, never as exploit authorization.
- MITRE ATT&CK:
  https://attack.mitre.org/
  - Useful as a taxonomy for tactics/techniques/evidence mapping. It should not
    be used to push the agent into offensive chaining by itself.

### Source Finding - Proposal-First Is Present But Needs Harder Boundaries

Current state:

- `secops_agent/core/agent.py:175-199` defaults
  `max_chained_actions_per_turn=0` and
  `allow_automatic_planner_execution=False`.
- `secops_agent/core/agent.py:1466-1495` still contains the automatic planner
  chain path when the explicit flag is enabled.
- `secops_agent/core/agent.py:1516-1519` turns post-tool LLM continuation into
  text-only when automatic planner execution is disabled.
- `secops_agent/core/planner.py:133-142` explicitly says suggestions are
  candidate actions only.

Assessment:

- The design direction is correct: proposal-first by default.
- The missing hard boundary is not code execution in normal defaults; it is
  governance around when `allow_automatic_planner_execution` can ever be
  enabled, and how visible that mode is to the user.

Required plan update:

- P48 should include an `autonomy_level` or `execution_mode` persisted in
  EngagementContext:
  - `answer_only`;
  - `single_action`;
  - `proposal_first` default;
  - `approved_batch`;
  - `autopilot_lab` disabled unless explicitly selected.
- Session permissions must never imply orchestration intent.
- Automatic planner execution, if retained for tests, must require an explicit
  visible state and should be disabled in normal interactive UX.

### Source Finding - Scope Model Is Useful But Still Too Permissive By Default

Current state:

- `secops_agent/core/mission.py:199-230` stores `Scope` with `in_scope`,
  `out_of_scope`, and `rules`.
- `Scope.is_in_scope()` returns true when no explicit in-scope entries exist
  except for explicit out-of-scope blocks.
- `secops_agent/core/scope_guard.py:84-107` blocks tool calls whose extracted
  target is outside scope.
- `secops_agent/core/request_context.py:51-55` defines `OUT_OF_SCOPE`.
- `secops_agent/core/request_context.py:174-179` never emits `OUT_OF_SCOPE`;
  any explicit target is treated as `EXPLICIT`.

Assessment:

- APTS requires pre-action scope validation and machine-parseable RoE before
  autonomous testing. Current `Scope.is_in_scope()` is intentionally permissive
  for interactive behavior, but that conflicts with higher assurance operation.
- `OUT_OF_SCOPE` exists as an enum but is not yet part of request
  classification. The execution guard can still block, but the LLM does not
  receive a precise "this request is out of scope" signal early.

Required plan update:

- Add explicit strictness levels:
  - `interactive_permissive` for early chat/local help;
  - `engagement_strict` once a mission scope is declared;
  - `high_risk_strict` for active scans, exploit validation, shell, VPN, and
    file access.
- Request classification must compare explicit target against mission scope and
  emit `OUT_OF_SCOPE` before the model produces a plan.
- The LLM context should include scope status, allowed targets, denied targets,
  and stop conditions in a compact form.

### Source Finding - Experience Memory Needs Environment-Neutral Compatibility

Current state:

- `secops_agent/core/experience.py:477-502` retrieves lessons by token overlap
  plus action match.
- `secops_agent/core/experience.py:505-553` builds lessons from tool results.
- `secops_agent/core/experience.py:605-618` derives platform tags from mission
  name tokens such as TryHackMe, HTB, RootMe, CTF.
- `secops_agent/core/planner.py:896-926` can turn planner lessons into chained
  calls only if the explicit chain path is enabled, but lessons still influence
  ranking through `planner.plan()`.

Assessment:

- The user concern is valid: "what ports are open?" looks the same in CTF,
  private VM, and client audit. Environment labels should not decide behavior.
- The current lesson system can still overfit on token overlap. A TryHackMe
  upload lesson should not rank a private VM path unless the technical
  fingerprint matches: service, version, endpoint shape, response code, parser
  evidence, and preconditions.

Required plan update:

- Replace platform-based lesson retrieval with compatibility gates:
  - same technical goal;
  - same service family;
  - compatible endpoint evidence;
  - compatible failure mode;
  - compatible authorization/risk class;
  - no sensitive/flag/credential data.
- Environment tags remain explanatory metadata only.
- Store lesson confidence as a reasoned score with match components, not only
  token overlap.

### Source Finding - Result Parser Suggestions Are Useful But Too Imperative

Current state:

- `secops_agent/core/result_parser.py:482-506` emits next-step strings such as
  "Run dir_brute on web services" and "Run nikto_scan".
- `secops_agent/core/result_parser.py:509-626` parses directory brute-force
  output and turns interesting paths into findings.
- `secops_agent/core/planner.py:392-498` turns missing tools, timeouts, host
  discovery failures, and empty discovery into corrective actions.

Assessment:

- Parser-derived next steps should be evidence annotations, not commands. The
  deterministic planner is the right place to turn evidence into candidate
  actions with risk and approval metadata.
- Wording like "Run ..." should become "Candidate: ..." or stay internal to
  structured suggestions. This matches the user preference: propose, do not
  chain.

Required plan update:

- Rename parser `next_steps` concept to `observed_followups` or
  `candidate_followups`.
- Ensure UI rendering of suggestions uses normalized numbering:
  `1. Text`, never mixed `1 Text` or `1.[Text]`.
- Keep risk labels visually quiet; only command/tool name or shortcut gets
  accent color.

### Source Finding - Ctrl+O Has Three Competing Surfaces

Current state:

- Runtime stores artifact expansion, transcript expansion, and anchored tool
  block state separately in `secops_agent/ui/runtime.py:132-142`.
- `RuntimeState.reset_ctrl_o_surface()` clears transcript state but clears the
  anchor only when `clear_anchor=True` (`runtime.py:144-152`).
- `RuntimeState.load_session_dict()` calls `reset_ctrl_o_surface()` without
  clearing the anchor (`runtime.py:285-314`).
- `Renderer.render_agent_stream()` sets a current turn transcript cache and
  then calls `runtime.set_ctrl_o_anchor()` for the latest tool
  (`renderer.py:4788-4806`).
- `InputHandler._show_ctrl_o_surface()` prefers anchored rewrite, then current
  transcript, then latest artifact fallback (`input_handler.py:651-683`).
- `_toggle_anchored_ctrl_o_surface()` refuses to rewrite in place if the target
  block is too far above the current viewport (`input_handler.py:570-577`).

Assessment:

- This explains the live behavior: if the old anchor is stale, too far away, or
  has an incorrect tail-line count, ctrl+o falls through and can render a
  duplicate at the bottom via artifact/transcript fallback.
- Session load/resume should not preserve interactive anchor state. It should
  preserve durable artifacts and transcript, then initialize a fresh "latest
  visible expandable block" only after replay.

Required plan update:

- P45 should split durable and ephemeral ctrl+o state:
  - durable: latest tool artifact metadata, transcript text if intentionally
    saved;
  - ephemeral: terminal line counts, anchor tail distance, currently expanded
    rows.
- On `/resume`, `/load`, `--session`, `/clear`, and `add_artifact`, call
  `reset_ctrl_o_surface(clear_anchor=True)`.
- Add PTY tests for:
  - ctrl+o immediately after latest tool;
  - ctrl+o after assistant text following latest tool;
  - ctrl+o after a new plain turn with no tool;
  - ctrl+o after `/resume` transcript replay;
  - too-far-above anchor fallback should show "Nothing to expand yet" or open
    `/trajectory`, not duplicate a stale block.

### Source Finding - Resume Replays Transcript But Does Not Treat It As A View

Current state:

- `Renderer.render_session_transcript()` can replay user, model, and tool
  messages from memory (`renderer.py:3898-3979`).
- `/resume` loads memory/runtime, restores artifacts, and calls
  `render_session_transcript(agent.memory)` (`main.py:1278-1305`).
- Preloaded session startup also calls `render_session_transcript()` without
  a bound or navigation surface (`main.py:886-889`).

Assessment:

- SecOps does replay visible transcript, but it is a one-shot dump, not an
  interactive session view. AGY-like resume feels different because the user
  returns to a visible conversation surface where the transcript and current
  prompt are coherent.
- Long sessions will dump too much content because `max_messages` exists but is
  not used on resume paths.

Required plan update:

- P45 should introduce a bounded resume replay policy:
  - default: replay last N visible turns plus a compact "loaded earlier
    messages" marker;
  - `/trajectory` remains full session view;
  - optional explicit full replay through a session view, not automatic dump.
- The replay renderer must rebuild ctrl+o cache for the latest displayed tool
  or explicitly say no current expandable block.

### Source Finding - VPN Handling Improved But Still Needs Ownership Metadata

Current state:

- `connect_vpn_config()` searches for `.ovpn/.conf`, verifies OpenVPN,
  checks sandbox and sudo, then starts `nohup sudo -n openvpn --config ...`
  in background (`forensics.py:725-890`).
- It watches logs and TUN addresses until connected/failed/started
  (`forensics.py:820-858`).
- It detects TLS handshake failure and recommends changing network or TCP
  configs (`forensics.py:196-204`, `forensics.py:878-881`).
- `disconnect_vpn()` discovers all OpenVPN processes and kills them by PID
  (`forensics.py:685-722`).

Assessment:

- The network/firewall explanation now matches the user’s live experience:
  first network blocked UDP/1194, second network allowed the handshake.
- The remaining risk is ownership. Disconnecting "OpenVPN process(es)" can
  affect VPNs not launched by SecOps. Connect success can also be confused by
  a pre-existing active TUN unless the tool records which process/config it
  owns.

Required plan update:

- P46 must add OpenVPN metadata:
  - SecOps-owned PID file;
  - config path;
  - log path;
  - connect timestamp;
  - pre-existing TUN snapshot;
  - OpenVPN `--writepid` and `--status` where possible.
- `disconnect_vpn()` should stop owned VPN only by default.
- "Kill all OpenVPN" should be a high-risk explicit option, not default.

### Source Finding - Long-Running Progress Foundation Exists But Is Uneven

Current state:

- `ExecutionSupervisor.run_shell()` supports process groups, spool files,
  output progress, idle reports, max runtime, inactivity timeout, cancellation,
  and process-group termination (`execution.py:70-253`).
- `run_cmd_streaming()` wraps the supervisor and records spool metadata
  (`helpers.py:74-137`).
- `nmap_scan()` uses `_run_cmd_streaming()` with 300s runtime and 120s
  inactivity timeout (`network.py:67-87`).
- Many smaller tools still call `_run_cmd()` which uses simple
  `asyncio.wait_for(proc.communicate())` and kills only the direct process
  (`helpers.py:21-71`).
- `run_shell()` uses the supervisor and preserves timeout/spool metadata
  (`forensics.py:442-525`).

Assessment:

- The "Codex/Claude/AGY feel better on long commands" gap is not the absence
  of a supervisor. It is inconsistent adoption and inconsistent rendering.
- `_run_cmd()` is fine for truly small commands, but unsafe for tools that
  can spawn children, block on network, or emit intermittent output.

Required plan update:

- P47 should classify each tool call path:
  - instant local read;
  - bounded local command;
  - network command;
  - long-running supervised command;
  - background service.
- Network and long-running commands must use supervisor or an equivalent
  process-group owner.
- Timeout must always become a structured failure finding with spool path, even
  when partial stdout exists.

### Source Finding - Sudo Detection Still Misses Some Shell Forms

Current state:

- `secops_agent/core/sudo.py:29-30` detects sudo with a regex limited to start
  or separators `;`, `&`, `|`.
- Shell command resources are extracted through
  `_extract_shell_executables()` in `permissions.py`, then used by
  `scope_guard.py:124-135`.
- Previous direct checks showed nested command substitutions like
  ``echo `sudo id` `` and `echo $(sudo id)` are not reliably classified as
  sudo commands by `command_uses_sudo()`.

Assessment:

- For an agent that can run `run_shell`, sudo detection must be parser-based
  enough to catch command substitutions, `bash -lc`, and nested invocations.
- The permission UI should ask for the normalized executable/prefix that
  actually matters, not a huge full command string unless that is the safest
  resource boundary.

Required plan update:

- P43 should add shell parsing tests before code change:
  - direct sudo;
  - chained sudo;
  - `$(sudo ...)`;
  - backtick sudo;
  - `bash -lc "sudo ..."`;
  - quoted non-command text containing "sudo" should not trigger.
- Use a structured command analyzer shared by:
  - sudo precheck;
  - permission resources;
  - scope guard;
  - approval prompt display.

### Source Finding - Tool Adapter Contract Should Prefer Structured Outputs

Current state:

- Existing parsers support Nmap, dir brute, Nikto, CVE, WHOIS, HTTP headers,
  technology detection, and operational blockers.
- External research shows several candidate tools support JSON/JSONL:
  - nuclei `-jsonl`;
  - httpx `-json`;
  - katana `-json` / JSONL output;
  - subfinder `-oJ` JSONL output;
  - nuclei stats JSONL.

Assessment:

- Adding tools one-by-one as ad hoc shell wrappers will multiply parsing
  problems. A `ToolAdapter` contract should define command build, risk,
  expected output format, parser, progress profile, install detection, and
  scope extraction.

Required plan update:

- P50 should start with structured, read-only adapters:
  - `httpx` for web probes;
  - `subfinder` for passive subdomains;
  - `katana` scoped crawl;
  - `ffuf` or `feroxbuster` bounded content discovery;
  - `nuclei` safe/passive or low-risk templates only.
- Adapter acceptance must include:
  - JSON parser tests;
  - missing-tool proposal;
  - bounded timeout/progress;
  - scope enforcement;
  - no hidden install.

Night pass update:

- ProjectDiscovery official docs confirm JSON/JSONL flags for the first adapter
  candidates:
  - `httpx`: `-json` writes JSONL output and can include response headers in
    JSON output;
  - `subfinder`: `-oJ` writes JSONL output and can include source attribution;
  - `katana`: `-json`/JSONL output is supported for crawler results;
  - `nuclei`: `-jsonl` output is supported for scan results.
- This makes them better first adapters than tools that only print
  human-formatted output.

## Reprioritized Queue After Night Pass 2

The sprint order remains similar, but the acceptance criteria are now sharper:

1. P43 local execution security:
   - `ssl_audit`;
   - shell/sudo analyzer;
   - file path permission enforcement;
   - strict tests.
2. P45 resume/ctrl+o:
   - clear ephemeral anchor state on load;
   - bounded transcript replay;
   - PTY tests around exact live regressions.
3. P46 VPN ownership:
   - owned PID/log/status metadata;
   - disconnect owned VPN by default;
   - explicit high-risk kill-all.
4. P47 long-running consistency:
   - supervisor adoption matrix;
   - process-group cleanup;
   - timeout as structured failure.
5. P48 engagement context:
   - scope/RoE/autonomy level/stop conditions;
   - request matrix across CTF, HTB, Root-Me, private VM, and authorized audit.
6. P49 reviewed playbooks:
   - convert courses/videos/writeups to deterministic playbooks with evidence
     and safety boundaries.
7. P50 tool adapters:
   - structured JSON-first external tools.
8. P51 vulnerability intelligence:
   - NVD/EPSS/KEV as prioritization only.

No implementation should start until the selected slice is named. The safest
first slice is still P43 because it reduces the risk of local execution mistakes
before more UX or capability work.

## Night Pass 3 - Subagent Integration And Timeout Correction

Two independent code-only subagent reviews were integrated after the previous
pass. They confirm the plan direction, but one finding needs a precise wording
correction.

### Integrated Finding - `ctrl+o` Needs Render Records, Not Only State Reset

Subagent finding:

- Session persistence writes message history and runtime metadata, but resume
  reconstructs a transcript from messages rather than replaying exact rendered
  records.
- `ctrl+o` uses several state sources:
  - live renderer state while streaming;
  - `RuntimeState.ctrl_o_*`;
  - anchored prompt rewrite state;
  - transcript fallback;
  - artifact fallback.
- `RuntimeState.set_ctrl_o_anchor()` sets `ctrl_o_anchor_tail_lines = 0`.
  If a tool row is followed by assistant text, later `ctrl+o` may not know how
  many lines exist between the tool row and the current prompt.
- `reset_ctrl_o_surface()` clears the anchor only when called with
  `clear_anchor=True`; several context changes use the default path.
- Tool/result association during transcript rebuild is name-based enough to be
  fragile when multiple calls have the same display name.

Plan impact:

- P45 remains a TUI priority, but the acceptance bar is higher:
  - clear stale anchors on context changes;
  - track tail lines after the latest expandable tool;
  - add bounded transcript replay;
  - start a render-record journal or equivalent transcript model;
  - associate tool calls and tool results by id wherever possible.

Additional test nuance:

- Existing TUI tests already cover anchored rewrite when
  `runtime.advance_ctrl_o_anchor_lines()` is called manually.
- The missing regression is an end-to-end stream test where:
  - a tool result is rendered;
  - assistant text is rendered after that tool;
  - the prompt returns;
  - `ctrl+o` expands the earlier tool in place.
- That test should fail if `render_agent_stream()` sets the latest tool anchor
  at the end of the turn with `ctrl_o_anchor_tail_lines = 0`.

### Integrated Finding - Privileged Execution Is Split Across Paths

Subagent finding:

- `run_shell` has the most complete flow:
  - tool permission;
  - command permission;
  - sudo precheck;
  - optional local password authentication;
  - supervised execution.
- VPN tools implement a separate privileged path. `connect_vpn_config()` checks
  sandbox and non-interactive sudo itself, then launches OpenVPN through
  `nohup sudo -n ... & echo $!`.
- In sandbox mode, `sudo` can be blocked even after an approval surface is
  shown, creating the impression that permission was granted but execution is
  still impossible.
- `disconnect_vpn()` can kill OpenVPN processes discovered locally instead of
  defaulting to a SecOps-owned process record.

Plan impact:

- P43 now includes permission/sudo UI alignment across `run_shell`, VPN, and
  internal privileged tools.
- P46 must replace the `nohup ... & echo $!` path with an owned background
  process contract, including PID/config/log/status metadata and cancellation
  cleanup.

### Corrected Finding - ToolRegistry Timeout Is Partly Present But Underdeclared

Initial wording:

- "The registry default timeout cuts long tools at 120 seconds."

Corrected source reading:

- `ToolRegistry._execution_timeout()` starts from `settings.TOOL_TIMEOUT`.
- It can extend the timeout when the tool arguments include `timeout` or the
  tool parameter schema defines a `timeout` default.
- It also has a special long-running-shell heuristic for `run_shell`.
- However, long native tools such as `nmap_scan`, `dir_brute`, and
  `nikto_scan` call `_run_cmd_streaming()` with internal 300s/600s timeouts
  but do not expose matching `timeout` defaults in their tool schemas.

Assessment:

- The problem is not absence of registry timeout logic.
- The problem is that long-running tool budgets are not declared in the tool
  contract consumed by the registry.

Plan impact:

- P47 should add an explicit runtime budget field to the tool contract, or make
  existing `timeout` defaults mandatory for long-running tools.
- Acceptance should verify that a 300s/600s supervised tool is not cancelled by
  the outer registry before the internal supervisor budget.

### Integrated Finding - `_run_cmd` Should Stay Only For Short Noninteractive Reads

Subagent finding:

- `ExecutionSupervisor` has strong process-group cleanup, spool files,
  progress, inactivity timeout, and cancellation handling.
- `_run_cmd()` inherits stdin, kills only the direct process on timeout, and
  does not use process-group cleanup.
- `sysinfo(users)` uses `sudo -l` in a non-dangerous information tool through
  `_run_cmd(["bash", "-c", ...])`; even with stderr redirection, this is a bad
  pattern for noninteractive helpers.

Plan impact:

- P47 should classify every local command helper:
  - pure file/process read;
  - short noninteractive command;
  - shell command with metacharacters;
  - long network command;
  - background service.
- `_run_cmd()` should use `stdin=DEVNULL`, clean up robustly, and never host
  interactive sudo probes.
- Any shell-spawning or long-running path should move to supervisor or an
  equivalent owner.

### Integrated Finding - Provider Tool Schema Is Better, But Needs A Contract

Current state:

- `GeminiProvider._build_config()` builds Gemini function declarations from
  registered tool schemas.
- It avoids mixing Google Search grounding with function declarations in the
  same request.
- It filters invalid function names before sending them to the provider.
- Tests already cover schema conversion, invalid function names, warning
  suppression, and compact API errors.

Assessment:

- The "AFC disabled" and `400 INVALID_ARGUMENT` errors observed in live runs
  are not only UX noise; they show that provider-facing tool schemas must be a
  first-class compatibility contract.
- External adapters should not be added until schema conversion tests cover
  names, parameter types, required arguments, enums, nested objects, nullable
  values, and provider-specific restrictions.

Plan impact:

- P50 should include a provider-schema acceptance suite for every new tool
  adapter.
- Tool schema failures should be shown as a compact local compatibility error,
  not as raw SDK warnings.

### Integrated Finding - Skills, Hooks, And MCP Are Real Trust Boundaries

Current state:

- Markdown skills are loaded from workspace and global directories, bounded by
  count and character limits, then injected into the model's system context.
- Hooks load from workspace/global JSON files and can execute list commands or
  shell strings through `bash -lc`/`sh -c`.
- MCP servers are loaded from workspace/global config files, started as local
  subprocesses, queried for tool declarations, and registered as dangerous
  tools at call time.
- MCP startup uses the local sandbox command validator, but there is no
  explicit trust database, provenance approval, signature check, or structured
  response validation before MCP tool outputs can enter the LLM context.

External evidence:

- OWASP MCP Tool Poisoning describes the connect-time/runtime trust gap: a tool
  can look acceptable when listed, then return poisoned runtime content.
- OWASP Agentic Skills guidance treats skills and config files as supply-chain
  and over-privilege surfaces that need review, provenance, and scoped
  permissions.

Assessment:

- The current UI intentionally exposes `/skills`, `/hooks`, and `/mcp` as
  panels, not mutation-heavy commands. That matches the user's request to avoid
  new commands and shortcuts.
- The missing work is not more extension UI. It is extension governance.

Plan impact:

- P44 should require:
  - explicit trust records for loaded workspace/global skills;
  - visible source/path/provenance and last-loaded hash;
  - hook permission prompts or a disabled-by-default policy for shell hooks;
  - MCP server allowlist and startup approval;
  - MCP response schema validation where possible;
  - separation between external MCP outputs and privileged internal tools.

## Night Pass 4 - CLI Agent Permission And Long-Task Lessons

External CLI-agent research was added after the source inventory. The goal was
not to copy another product's command set, but to identify durable design
patterns that match the user's observed pain points.

### Permission Resources Beat Raw Command Strings

External evidence:

- Antigravity CLI documentation describes sensitive actions as permission
  resources such as commands, files, URLs, and MCP tools, evaluated through
  deny/ask/allow lists.
- GitHub Copilot CLI documentation describes allowed tool patterns, one-time
  approvals, session approvals, and deny patterns such as allowing Git commands
  while denying `git push`.

Local fit:

- SecOps currently has command and tool permissions, but prompts can still show
  over-specific strings such as a full `sudo apt update && sudo apt upgrade -y`
  command.
- The tool risk inventory gives SecOps a better internal vocabulary:
  `R2 Network Observation`, `R3 Active Enumeration`, `R5 Privileged Local
  Action`, and `R7 Extension/Supply-Chain Execution`.

Plan impact:

- P43 should move approval copy toward resource-based prompts:
  - `command(sudo)`;
  - `command(apt)`;
  - `tool(nmap_scan)`;
  - `file(/etc/shadow)`;
  - `mcp(server/tool)`.
- The prompt should still show the exact command/details underneath, but the
  reusable allow/deny rule should be the smallest meaningful resource.

### Resume And Long Tasks Need First-Class Session Records

External evidence:

- Claude Code exposes resume, named sessions, background sessions, logs, stop,
  respawn, and PTY-backed background execution flags.
- Copilot CLI describes autonomous/long-running modes and parallel delegation,
  but still frames planning and approvals as explicit workflow controls.

Local fit:

- SecOps persists conversation messages and runtime metadata, but replay is a
  reconstructed transcript, not an exact render/event journal.
- Long-running command infrastructure exists, but native tools, VPN, and
  `_run_cmd()` helpers do not all use the same supervisor/ownership model.

Plan impact:

- P45 should introduce render records or a durable transcript event model.
- P47 should make all long-running jobs visible as task records with status,
  spool/log path, cancellation state, and final outcome.
- P46 should model VPN as an owned background service, not a shell command
  launched through `nohup`.

### Provider Compatibility Is Part Of UX

External evidence:

- Copilot's custom provider guidance requires tool calling/function calling and
  streaming support.

Local fit:

- The user's Gemini/Gemma sessions showed provider errors and AFC warnings
  during tool-heavy requests.
- SecOps already has tests for not mixing Google Search grounding with function
  declarations and for suppressing known SDK warnings.

Plan impact:

- P50 should include provider compatibility tests before adding new external
  tool adapters.
- Provider errors should be collapsed into actionable local errors:
  incompatible schema, unavailable model/tool-calling, transient provider
  failure, or quota/network failure.

## Night Pass 5 - Benchmark Lessons For SecOps Evaluation

Recent cybersecurity-agent benchmarks add a useful correction to the product
direction: the right target is not "fully autonomous pentester". The right
target is a measurable assistant with explicit state, validated evidence,
bounded actions, and reproducible evaluation.

### Subtasks And Task Trees Are Better Than Hidden Chains

External evidence:

- Cybench evaluates CTF tasks with subtask guidance and different scaffolds such
  as structured bash and pseudoterminal execution.
- CTFAgent uses a plan-and-execute paradigm and task-tree memory to record
  strategic plans and step status.

Local fit:

- SecOps already has mission state, planner proposals, structured memory, and
  experience lessons.
- The missing layer is a durable task tree that records:
  - current objective;
  - evidence already collected;
  - blocked attempts;
  - proposed next action;
  - user approval state;
  - stop conditions.

Plan impact:

- P48 should persist this engagement/task tree separately from chat transcript.
- P49 should convert reviewed labs and courses into deterministic task
  templates with preconditions and evidence checks.

### Real Exploitation Benchmarks Reinforce Evidence Separation

External evidence:

- CVE-Bench and CyberGym use realistic vulnerabilities and sandboxed
  evaluation to test whether agents can reproduce or exploit vulnerabilities.
- ExploitGym focuses on turning vulnerabilities into concrete exploit impact
  and highlights the long-horizon nature of exploitation.

Local fit:

- SecOps currently has parsers and vulnerability-intelligence plans, but CVE
  lookup and exploit references can still sound stronger than the evidence
  actually supports.

Plan impact:

- P51 must keep three states separate:
  - candidate intelligence;
  - observed target evidence;
  - validated finding.
- Exploitation steps should require explicit scope, user intent, and a verified
  vulnerable condition.

### Evaluation Should Be Scenario-Based

External evidence:

- Modern cyber-agent benchmarks measure different task types and scaffolds
  rather than only a single final answer.

Local fit:

- SecOps already has `tests/test_lab_replay_harness.py`, covering RootMe,
  HackTheBox, TryHackMe, PortSwigger, and generic CTF fixtures. It already
  validates scan parsing, host-discovery retry, content discovery empty result,
  missing local tools, timeout recovery, sensitive path review, and report
  generation.
- The user's TryHackMe transcript exposed additional scenario failures that are
  not fully represented by that harness:
  - over-chaining after Nmap;
  - hidden directory brute-force problems;
  - missing wordlist handling;
  - provider AFC errors;
  - manual interruption when commands appeared late;
  - VPN setup and firewall diagnosis.

Plan impact:

- Extend the existing replay suite with interaction-level scenario transcripts:
  - local time/OS/IP narrow questions;
  - VPN connect/fail/retry/disconnect;
  - CTF questionnaire flow;
  - private VM port scan;
  - missing tool/wordlist;
  - sudo install/update request;
  - `ctrl+o` expansion after assistant text.
- Each replay should assert not only the final answer, but also tool count,
  permission prompt shape, transcript rendering, and whether the agent stopped
  after the requested step.

### Scope Guardrail Recheck

Current state:

- `ScopeGuard` tests already cover:
  - CIDR/domain/subdomain/URL path matching;
  - shell target extraction for network commands;
  - blocking out-of-scope tool calls before execution;
  - blocking out-of-scope shell network commands before permission prompts;
  - allowing in-scope URL tools;
  - explicit out-of-scope deny even when no in-scope list exists.

Remaining gap:

- `request_context.ScopeStatus.OUT_OF_SCOPE` exists, but `_scope_status()` only
  returns `EXPLICIT`, `INFERRED_FROM_SESSION`, or `MISSING`.
- This means the deterministic execution gate can block out-of-scope actions,
  but the request classification/UX does not yet surface "this request targets
  an out-of-scope asset" early enough.

Plan impact:

- P48 should extend request classification to identify explicit out-of-scope
  targets against the current mission scope.
- The UI/model context should receive that status before any tool proposal is
  generated.

### Reporting And RoE Recheck

External baseline:

- NIST SP 800-115 separates planning, conducting, analyzing, and
  reporting/mitigation activities. This supports a mission object that carries
  authorization and reporting requirements from the start, instead of treating
  reports as a transcript summary.
- OWASP WSTG reporting keeps vulnerability category, threat, root cause,
  testing technique, remediation, and severity separate. This is a useful guard
  against vague "tested" claims generated by the model.
- OWASP APTS Rules of Engagement separates authorization, in-scope assets,
  out-of-scope assets, safety controls, timing, and reporting constraints.

Local fit:

- SecOps already has mission state, structured findings, evidence records,
  replay tests, and report-oriented artifacts.
- The missing piece is stricter binding between RoE, execution gates, evidence,
  and final claims.
- `PentestReportGenerator` already separates scope, methodology, attack surface,
  findings, remediation, and appendix, but it still trusts the `MissionContext`
  it receives.
- `Finding` already distinguishes `confirmed` from unconfirmed/reference and can
  carry multiple `Evidence` items, but reports need validation rules before
  generation.
- Current report generation lists any `Finding` present in `MissionContext`.
  Findings without structured evidence can still appear with "Not recorded" in
  the evidence section.
- Reference intelligence such as `cve_reference` and `exploit_reference` is
  excluded from "actionable non-reference findings", but critical references can
  still influence the highest recorded severity if severity calculation uses all
  findings.
- `/export` exports the conversation Markdown, not necessarily the structured
  pentest report, so a chat-generated "report" can remain free-form model text.

Plan impact:

- P48 should persist RoE fields for:
  - authorization basis;
  - in-scope and out-of-scope assets;
  - allowed and prohibited techniques;
  - time windows;
  - data sensitivity;
  - stop conditions;
  - reporting requirements.
- `Scope.rules` should not remain only display text. It should be converted into
  structured RoE constraints such as:
  - `allow_exploitation`;
  - `allow_bulk_download`;
  - `allow_credential_testing`;
  - `allow_password_spray`;
  - `rate_limit`;
  - `time_window`;
  - `data_handling`;
  - `proof_limits`.
- Add a `RoEGuard` before planner ranking and before execution. Each proposed
  `NextAction` should be able to expose `roe_status`, `blocked_reason`, and
  `approval_reason`.
- Reports must not claim a technique was used unless a tool event, evidence
  record, or explicit user-provided fact supports it.
- Before report generation, validate:
  - every non-info confirmed finding has at least one evidence item;
  - every evidence item has source, target, timestamp, and snippet;
  - every methodology tool claim appears in evidence or tool event history;
  - reference-only CVE/exploit entries remain labelled as unconfirmed/reference;
  - remediation can be defaulted, but impact and confirmation status cannot.
- Add report support levels:
  - `observed`;
  - `inferred`;
  - `reference`;
  - `unsupported`.
- Executive severity should be calculated from observed/confirmed affected
  findings, not from reference-only intelligence.
- Keep "Reference Intelligence" separate from "Affected Findings".

## Night Pass 6 - Experience Memory Recheck

Current state:

- `ExperienceStore` stores append-only JSONL case lessons.
- Lessons are sanitized and bounded.
- `run_shell` lesson capture is disabled by default because shell output may
  contain secrets, flags, credentials, local paths, or private data.
- The store supports audit summaries, export, pruning, dry-run anonymization,
  backup rewrite, and malformed-entry tolerance.
- Tests cover persistence, audit, anonymization, pruning, duplicate handling,
  technical failures, user denials, planner influence, and agent persistence.

Risk:

- Retrieval is currently based on token overlap across mission/action tokens
  and lesson fingerprint tokens.
- Platform tags, targets, services, technologies, and endpoints can all
  contribute to overlap.
- This is useful and explainable, but it can still retrieve a lesson because
  two cases share broad terms such as `apache`, `upload`, `ctf`, or `http`,
  even when the exploitation path should not be reused.

Plan impact:

- P49 should add compatibility gates before a lesson can influence a playbook
  or planner ranking:
  - matching service family;
  - compatible port/protocol;
  - compatible endpoint evidence;
  - compatible failure mode;
  - same risk class or lower-risk action;
  - platform tag as weak metadata only.
- P49 should distinguish three memory layers:
  - episodic lesson: what happened in one run;
  - reviewed playbook: human-approved reusable pattern;
  - persistent fact: current mission fact such as host, service, finding, or
    blocker.
- The agent can say "this resembles a previous case" only when the compatibility
  gates are visible and the missing evidence is stated.

## Night Pass 7 - Response Style Regression Scope

Current state:

- The system instruction now requires concise terminal-agent style.
- It explicitly says not to print full mission state after narrow local
  questions such as time, OS, IP address, or VPN status.
- It requires numbered lists as `1. Item` / `2. Item`.
- It requires sparse visual emphasis: bold only for critical outcomes, risks,
  decisions, or final answers.
- Tests assert that these rules are present in the system instruction.
- TUI markdown normalization tests already preserve code fences and rewrite
  malformed ordered lists like `1 Item` into visible `1. Item`.

Risk:

- Prompt-contract tests prove the instruction exists, not that a live or fake
  model response follows it.
- The user's transcripts showed residual drift:
  - repeated "Mission State" after narrow local questions;
  - inconsistent list numbering;
  - overly bold or over-highlighted prose;
  - assistant text repeated several times during provider instability.

Plan impact:

- P48/P52 should add response-shape regression fixtures with fake model output:
  - local time question should answer only time;
  - OS/IP/VPN status should not append a generic mission block;
  - malformed ordered lists are normalized;
  - excessive repeated paragraphs are collapsed or surfaced as provider/output
    anomaly;
  - bold/color emphasis remains sparse after rendering.

## Night Pass 8 - Permission Prompt Recheck

Current state:

- Permission resources already include `command`, `command_exact`,
  `command_prefix`, `tool`, `read_file`, and `write_file`.
- `command_prefix` exists for useful low-risk/contextual approvals such as
  `pwd` or `nmap 127.0.0.1`.
- Exact command approval is used when a prefix would be unsafe, including
  `uname -a` and compound commands.
- Compound/high-impact exact commands such as
  `sudo apt update && sudo apt upgrade -y` show only "Allow once" and "No".
  They do not offer session/persistent allow.
- Tests already assert that unsafe prefix extensions with shell control
  operators do not inherit a remembered `nmap target` approval.

Assessment:

- The older issue "always allow commands that start with huge sudo command" is
  no longer the accurate description of the current code.
- The remaining permission gap is semantic:
  - the prompt does not show risk class;
  - sandbox/sudo feasibility can still be confusing for internal privileged
    tools;
  - file permissions exist but are not uniformly enforced before file-reading
    tools;
  - internal tools such as VPN have separate privileged execution paths;
  - `command_uses_sudo()` and command extraction still need shared parser
    coverage for substitutions and nested shells.

Plan impact:

- A5 remains valid, but its purpose is to align semantics and feasibility, not
  to re-create already-fixed prefix behavior.
- Approval prompts should ultimately show:
  - resource;
  - exact details;
  - risk class;
  - sandbox/sudo feasibility;
  - smallest safe reusable rule.
- Sudo prompts should only appear after a single feasibility check confirms that
  the selected permission mode and sandbox will allow the privileged command if
  authentication succeeds. Asking for a password and then failing on sandbox is
  a product bug.

## Night Pass 9 - Heavy Tool Adapter Expansion

External baseline:

- Burp Suite, OWASP ZAP, Metasploit, Impacket, NetExec, and BloodHound are all
  useful in authorized work, but they have very different impact levels.
- Their workflows include passive observation, active scanning, request
  mutation, credential use, password spraying, remote command execution, file
  upload/download, exploit module execution, and graph ingestion.

Local implication:

- SecOps should not represent all of these as a generic `run_shell` or one
  generic "pentest tool" category.
- The current `ToolDefinition` carries `name`, `description`, `category`,
  `parameters`, `func`, and binary `dangerous`, but not native adapter metadata:
  binary requirements, version, parser, output format, install proposal,
  risk class, credential use, artifacts, or declared runtime profile.
- The registry timeout can still conflict with native wrappers whose internal
  command timeout is longer than the global default when no `timeout` parameter
  is declared in the schema.
- Missing dependency parsing currently relies on text patterns and apt-centric
  install hints. Structured adapter errors would be cleaner and portable across
  package managers.
- Parsing currently runs primarily on successful tool outputs; timeout and
  missing-dependency errors should be parseable as structured operational
  blockers too.
- A future adapter contract should expose:
  - supported action type;
  - required credentials or secrets;
  - scope extractor;
  - default timeout/inactivity profile;
  - output parser;
  - evidence records produced;
  - install detection and install proposal;
  - risk class;
  - whether it can mutate, authenticate, spray, upload, execute, or exploit.
- Minimal `AdapterSpec` fields:
  - `name`;
  - `family`;
  - `category`;
  - `description`;
  - `parameters`;
  - `risk_class`;
  - `target_fields`;
  - `credential_fields`;
  - `default_timeout`;
  - `inactivity_timeout`;
  - `output_format`;
  - `parser`;
  - `requirements`;
  - `artifacts`.

Plan impact:

- P50 should add adapter conformance fixtures before any new heavy tool is
  registered.
- P43 should treat credentialed execution, spraying, payload generation, and
  remote command execution as separate permission resources.
- P48 should require engagement-level authorization before credentialed internal
  network workflows, even in labs.
- P47/P50 should ensure the outer registry timeout honors adapter runtime
  profiles for native wrappers and API-backed adapters.
- P50 should move missing-dependency handling from raw text matching toward
  `error_code=missing_dependency` with OS-aware install proposals.

## Night Pass 10 - Provider Reliability Recheck

Observed user symptoms:

- Gemini API `500 INTERNAL` on simple questions.
- Gemini API `400 INVALID_ARGUMENT` after some tool-call prompts.
- SDK warning about automatic function calling compatibility.
- Repeated paragraph output after provider instability.
- Long latency on narrow local questions.

Current code:

- `SecOpsAgent._is_retriable_llm_error()` retries 429, 502, 503, 504,
  timeouts, temporary failures, and high traffic, but not explicit `500` or
  `internal`.
- `GeminiProvider._format_api_error()` compacts 400/tool-call failures and
  malformed responses, which keeps noisy provider details out of the terminal.
- Known SDK AFC and malformed finish warnings are suppressed in the provider.
- Function declarations are sent through `config.tools`, but SDK automatic
  function calling is not disabled explicitly. SecOps wants manual orchestration;
  the SDK should not attempt its own tool execution layer.
- The normal first LLM call still exposes the full registry unless a special
  follow-up path disables tools. This increases request size and provider schema
  rejection surface for narrow prompts.
- Tool schema conversion has tests for object schemas, enum arrays, invalid
  function names, and compact invalid-argument messages.
- Streaming chunks are rendered before the attempt is known to have completed.
  If a retry happens after partial text, the next attempt can duplicate the
  visible prefix.
- There is no current regression fixture for:
  - repeated assistant paragraphs;
  - retry after partial stream;
  - focused local questions avoiding the full tool registry;
  - MCP schema degradation for unsupported shapes.

Plan impact:

- Add provider-observability tests for:
  - `500 INTERNAL` is retriable once with backoff;
  - repeated paragraphs are detected or compacted before rendering;
  - narrow local questions bypass the provider when a deterministic local
    preflight exists;
  - provider failures do not append generic mission-state blocks.
- Keep `400 INVALID_ARGUMENT` non-retriable when it is caused by tool schema or
  provider request shape.
- Disable SDK automatic function calling explicitly when SecOps provides manual
  function declarations.
- Expose a narrow tool schema per request goal instead of the full registry:
  - no tools for pure local text answers;
  - minimal local preflight tools for time/OS/IP/VPN;
  - goal-compatible tools for explicit actions;
  - no tools for post-tool summaries unless the user asks for the next step.
- Buffer or reconcile partial streamed text across retry attempts so a failed
  first attempt cannot duplicate the final answer.
- Add a provider compatibility matrix per model profile:
  - function declarations supported;
  - Google Search grounding compatibility;
  - thinking support;
  - maximum tool schema size;
  - fallback behavior.

## Night Pass 11 - Data Retention And Secret Hygiene Recheck

External baseline:

- OWASP Logging Cheat Sheet warns that logs can contain secrets, code, session
  identifiers, tokens, personal data, passwords, connection strings, keys, and
  other sensitive information.
- OWASP Secrets Management treats secrets as lifecycle-managed assets: creation,
  rotation, revocation, expiration, auditing, and minimum privilege.
- NIST SP 800-92 treats log generation, transmission, storage, access, analysis,
  and disposal as parts of a log management program.

Current local surfaces:

- Sessions are stored under `~/.secops_agent/sessions/*.json`, with a local
  fallback under `./.secops_sessions`.
- Exports are written under `~/.secops_agent/exports/*.md`.
- Supervised command spools are written under
  `~/.secops_agent/runs/<run>/combined.log`, `stdout.log`, and `stderr.log`.
- VPN logs are written under `~/.secops_agent/vpn/openvpn-<config-stem>.log`.
- Experience lessons are written under
  `~/.secops_agent/experience/case_lessons.jsonl`.
- Settings and remembered permissions are written under
  `~/.secops_agent/settings.json`.
- TUI history and application logs are also stored under `.secops_agent` by
  default.

Risks:

- Session/export names are not yet a strict safe slug in every path.
- File and directory permissions depend on system umask, not explicit
  `0700`/`0600`.
- Structured credentials are redacted in mission objects, but prompts, raw tool
  outputs, artifacts, attachments, spools, VPN logs, and exports can still
  contain raw secrets, flags, cookies, tokens, paths, or internal targets.
- Experience memory keeps some target-like fields in clear text by default.
- Exact session replay and public export need different policies: exact replay
  is private/local; export should be redacted by default.

Plan impact:

- Add `SECOPS_HOME` storage policy:
  - create directories as `0700`;
  - create files as `0600`;
  - perform atomic writes;
  - apply the same policy to local fallbacks.
- Validate session/export names:
  - strict slug;
  - reject absolute paths;
  - reject `..`;
  - reject path separators;
  - resolve and verify the target stays below the expected base directory.
- Add common `RedactionPolicy` for:
  - sessions;
  - exports;
  - traces;
  - artifacts;
  - attachment previews;
  - tool summaries.
- Keep raw spools private by default and expose raw export only through explicit
  opt-in such as `--include-raw` / `--include-spools`.
- Add retention defaults:
  - sessions: last N or 90 days;
  - spools and VPN logs: 7-14 days;
  - app logs and traces: 14 days;
  - experience lessons: bounded count or 180 days.
- Store exact replay as a private bundle with manifest, schema version,
  redaction version, hashes, relative paths, runtime metadata, artifacts, and
  task state.

## Night Pass 12 - Evaluation Contamination Recheck

External baseline:

- CTFusion argues that static CTF benchmarks can be unreliable for LLM agents
  because existing challenges may be contaminated by writeups, memorized
  content, or search-assisted shortcuts.
- PentestGPT and Cybench both reinforce that multi-step task state, context
  preservation, tool-use scaffolding, and subtask decomposition are central to
  pentest-agent evaluation.

Local implication:

- SecOps should not optimize only for answering known TryHackMe/HTB questions.
- Replays should test behavior shape, tool count, evidence, approvals, stop
  conditions, and recovery from failed tools.
- Experience memory should never store or replay raw flags as "learned
  solutions".

Plan impact:

- P49 evaluation fixtures should use:
  - synthetic lab transcripts;
  - isolated local services;
  - mocked tool outputs;
  - known failure modes;
  - negative cases where a previous pattern must not apply.
- Scoring should track:
  - correct next proposal;
  - correct stop point;
  - evidence-bound answer;
  - no hidden tool chain;
  - no flag memorization.

## Night Pass 13 - Exact Resume And `ctrl+o` Replay Recheck

External baseline:

- GitHub Copilot CLI documents `/resume`, `--resume`, `--continue`,
  background compression, context monitoring, and persisted reasoning
  visibility as session-level product behavior.
- Codex CLI treats approvals, sandboxing, MCP, skills, subagents, web search,
  and local session work as distinct surfaces. The lesson for SecOps is that
  transcript replay should not be an accidental side effect of model memory.

Current local code:

- `ConversationMemory.save_session()` stores full message history,
  structured memory, metadata, and `runtime.to_session_dict()`.
- `RuntimeState.to_session_dict()` stores artifacts, workspace directories,
  fast mode, sandbox mode, and permission mode only.
- `RuntimeState.load_session_dict()` resets `ctrl+o` state after restoring
  runtime data.
- `run_chat_loop()` calls `renderer.render_session_transcript()` after
  `--session` preload and after `/load`.
- `Renderer.render_session_transcript()` reconstructs user/model/tool display
  from `Message` objects. It does not replay a terminal-render journal.
- Tool replay uses pending tool calls matched by name. This loses exact row
  identity, permission rows, expansion state, timing, previous collapsed
  previews, and any terminal-specific line count.
- `_toggle_latest_transcript()` still works on the latest in-memory tool or
  thought anchor. It cannot target an arbitrary historical row because no
  durable per-row anchor exists.
- A normal launch creates a fresh autosave name, but after `/resume` the current
  autosave target can become the resumed session name. This means close-time
  autosave can rewrite the source session instead of saving a new launch as a
  child/current session.
- `/model` already persists a global model preference in
  `~/.secops_agent/settings.json`; session metadata also stores model state.
- Permission rules can persist in `settings.json`, but the active permission
  mode is mainly runtime/session state, not a global preference by default.

Implications:

- The agent can preserve context while still failing AGY-like visual resume.
- Exact visible replay requires a private render journal, not only messages.
- `ctrl+o` should be row-anchored. If an old row is no longer addressable,
  the UI should say that the historical block is not expandable instead of
  appending an expanded duplicate at the tail.
- `/export` should remain redacted and report-like; exact replay should be a
  private local session artifact governed by P55.

Plan impact:

- Extend P45 with `TranscriptJournal`:
  - append-only events for prompt, model text, tool call, tool result,
    permission decision, divider, status, error, and artifact reference;
  - stable row IDs;
  - terminal-width-aware display metadata;
  - collapsed and expanded payload references;
  - redaction version and private/raw flag.
- Store journal metadata in the session bundle while keeping raw spools private.
- On resume:
  - restore model, runtime, artifacts, and message context;
  - replay the bounded visible journal;
  - reset live anchors;
  - rebuild only missing journal rows from messages as a degraded fallback.
- Split session lifecycle:
  - `resumed_from`: immutable source session;
  - `current_session_name`: fresh autosave target for this launch;
  - explicit `/save <same-name>` remains the only way to overwrite a prior
    session.
- Persist default permission mode and sandbox preference separately from
  per-session runtime state.
- Add PTY regression tests for:
  - exact transcript after `/load`;
  - `ctrl+o` on latest current block;
  - no duplicate tail expansion for historical rows;
  - `/clear` starts a new visible journal and does not replay older rows.

## Night Pass 14 - Extension Governance Recheck

External baseline:

- OWASP MCP Tool Poisoning identifies a runtime trust gap: reviewed tool
  declarations do not make tool responses trustworthy.
- OWASP MCP Security highlights tool descriptions, schemas, return values,
  cross-server shadowing, confused-deputy behavior, supply chain risk, and
  auditability.
- OWASP AI Agent Security recommends least privilege, per-tool scoping,
  isolated memory, human-in-the-loop controls, output validation, monitoring,
  and adversarial regression tests.

Current local code:

- Native tools are registered through static imports and the `@tool`
  decorator, so the core registry is predictable.
- Skills are loaded from workspace and global Markdown directories, truncated,
  deduplicated by file stem, and injected into prompt context.
- Skill definitions include source and path, but no content hash, trust state,
  signature, approval timestamp, or prompt-injection review result.
- Hooks load from workspace and global `hooks.json`. Enabled hooks can run
  shell commands before/after tools or on errors.
- Hook execution passes tool arguments and errors through environment
  variables, runs in the current workspace, and keeps only the last 50 hook
  runs in memory.
- String hook commands are normalized through shell execution, which makes them
  higher risk than an argv-only adapter.
- MCP servers load from workspace and global config files. Their tools are
  registered as `dangerous=True`, but no per-server trust decision, schema hash,
  return-value validation, or privilege separation exists.
- MCP server startup happens before remote tools are registered as dangerous.
  A malicious configured server can therefore start and receive inherited
  environment variables before ordinary tool approval protects anything.
- MCP schema translation keeps only basic type, description, and required
  flags; richer constraints such as enum, items, defaults, bounds, and nested
  object shape are dropped.
- Displayed agent profiles are currently read-only metadata, while side
  questions use an internal secondary agent with approvals denied in the
  background.
- Observability is optional and redacted only partially; extension lifecycle
  events such as `extension_loaded`, `hook_run`, `mcp_started`, and
  `tool_registered` are not yet durable audit records.

Risks:

- A workspace skill can influence the system prompt before the user has a clear
  trust review.
- A hook can execute local commands through configuration, which is more
  powerful than a normal tool description.
- The risk is not only future-facing: current hook and MCP startup paths already
  need trust gates before adding more extension capability.
- MCP tools are all "dangerous", but binary danger does not express server
  provenance, remote origin, credential use, file access, or network target.
- Tool outputs from external servers can inject instructions into the model
  context unless SecOps validates and labels them as untrusted data.
- Global extension locations can affect unrelated workspaces unless trust is
  scoped per workspace.

Plan impact:

- Expand P44 into an `ExtensionTrustStore`:
  - source type: workspace, global, user, managed;
  - canonical path or server URI;
  - content/schema hash;
  - first seen and last approved timestamps;
  - approved workspace roots;
  - risk flags;
  - review status.
- Gate extension activation:
  - skills may be listed before trust, but not injected into the system prompt;
  - hooks must be disabled by default until explicitly trusted;
  - MCP servers must be approved by server, command, environment policy, and
    schema hash before startup.
- Prohibit or high-risk-gate string shell hooks by default; prefer argv hooks
  with explicit command preview.
- Do not inherit the full environment into MCP servers by default; use an
  allowlist and explicit secret references.
- Add durable audit events:
  - `extension_loaded`;
  - `extension_trusted`;
  - `hook_run`;
  - `mcp_start_requested`;
  - `mcp_started`;
  - `tool_registered`;
  - `approval_decision`.
- Add MCP response isolation:
  - structured return schemas where possible;
  - untrusted output labels;
  - no direct promotion of MCP free text to planning facts;
  - high-privilege local tools isolated from untrusted external context.
- Add tests for:
  - modified MCP schema requires re-approval;
  - poisoned tool description is visible in review, not silently trusted;
  - hook config cannot run before trust;
  - global skills do not override workspace trust silently;
  - external tool output cannot create a privileged tool call without a fresh
    deterministic approval.

## Night Pass 15 - Methodology Coverage Recheck

External baseline:

- PTES frames a penetration test as a staged engagement from
  pre-engagement through intelligence gathering, threat modeling,
  vulnerability analysis, exploitation, post-exploitation, and reporting.
- OWASP ASVS provides a web/API verification vocabulary and stable requirement
  identifiers that can be mapped to evidence.
- HTB Academy's penetration testing process module similarly separates
  pre-engagement, information gathering, vulnerability assessment,
  exploitation, post-exploitation, lateral movement, proof of concept, and
  post-engagement.
- TCM Practical Ethical Hacking emphasizes hands-on methodology and effective
  note keeping, not just tool execution.

Product decision:

- Do not add a CTF-only mode.
- Use one technical workflow for CTFs, labs, private virtual environments, and
  authorized client-style tests.
- Treat platform/provider as weak metadata:
  - useful for VPN/setup hints;
  - not a reason to skip scope, evidence, or permissions;
  - not a reason to auto-chain exploitation.
- Use methodology stages and control vocabularies as coverage maps, not as
  hidden autonomous instructions.

Plan impact:

- P48 should store methodology context separately from target type:
  - engagement type;
  - authorization statement;
  - targets and exclusions;
  - testing depth;
  - allowed/prohibited techniques;
  - stop conditions;
  - reporting expectations.
- P49 playbooks should expose:
  - stage;
  - objective;
  - evidence needed;
  - safe next proposal;
  - stop condition;
  - what would make the playbook not applicable.
- Reports should support optional mappings:
  - WSTG category;
  - ASVS requirement;
  - MITRE technique;
  - CVE/KEV/EPSS signal.
- The agent should answer lab questions from evidence while preserving the
  same discipline used for private VMs and client work.

## Night Pass 16 - Test Coverage And Behavioral Locks Recheck

Current local test coverage:

- The repository already has focused tests for:
  - permissions and sudo authentication;
  - VPN setup, status, disconnect, sandbox blocking, and TLS failure;
  - command streaming and execution supervisor behavior;
  - result parsers and missing local tools;
  - lab replay harness and planner behavior;
  - runtime/session persistence;
  - TUI polish for `/skills`, `/hooks`, `/mcp`, `/permissions`, and `ctrl+o`;
  - experience memory retention, target hashing, and audit reporting.

Important behavioral locks:

- Some tests preserve current `/resume` semantics where the resumed session can
  become the exit autosave target. P45 intentionally changes that behavior, so
  those tests should be rewritten, not blindly preserved.
- Existing tests validate extension panels, but mostly as display surfaces. They
  do not yet test trust gating, hook command approval, MCP startup approval, or
  poisoned tool descriptions.
- Missing-tool tests still expect apt-only install commands. P50 should replace
  those with OS/package-manager-aware proposals.
- VPN and sudo tests are strong enough to protect recent fixes, but they do not
  yet prove that every internal privileged tool path uses the same resource
  analysis as `run_shell`.
- TUI tests cover some `ctrl+o` behavior, but exact transcript replay needs PTY
  fixtures that verify visible terminal output, not only helper strings.

Plan impact:

- Add a "behavioral lock audit" before each implementation phase:
  - identify tests that protect desired behavior;
  - identify tests that encode known-bad legacy behavior;
  - rewrite legacy-lock tests first with the new intended behavior.
- For P44, add poisoning and startup tests before refactor:
  - workspace skill is inventoried but not injected until trusted;
  - hook string command is denied or exact-only high risk;
  - MCP server startup asks before subprocess creation;
  - full environment is not inherited by default;
  - MCP schema mutation invalidates prior approval.
- For P45, add PTY tests that compare rendered output after resume and ensure
  no historical `ctrl+o` duplicate appears at the tail.
- For P50, update missing-tool tests to validate proposals as structured
  objects instead of hardcoded `sudo apt install` strings.

## Night Pass 17 - Experience Learning Governance Recheck

External baseline:

- OWASP AI Agent Security lists memory poisoning and excessive autonomy as
  agent-specific risks.
- CTFusion highlights contamination risk when benchmarks or agents rely on
  existing public challenge material.
- Pentest-agent research repeatedly shows that task decomposition and context
  preservation help, but success claims need controlled evaluation.

Current local code:

- `ExperienceStore` already persists local lessons and can audit, export,
  anonymize, retain, and rerank prior patterns.
- The planner can use similar prior successes and failures as suggestion
  context.
- `run_shell` capture is intentionally not enabled for experience by default,
  because shell output may contain secrets.
- Some tests already verify that experience does not create out-of-scope
  actions.

Risks:

- Lessons can still become too influential if they are not explicitly reviewed.
- Similarity based on text can match cases that look linguistically similar but
  differ technically.
- A known CTF solution can contaminate future lab answers if raw flags, exact
  paths, or challenge-specific secrets are stored as "experience".
- A prior success should never bypass scope, permission, evidence, or stop
  conditions.

Plan impact:

- Add P56 "Reviewed Experience Learning":
  - every lesson stores provenance, source type, review status, confidence, and
    expiry;
  - raw flags, secrets, credentials, and exact challenge answers are excluded;
  - lesson influence is explanation-only until reviewed;
  - compatibility gates must pass before a lesson affects next-action ranking:
    service, port/protocol, endpoint evidence, failure mode, risk class,
    required credential state, and platform tag as weak metadata only;
  - failed attempts are first-class lessons when they identify missing tools,
    blocked network, wrong wordlist, timeout, or scope mismatch.
- Add an evaluation loop:
  - replay synthetic lab transcripts;
  - measure suggestion quality;
  - measure whether the agent stops correctly;
  - measure whether evidence is required before answering;
  - include negative tests where a tempting prior lesson must not apply.
- Add user-visible lesson explanation:
  - "similar prior success" or "similar prior failure";
  - why it matches;
  - what evidence is still missing;
  - why it is not being executed automatically.

## Night Pass 18 - Long-Running Execution Recheck

External baseline:

- CLI guidance from Codex, Claude Code, Copilot CLI, and Antigravity points to
  the same pattern: approvals, sandbox state, progress, cancellation, and
  session state are separate surfaces.
- Rich progress documentation reinforces state-driven progress rather than
  printing a static spinner or waiting until process end.
- OpenVPN process control documentation supports using explicit PID/status/log
  ownership instead of broad `killall` behavior.

Current local code:

- `ExecutionSupervisor` already owns process lifecycle, output spooling, idle
  tracking, max runtime, process-group termination, and progress events.
- `run_cmd_streaming()` wraps argv commands through `ExecutionSupervisor`,
  emits progress, and records spool metadata.
- `run_shell()` also uses `ExecutionSupervisor` and gives better sudo/manual
  guidance than earlier versions.
- `nmap_scan`, `dir_brute`, and `nikto_scan` use streaming helpers with
  internal timeouts of 300/600 seconds.
- The registry-level timeout can still cut a tool at `TOOL_TIMEOUT` if the
  schema does not expose the longer timeout.
- `connect_vpn_config()` starts OpenVPN through a background shell command with
  `nohup`, redirects logs, polls handshake state, and returns PID/log details.
- Short helpers such as `run_cmd()` still exist for simple commands, and some
  system info paths use `bash -c` for convenience.
- Focused explorer validation passed 54 execution/sudo/local-lab tests plus 4
  targeted `ctrl+o`/progress renderer tests in the project virtualenv.

Risks:

- Tool-specific timeout intent and registry timeout are not a single contract.
- A long process can have good internal progress but still be reported as a
  generic tool timeout by the outer registry.
- VPN ownership is not yet a first-class supervised process with durable
  metadata, stop policy, and exact owned-process disconnect.
- `disconnect_vpn()` can stop every detected OpenVPN process instead of only a
  SecOps-owned session, which can disrupt a user VPN started outside SecOps.
- The VPN start path can report "started" while handshake is still pending,
  and an existing unrelated TUN interface can be confused with the new VPN.
- If an outer registry timeout or user cancellation happens after detached
  OpenVPN PID creation, the child can be orphaned without a cleanup path.
- Newline-separated sudo commands need to be treated as shell-separated
  commands, the same way `;`, `&`, and `|` are handled.
- Progress display can still feel blocked when the tool emits no output and no
  domain-specific phase is available.
- Active `ctrl+o` expansion currently preserves tool rows better than before,
  but it does not yet show recent progress details for a running long task.
- Parsing currently focuses on success/output. Structured timeout and
  dependency errors should feed planner and user-facing next proposals.

Plan impact:

- P47 should promote `ExecutionSupervisor` from helper to runtime contract:
  - `max_runtime`;
  - `inactivity_timeout`;
  - `progress_interval`;
  - `expected_idle_phases`;
  - `cancel_policy`;
  - `spool_policy`;
  - `result_parser`;
  - `structured_error_parser`.
- P50 adapter metadata should declare the execution profile so the registry,
  UI, planner, and parser all agree.
- Heavy tools should report progress even during quiet periods:
  - elapsed;
  - last output age;
  - process PID;
  - output lines/chars;
  - current phase;
  - cancel hint.
- VPN should become an owned long-running task:
  - owned PID file;
  - config hash;
  - log path;
  - started-at timestamp;
  - handshake state;
  - tunnel interface snapshot;
  - disconnect only owned PID by default;
  - explicit high-risk kill-all escape hatch.
- VPN connect should refuse or clearly warn before starting a second session
  when an existing OpenVPN process or TUN interface is present.
- VPN connect should distinguish:
  - `starting`;
  - `pending-handshake`;
  - `connected`;
  - `failed`;
  - `stale`;
  - `disconnected`.
- Add cancellation cleanup for any SecOps-started OpenVPN PID/process group.
- Add exact regression tests from the execution audit:
  - `test_connect_vpn_config_refuses_to_start_when_openvpn_process_already_running`;
  - `test_connect_vpn_config_cleans_started_pid_on_cancellation`;
  - `test_disconnect_vpn_does_not_kill_untracked_openvpn_process`;
  - `test_connect_vpn_config_wait_limit_reports_pending_not_connected`;
  - `test_run_shell_sudo_detection_handles_newline_separator`;
  - `test_run_shell_force_noninteractive_sudo_rewrites_newline_sudo`;
  - `test_ctrl_o_during_running_tool_shows_latest_progress_detail`.
- Add tests where outer registry timeout and inner tool timeout disagree, then
  enforce that the adapter contract wins.

## Night Pass 19 - Provider Tool Schema And Local Preflight Recheck

External baseline:

- Agent CLIs that run tools reliably separate model reasoning from local tool
  orchestration. The model may propose a tool, but the runtime owns execution,
  approval, retries, cancellation, and replay.
- OpenAI Codex CLI and Claude Code documentation both expose explicit approval
  and tool-control surfaces instead of leaving all tool behavior to model
  auto-calling.
- Gemini SDK warnings seen during the lab show a concrete provider risk:
  automatic function-calling compatibility can fail before the agent reaches
  its own permission and execution logic.

Current local code:

- `SecOpsAgent.stream_response()` computes a `RequestDecision`, injects it into
  model context, and runs some deterministic local preflight tools.
- The local preflight path already covers VPN connect/status/disconnect,
  lab-readiness checks, selected suggested actions, and some web-directory
  requests.
- Outside those preflight paths, the agent still sends
  `self.registry.get_tools_schema()` to the model for most turns.
- After a tool call, the next summary pass can be text-only when automatic
  planner execution is disabled.
- `GeminiProvider._build_config()` sends function declarations when tool schema
  is present and only enables Google Search grounding when no function tools
  are attached.
- The code currently suppresses known SDK AFC warnings and compacts
  `400 INVALID_ARGUMENT` tool-schema errors, but it does not yet prove that AFC
  is disabled by configuration.
- Existing tests cover rich schema conversion, invalid function-name filtering,
  Google Search not mixing with function declarations, and compact provider
  error text.
- Existing tests do not yet prove request-scoped schema reduction, local no-tool
  answers for time/OS/IP/VPN status, partial-stream deduplication, or explicit
  AFC disablement.
- Explorer validation on the current tree reported 67 focused tests passing for
  provider/schema/request-context/local-lab/tool-chaining coverage, while also
  confirming that the built-in registry currently exposes 32 tools and roughly
  13 KB of schema before MCP tools are added.

Risks:

- A narrow local question can still depend on model availability when a local
  deterministic tool would be enough.
- Sending the full registry increases provider rejection probability and gives
  the model too many irrelevant actions to choose from.
- Suppressing AFC warnings hides noise but does not guarantee that the SDK is
  configured exactly for manual orchestration.
- Provider retries can duplicate already-streamed text if the retry boundary is
  not explicit.
- Request classification can become "analysis only" unless it drives tool
  exposure, approval wording, and tests.
- `INVALID_ARGUMENT` should remain non-retriable as a generic provider error;
  the safer special case is a single explicit fallback with reduced or empty
  tool schema when the failure is clearly a function-declaration rejection.

Plan impact:

- P54 should add a `ToolSchemaSelector` before provider calls:
  - `LOCAL_SYSTEM` exposes no remote/pentest tools;
  - `LAB_READINESS` exposes only setup/status tools;
  - `PORT_SCAN` exposes scan tools only;
  - `WEB_DIR_ENUM` exposes directory-enum tools only;
  - `REPORT` exposes reporting tools only;
  - unknown/high-risk prompts expose a minimal safe set or ask for scope.
- Local deterministic questions should bypass the provider when possible:
  - time/date;
  - OS/kernel;
  - local IP/interface/VPN status;
  - current model/config/session status.
- Add provider config tests for manual orchestration:
  - function declarations present only for selected tools;
  - no Google Search when function declarations exist;
  - AFC explicitly disabled if the SDK exposes that control;
  - tool-schema `400 INVALID_ARGUMENT` is non-retriable;
  - `500 INTERNAL` is retriable without duplicating completed text.
- Add exact regression tests proposed by the provider audit:
  - `ToolSchemaReductionTests.test_local_system_question_sends_no_function_tools`;
  - `ToolSchemaReductionTests.test_port_scan_question_exposes_only_network_scan_tools`;
  - `ToolSchemaReductionTests.test_web_directory_request_exposes_only_dir_brute`;
  - `ToolSchemaReductionTests.test_mcp_tools_are_excluded_until_explicitly_requested`;
  - `LocalSystemPreflightTests.test_time_question_does_not_call_llm_with_tools`;
  - `LocalSystemPreflightTests.test_os_question_routes_to_sysinfo_or_text_only`;
  - `LocalSystemPreflightTests.test_local_ip_question_uses_no_function_schema`;
  - `GroundingRoutingTests.test_latest_cve_prompt_sends_empty_schema_to_enable_search`;
  - `ProviderToolFallbackTests.test_invalid_argument_retries_once_without_tools`;
  - `ProviderToolFallbackTests.test_invalid_argument_after_fallback_surfaces_compact_error`.
- Add replay tests from the user-observed failures:
  - "Find directories using GoBuster" must not trigger provider 400 because of
    unrelated tools;
  - "what time is it" must work when provider is unavailable;
  - "is VPN still active" must route to `vpn_status`;
  - retry after provider 500 must not duplicate paragraphs.

## Night Pass 20 - External Agent Repositories And Curriculum Watch

External baseline:

- Current pentest-agent repositories emphasize live walkthroughs, persistent
  sessions, local LLM routing, containerized tool environments, playbooks,
  blackboards, and broad adapter catalogs.
- Recent benchmark papers such as Cybench, CyberGym, and ExploitGym show that
  cybersecurity agents need subtasks, reproducible environments, and careful
  measurement. They also show that full exploitation remains difficult and
  dual-use-sensitive.
- OWASP Agentic and MCP material highlights goal hijack, tool misuse, identity
  abuse, supply-chain poisoning, unexpected code execution, memory poisoning,
  and cascading failures.
- Course and video sources are useful for methodology and technique tags, but
  they should not become memorized answers, hidden chains, or unreviewed
  experience.

Current local code:

- SecOps already has structured mission state, planners, parsers, experience
  memory, runtime tasks, session persistence, permissions, hooks, skills, and
  MCP support.
- The current project is closer to a single-agent orchestrator with local
  adapters than to a blackboard/swarm runtime.
- Experience memory and structured memory exist, but trust, review state, and
  anti-contamination policy need to be strengthened before learning can safely
  affect tool ranking.
- The adapter catalog is growing, but some tools still enter through shell
  wrappers or broad schemas rather than a strict adapter contract.

Risks:

- Copying "autonomous pentest" repository patterns without governance would
  recreate the exact user complaint: hidden enchainment and blocked terminals.
- Adding many adapters without risk classes, parser contracts, and install
  proposals would increase noise and permission confusion.
- Video/course-derived knowledge can contaminate lab answers if the agent
  stores raw flags, exact hidden paths, or challenge-specific solutions.
- Swarm or multi-agent designs can hide decisions unless every proposal,
  action, and state transition is auditable.

Plan impact:

- P50 should treat every new tool as an adapter with declared scope, risk,
  install, runtime, parser, evidence, and reporting fields.
- P49 should turn external courses and walkthroughs into reviewed playbooks
  only after removing challenge-specific answers and adding stop conditions.
- P56 should require review/provenance before experience affects ranking.
- P44 should govern hooks, skills, MCP servers, and any future multi-agent
  worker with the same trust store and audit ledger.
- Add an optional "evidence board" concept before any swarm-like feature:
  - facts;
  - hypotheses;
  - blockers;
  - attempted actions;
  - failed assumptions;
  - next proposals.
- Keep the product principle: propose next actions with evidence and risk,
  then execute only the selected action unless the user explicitly approved a
  bounded batch.

## Night Pass 21 - Storage, Export, And Secret Hygiene Recheck

External baseline:

- OWASP Logging and Secrets Management guidance treats logs, exports, traces,
  credentials, cookies, tokens, private keys, and sensitive operational data as
  lifecycle-managed records.
- NIST log-management guidance reinforces that generation, storage, access,
  retention, analysis, and disposal are separate requirements.

Current local code:

- `Config.sessions_dir` creates `~/.secops_agent/sessions` or a local fallback,
  but there is no centralized `SECOPS_HOME` helper with file-mode enforcement.
- `ConversationMemory.save_session()` writes all messages, structured memory,
  metadata, and runtime state to JSON in clear text.
- `RuntimeArtifact.to_dict()` persists artifact content and paths.
- `/export` writes Markdown under `~/.secops_agent/exports` and includes user
  messages, assistant messages, tool arguments, and the first 3000 characters of
  each tool result.
- `/attach` stores metadata, hashes, absolute paths, and bounded previews in a
  runtime artifact; prompt context can include those previews.
- `StructuredTracer` redacts sensitive key names such as `api_key`, `password`,
  `secret`, and `token`, and truncates long strings, but target values are still
  trace-visible by design.
- `ExperienceStore` sanitizes allowed arguments and can export with target
  hashing, but its append/export paths do not enforce file permissions through a
  shared storage helper.
- `settings.json` is shared by preferences and persistent permissions.

Risks:

- A permissive process umask can create sessions, settings, traces, exports, or
  lesson files with broader permissions than intended.
- Exact session replay and public export need different privacy defaults; a
  replay journal should be private by default, while export should be redacted
  by default.
- Attachment previews can bring secrets into artifacts, prompt context, and
  saved sessions.
- Runtime artifact paths can reveal home paths, lab names, or customer
  directory structure.
- Hashing targets only during explicit experience export is useful but not
  enough for generic public export or trace retention.

Plan impact:

- P55 should introduce a single storage helper:
  - `secops_home()`;
  - `ensure_private_dir(path, mode=0o700)`;
  - `write_private_text(path, text, mode=0o600)`;
  - `append_private_jsonl(path, event, mode=0o600)`;
  - strict slug validation for session/export names.
- Split output types:
  - private exact replay session;
  - private raw artifact;
  - redacted public export;
  - sanitized trace;
  - reviewed experience lesson.
- Add a shared `RedactionPolicy` for:
  - credentials and tokens;
  - cookies and headers;
  - private keys and VPN material;
  - flags and challenge answers;
  - local absolute paths;
  - target IPs/domains when exporting publicly.
- Add exact tests:
  - session names cannot escape the sessions directory;
  - export names cannot escape the exports directory;
  - settings/session/export/trace/experience files are written with `0600`;
  - `~/.secops_agent` subdirectories are created with `0700`;
  - attachment previews redact obvious secrets before prompt injection;
  - public export redacts targets and secrets by default;
  - private replay remains exact but is clearly marked private.

## Night Pass 22 - Shell Command Analysis Unification

Current local code:

- `permissions.py` already has the strongest command tokenization path through
  `_shell_tokens()`, `_extract_shell_executables()`, contextual prefix
  approvals, exact-only commands, and unsafe extension markers.
- Existing tests cover command-prefix approval not covering `&&`, `||`, `;`,
  pipes, redirections, command substitution, backticks, and newlines.
- `scope_guard.py` imports `_shell_tokens()` and `_extract_shell_executables()`
  from `permissions.py` to decide when shell commands contain network targets.
- `sudo.py` still uses a separate regex for sudo detection.
- `sandbox.py` still uses a separate `shlex.split()` path and scans every token
  as if it could be an executable.
- `forensics.py` also has sudo rewrite helpers tied to its local command path.

Risks:

- Permission, sudo preflight, sandbox, and scope can disagree on the same shell
  command.
- Regex-based sudo detection misses separators that the permission parser
  already considers unsafe, such as newline-separated commands.
- `sandbox.py` can both under-block and over-block because it does not know
  command positions, shell separators, assignments, nested `bash -lc`, or
  redirections as structured facts.
- Sharing private helper functions across modules works for now, but it makes
  the parser contract implicit and hard to test as a product boundary.

Plan impact:

- Add a public `ShellCommandAnalysis` module with:
  - tokens;
  - command segments;
  - executables;
  - nested shell scripts;
  - redirections;
  - command substitutions;
  - network target candidates;
  - sudo usage;
  - unsafe extension flags.
- Make `PermissionEngine`, `sudo.py`, `sandbox.py`, `scope_guard.py`, and
  `run_shell()` consume the same analysis object.
- Keep the current approval UX decisions, but derive them from the shared
  parser.
- Add exact tests:
  - newline sudo is detected;
  - nested `bash -lc` sudo is detected;
  - quoted non-command text containing "sudo" is not detected;
  - sandbox uses command position, not every token;
  - scope target extraction for nested shell scripts matches permission
    executable extraction;
  - command-prefix approvals never apply when analysis reports shell chaining,
    redirection, substitution, or newline segments.

## Night Pass 23 - Reporting And Evidence Support Levels

Current local code:

- `mission.py` defines structured `Evidence`, `Finding`, hosts, services,
  credentials, scope, phase history, and mission state.
- `Finding.__post_init__()` converts legacy raw evidence into structured
  evidence items and deduplicates evidence by key.
- `reporting.py` generates deterministic Markdown with title, executive
  summary, scope, methodology, attack surface, findings, remediation, and
  appendix sections.
- The report says testing was reconstructed from structured mission state and
  recorded tool evidence.
- Findings render `confirmed` versus `unconfirmed/reference`.
- Reference categories such as `cve_reference` and `exploit_reference` are
  excluded from the remediation summary and actionable count.
- Tests verify sections, evidence rendering, severity ordering, empty mission
  behavior, report artifact generation, and evidence metadata roundtrip.

Risks:

- Executive highest severity currently uses all findings, not only confirmed or
  observed affected findings.
- Report methodology can list a tool from a finding field even when no matching
  tool history or evidence source exists.
- Evidence has source, target, snippet, metadata, and timestamp, but there is no
  explicit support level such as observed, inferred, reference, or unsupported.
- A finding with legacy `evidence` text can become report-visible even if the
  parser produced low-confidence or reference-only data.
- Report export does not yet share the future public/private redaction policy.

Plan impact:

- P48/P49 should add `support_level` to findings or evidence:
  - observed;
  - inferred;
  - reference;
  - unsupported.
- Executive severity should be computed from confirmed/observed affected
  findings only.
- Keep reference intelligence in a separate section:
  - CVE metadata;
  - exploit references;
  - EPSS/KEV;
  - public writeups;
  - applicability status.
- Add a pre-report validator:
  - confirmed finding requires at least one evidence item;
  - evidence requires source, target, timestamp, and snippet;
  - methodology tool claim must appear in evidence or tool history;
  - reference-only CVE/exploit stays unconfirmed/reference;
  - unsupported claims are blocked from executive severity.
- Add exact tests:
  - unconfirmed critical reference does not raise executive highest severity;
  - report separates reference intelligence from affected findings;
  - confirmed finding without evidence fails validation;
  - methodology does not claim tools without evidence/tool history;
  - public report export uses the shared redaction policy.

## Night Pass 24 - Built-In Adapter Inventory Recheck

Current local code:

- Importing all built-in tool modules registers 32 tools:
  - 6 system tools;
  - 5 network tools;
  - 5 recon tools;
  - 5 web tools;
  - 4 exploit/reference tools;
  - 4 crypto tools;
  - 3 forensics tools.
- The only registry-level risk bit is currently `dangerous`.
- Very different actions share the same risk shape:
  - `nmap_scan`;
  - `dir_brute`;
  - `waf_detect`;
  - `generate_payload`;
  - `connect_vpn_config`;
  - `disconnect_vpn`;
  - `run_shell`.
- Some passive-looking tools still touch local sensitive files:
  - `file_analyze`;
  - `log_analyze`;
  - `find_files`.
- Several adapters already use streaming helpers and progress:
  - `nmap_scan`;
  - `dir_brute`;
  - `nikto_scan`;
  - `sql_injection_test`;
  - `run_shell`.
- Several tools still use shorter `_run_cmd()` helpers or local `bash -c`
  wrappers for convenience.
- Planner code already turns missing tools and missing wordlists into retry or
  install proposals in some cases, but installation is still represented as a
  `run_shell` action with a command string.

Risks:

- `dangerous=True` cannot distinguish active scan, credentialed action,
  filesystem write, payload generation, VPN/network reconfiguration, or shell
  execution.
- Provider tool-schema selection cannot be reliable without adapter metadata.
- Permission prompts cannot be consistently relevant without adapter resource
  declarations.
- Missing-tool proposals can still be too OS-specific or too command-string
  oriented.
- File-read tools can bypass the user's mental model if they are considered
  non-dangerous by name only.

Plan impact:

- P50 should add an `AdapterSpec` for each tool:
  - technical goal;
  - risk class;
  - target fields;
  - local resource fields;
  - credential fields;
  - required binaries/APIs;
  - install hints per OS/package manager;
  - runtime profile;
  - progress phases;
  - parser;
  - evidence outputs;
  - report mapping;
  - provider schema group.
- P43 should keep `dangerous` only as compatibility and derive approval from
  risk class plus resource analysis.
- P54 should use adapter specs to select provider schemas.
- P47 should use adapter runtime profiles to align registry timeout with tool
  timeout.
- P49 should use adapter specs to generate playbook steps and stop conditions.
- Add tests:
  - every registered built-in tool has an `AdapterSpec`;
  - every `dangerous=True` tool has a non-passive risk class;
  - file tools declare local path resources;
  - provider schema groups match request-context goals;
  - install proposals are structured package intents, not raw apt strings.

## Night Pass 25 - Prompt, Skills, Hooks, And MCP Trust Recheck

Current local code:

- `GeminiProvider._system_instruction()` concatenates the base system
  instruction, model-specific terminal contract, mission context, and extension
  context.
- `extensions.py` loads up to 12 Markdown skills from workspace and global
  directories and injects their content into system context.
- Skill entries include source and path, but not content hash, approval state,
  trust status, or review metadata.
- `output_sanitizer.py` wraps tool outputs in data-boundary markers and filters
  common prompt-injection phrases before they reach memory.
- `hooks.py` loads `.agents/hooks.json` plus global hook files. String hooks are
  converted into `bash -lc` commands and enabled by default.
- Hooks inherit the full environment and receive tool arguments plus tool
  success/error in environment variables.
- `mcp.py` loads workspace/global MCP configs, starts configured commands,
  inherits the full environment plus server env, lists tools, registers MCP
  tools as dangerous, and then exposes them through the normal registry.
- MCP schema conversion preserves top-level parameter type, description, and
  required bit, but drops nested schema metadata such as enum, items, and object
  properties.
- Existing tests focus on display surfaces for `/skills`, `/hooks`, and `/mcp`;
  they do not yet enforce trust, hash, startup gating, env allowlists, or schema
  fidelity.

Risks:

- A workspace skill can become system-level instructions without user review.
- A hook can execute local shell code around a tool call before a dedicated
  extension trust policy exists.
- Hook environment variables can carry sensitive tool arguments to child
  processes.
- MCP startup is a local command execution event before MCP tools are visible to
  the permission engine.
- Inheriting the full environment can leak API keys, tokens, cookies, proxy
  credentials, or local secrets to an MCP server.
- MCP tool schemas may be weakened before provider validation, increasing both
  bad calls and provider rejection.

Plan impact:

- P44 should add `ExtensionTrustStore` before any new extension feature:
  - source type;
  - canonical path or server identity;
  - content/schema hash;
  - first seen and last approved timestamps;
  - review status;
  - allowed workspace roots;
  - risk flags.
- Do not inject untrusted skill content into the system prompt. Show it in the
  `/skills` panel as pending review.
- Disable configured hooks by default until source/path/command hash is
  trusted.
- Gate hook execution through `PermissionEngine` with exact command resources
  for string shell hooks.
- Gate MCP startup before process creation:
  - command preview;
  - source/path/hash;
  - requested env keys;
  - inherited env count;
  - schema hash.
- Use an environment allowlist for MCP startup instead of `os.environ.copy()`.
- Preserve MCP nested schemas and run provider schema preflight before
  registering remote tools.
- Add exact tests:
  - untrusted workspace skill is listed but not injected into system prompt;
  - trusted skill hash is injected and hash drift returns to pending review;
  - string hook defaults to disabled/untrusted;
  - hook execution asks through `PermissionEngine`;
  - hook env redacts sensitive arguments by default;
  - MCP startup does not inherit full environment;
  - MCP server requires approval before process creation;
  - MCP schema preserves enum, array items, and nested object properties;
  - MCP tool output is treated as external untrusted data.

## Night Pass 26 - Prompt Boundary, Parser Context, And Response Duplication

Current local code:

- `GeminiProvider._system_instruction()` appends mission and extension context
  directly into the provider system instruction after the base rules.
- Skills are framed as instructions to follow, then injected into the provider
  context through the main runtime path.
- Tool output is wrapped with explicit data-boundary markers by
  `output_sanitizer.py`.
- The sanitizer filters common prompt-injection phrases, but embedded boundary
  marker strings inside tool output are not neutralized before wrapping.
- Conversation memory stores sanitized tool output, but result parsers consume
  raw `res.output`.
- Parser-derived strings can be promoted into structured memory and mission
  context, then rendered back into the next system prompt.
- `ConversationMemory.trim_to_budget()` exists, but the main LLM path sends
  `memory.get_messages()` directly.
- The agent streams model text before tool calls, then can run a post-tool
  text-only summary pass.
- The renderer flushes accumulated live text once, so repeated user-visible
  paragraphs are more likely to come from the agent loop/provider output than
  from a simple renderer double-flush.
- Mission-state stripping exists for focused answers, but only covers a narrow
  heading shape.

Risks:

- Extension context can override or weaken base safety and formatting rules if
  it is treated as peer system instruction text.
- A malicious tool result can include boundary marker text and confuse the
  model about where trusted instructions end.
- Parser-derived banners, versions, paths, titles, or evidence summaries can
  carry prompt-injection content into future system context.
- Long raw outputs keep being fed to the model even when parsed summaries and
  artifacts would be safer and cheaper.
- Repeated pre-tool and post-tool narratives can create duplicated answer
  blocks in the terminal.
- Narrow local questions can still receive generic mission-state boilerplate
  when the model uses a markdown variant not covered by the stripper.

Plan impact:

- P44 should wrap extension context as lower-trust extension data with explicit
  non-override language, provenance, and role-marker filtering.
- P44 should neutralize boundary marker text inside all tool-derived strings
  before those strings enter memory, structured memory, mission context, or
  provider prompts.
- P48/P55 should treat parser-derived claims as untrusted evidence candidates
  until they have support level, source, target, and timestamp.
- P54 should send compact parsed tool summaries plus artifact references to the
  next provider call, not full raw output by default.
- P54 should enforce provider-budget trimming on the main request path.
- P54 should add response deduplication and collapse pre-tool narrative when the
  same model turn also emits tool calls.
- P48 should strip common mission-state heading variants for narrow answers
  without deleting legitimate answer text.

Add exact tests:

- `test_extension_context_cannot_override_base_safety`;
- `test_boundary_markers_inside_tool_output_are_neutralized`;
- `test_common_prompt_injection_variants_are_filtered`;
- `test_parser_derived_context_treats_tool_strings_as_untrusted`;
- `test_second_llm_turn_receives_compact_parsed_tool_summary_not_full_raw_output`;
- `test_agent_trims_messages_to_provider_budget_before_llm_call`;
- `test_tool_turn_does_not_emit_duplicate_preamble_and_final_answer`;
- `test_focused_answer_strips_markdown_mission_state_variants`.
