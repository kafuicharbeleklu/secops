# SecOps v2 Next Sprint Queue

Date: 2026-06-05

This is the short execution queue derived from:

- `docs/SECOPS_V2_NIGHT_RESEARCH_IMPROVEMENT_PLAN.md`
- `docs/SECOPS_V2_DEEP_RESEARCH_AND_CODE_AUDIT_2026-06-05.md`
- `docs/SECOPS_V2_TOOL_RISK_INVENTORY_2026-06-05.md`

## Sprint Rule

Do not add new user-facing commands, shortcuts, or autonomous chains during
this sprint.

The sprint goal is to make the current agent safer and more predictable before
adding capability.

Before each phase:

1. Identify tests that protect desired behavior.
2. Identify tests that encode known-bad legacy behavior.
3. Rewrite legacy-lock tests with the intended behavior before changing code.
4. Keep PTY tests for visible terminal behavior, not only helper-level strings.

## Current Priority Override

As of 2026-06-05, extension surfaces are not the product priority.

Pause non-essential MCP, skills, artifacts, plugins, and extra slash-command
work after the already-completed safety slice. The next implementation work
must improve the agent's reasoning loop:

1. classify the user's technical intent before choosing tools;
2. expose only tools relevant to that intent;
3. prefer proposals over hidden autonomous chaining;
4. learn from successful and failed attempts without memorizing flags,
   secrets, or exact challenge answers;
5. require evidence compatibility before prior lessons influence ranking;
6. keep local system questions out of the provider/tool-schema path when a
   deterministic answer is available.

Immediate priority order:

1. P54 provider/tool-routing reliability, especially local preflight and tool
   schema reduction;
2. P56 reviewed experience learning, moved forward as the core intelligence
   workstream;
3. P49/P50/P51 capability maturity only where it improves planner quality,
   evidence boards, adapter specs, and install proposals;
4. return to remaining extension governance only when a concrete runtime risk
   blocks the above.

## Phase A - P43 Local Execution Security Hotfixes

Priority: P0

### A0 - Add Risk-Class Vocabulary Without Changing UI Yet

Files:

- `secops_agent/core/tools.py`
- `secops_agent/core/permissions.py`
- `tests/test_agent_permissions.py`

Work:

1. Add internal risk classes matching
   `docs/SECOPS_V2_TOOL_RISK_INVENTORY_2026-06-05.md`.
2. Keep the existing `dangerous` flag for compatibility.
3. Add tests that map representative tools into expected risk classes.

Acceptance:

- No visible prompt behavior changes yet.
- Later approval prompt work has a deterministic risk vocabulary.

### A1 - Fix `ssl_audit`

Files:

- `secops_agent/tools/crypto.py`
- `tests/test_tool_argument_validation.py` or new focused test file

Work:

1. Add strict `host:port` parser.
2. Reject shell metacharacters, newlines, substitutions, and invalid ports.
3. Replace fallback `bash -c` OpenSSL pipeline with subprocess execution that
   does not shell-expand target data.
4. Trim OpenSSL output in Python.
5. Add tests for hostile targets:
   - `example.com:443; id`
   - `example.com:443 && id`
   - `example.com:443 | id`
   - ``example.com:443 `id` ``
   - `example.com:443 $(id)`
   - newline injection.

Acceptance:

- No shell is used with untrusted target data.
- The tool remains usable for valid `host` and `host:port` inputs.

### A2 - Fix Command Substitution And Sudo Detection

Files:

- `secops_agent/core/shell_analysis.py` (new)
- `secops_agent/core/permissions.py`
- `secops_agent/core/sudo.py`
- `secops_agent/core/sandbox.py`
- `secops_agent/core/scope_guard.py`
- `tests/test_agent_permissions.py`

Work:

1. Add a shared `ShellCommandAnalysis` helper with:
   - command segments;
   - executables;
   - nested shell scripts;
   - redirections;
   - command substitutions;
   - network target candidates;
   - sudo usage;
   - unsafe extension flags.
2. Make sudo detection consume the same executable extraction result as command
   permission.
3. Make sandbox and scope consume the same analysis object where possible.
4. Detect or reject backtick command substitution.
5. Keep `$()` detection covered.
6. Treat newlines as command separators for sudo detection and rewrite.
7. Add tests:
   - `echo $(sudo id)`
   - ``echo `sudo id` ``
   - `bash -lc "sudo id"`
   - `echo ok\nsudo id`
   - nested non-sudo command substitution.
8. Add named regression tests:
   - `test_run_shell_sudo_detection_handles_newline_separator`
   - `test_run_shell_force_noninteractive_sudo_rewrites_newline_sudo`
   - `test_shell_analysis_ignores_quoted_non_command_sudo_text`
   - `test_sandbox_uses_command_position_not_every_token`
   - `test_scope_targets_match_nested_shell_analysis`

Acceptance:

- Sudo preflight, command permission, and approval prompt agree.
- Backticks cannot hide a privileged command.
- Newlines cannot hide a privileged command.
- Permission, sudo, sandbox, and scope do not parse shell commands with
  divergent rules.

### A3 - Enforce File Tool Path Policy

Files:

- `secops_agent/core/agent.py`
- `secops_agent/core/permissions.py`
- `secops_agent/tools/forensics.py`
- `tests/test_agent_permissions.py`

Work:

1. Replace or augment `evaluate_tool()` with argument-aware permission checking.
2. Normalize registered tool names:
   - `file_analyze`
   - `log_analyze`
   - `find_files`
3. Make sensitive local reads ASK/DENY before opening files.
4. Add tests:
   - `file_analyze('/etc/shadow')`
   - `file_analyze('~/.ssh/id_rsa')`
   - `log_analyze('/etc/shadow')`
   - `find_files('/', pattern='suid')`
   - workspace-safe file read remains allowed when policy permits.

Acceptance:

- Permission is decided before any sensitive file access.
- Existing allowed workspace workflows remain usable.

### A4 - Verify P43

Commands:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_agent_permissions.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
  tests/test_tool_argument_validation.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q secops_agent tests scratch
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
```

Stop condition:

- Do not continue to TUI/VPN refactor until P43 tests are green.

### A5 - Keep Tool Permission, Command Permission, And Sudo UI Aligned

Files:

- `secops_agent/core/agent.py`
- `secops_agent/core/permissions.py`
- `secops_agent/core/sudo.py`
- `secops_agent/tools/forensics.py`
- `tests/test_agent_permissions.py`

Work:

1. Ensure VPN and other internal privileged tool paths use the same resource
   analysis vocabulary as `run_shell`.
2. Do not display a sudo password prompt when the current sandbox mode will
   block sudo anyway.
3. Normalize permission prompt text around the smallest meaningful resource:
   executable, tool, or safe prefix, not a huge full command when avoidable.
4. Preserve current safeguards:
   - compound/high-impact exact commands get no session/persistent allow;
   - `nmap target` prefix does not allow appended shell control operators;
   - low-risk simple commands can still use persistent prefix approvals.
5. Add risk-class and feasibility detail to approval copy after A0 exists.

Acceptance:

- The approval surface does not imply that a command can run when sandbox mode
  will block it.
- Permission decisions are consistent across `run_shell`, VPN tools, and other
  local privileged commands.

## Phase B - P44 Agentic Extension Governance

Priority: Paused after completed safety slice

Note:

- Do not continue P44 unless an extension runtime risk directly blocks the
  reasoning, learning, or tool-routing workstreams.
- Treat P44 as P0 for existing hooks and MCP startup paths once P43 is green.
  This is not only preparation for future features: current config-driven
  hooks and `/mcp start` already execute local commands.

Implemented slice:

- skills now carry source/path/content hash and untrusted skills are listed but
  not injected into the prompt;
- trusted skill context is framed as lower-trust extension data;
- hooks default to disabled unless the configured command hash is trusted;
- hook execution uses an allowlisted environment and redacts sensitive args;
- MCP configs loaded from disk require a matching trusted hash before startup;
- MCP startup uses an allowlisted environment instead of full inheritance;
- MCP tool schemas preserve enum, array items, defaults and nested objects.

Work:

1. Add provenance records for loaded skills:
   - source;
   - path;
   - content hash;
   - load time.
2. Add an `ExtensionTrustStore` with:
   - source type: workspace, global, user, managed;
   - canonical path or server URI;
   - content/schema hash;
   - first seen and last approved timestamps;
   - approved workspace roots;
   - risk flags;
   - review status.
3. Keep `/skills`, `/hooks`, and `/mcp` as panels; do not add mutation commands
   in this sprint.
4. Gate hook execution and MCP startup through an explicit trust/permission
   policy.
5. Treat MCP tool names, descriptions, schemas, and outputs as untrusted
   external data.
6. Do not inject untrusted skills into the system prompt.
7. Frame trusted extension context as lower-trust extension data:
   - explicit non-override language;
   - provenance labels;
   - role-marker filtering;
   - no raw peer system-prompt wording.
8. Neutralize prompt and boundary markers in extension text, MCP descriptions,
   MCP outputs, hook text, and parser-derived strings before prompt injection.
9. Disable configured hooks by default until their source and command hash are
   trusted.
10. Require MCP server approval by server identity and schema hash before
   startup.
11. Gate MCP startup command and environment:
   - show source/path/hash;
   - show command preview;
   - show inherited environment count;
   - use an allowlist instead of full environment inheritance by default.
12. Gate hooks through `PermissionEngine`:
   - string shell hooks are high-risk exact-only;
   - argv hooks are preferred;
   - hooks do not inherit secrets by default.
13. Preserve richer MCP schema constraints when possible:
   - enum;
   - items;
   - defaults;
   - bounds;
   - nested object shape.
14. Add response isolation for MCP output:
   - structured return schemas where possible;
   - untrusted output labels;
   - no direct promotion of free text to planning facts.
15. Add durable audit events:
   - extension loaded/trusted;
   - hook run;
   - MCP start requested/allowed/denied;
   - tool registered/unregistered;
   - approval decision.
16. Add named tests:
   - `test_untrusted_workspace_skill_is_listed_but_not_injected`;
   - `test_trusted_skill_hash_is_injected`;
   - `test_skill_hash_drift_returns_to_pending_review`;
   - `test_extension_context_cannot_override_base_safety`;
   - `test_boundary_markers_inside_tool_output_are_neutralized`;
   - `test_common_prompt_injection_variants_are_filtered`;
   - `test_string_hook_defaults_to_disabled_untrusted`;
   - `test_hook_execution_asks_permission_engine`;
   - `test_hook_env_redacts_sensitive_arguments`;
   - `test_mcp_startup_does_not_inherit_full_environment`;
   - `test_mcp_server_requires_approval_before_process_creation`;
   - `test_mcp_schema_preserves_enum_array_and_nested_objects`;
   - `test_mcp_tool_output_is_untrusted_external_data`.

Acceptance:

- Existing extension panels remain sparse and read-only by default.
- Hook/MCP execution cannot happen silently from global or workspace config.
- Extension provenance is visible and auditable.
- Modified MCP schemas require a fresh approval.
- Poisoned descriptions and return values are displayed as untrusted data, not
  treated as instructions.
- `always-proceed` does not silently turn untrusted extension startup into an
  unreviewed local command path.
- Boundary markers appearing inside tool or extension content cannot break the
  trusted/untrusted prompt boundary.

## Phase C - P45 Resume And `ctrl+o`

Priority: P1

Work:

1. Split session identity:
   - `resumed_from` is the immutable loaded source;
   - `current_session_name` is a new autosave target for this launch;
   - only explicit `/save <same-name>` can overwrite a prior session.
2. Add a private `TranscriptJournal` instead of relying only on message replay:
   - prompt rows;
   - model text rows;
   - tool call rows;
   - tool result rows;
   - permission rows;
   - status and error rows;
   - artifact references;
   - stable row IDs.
3. Persist collapsed and expanded payload references for expandable rows.
4. Clear live `ctrl+o` anchors on `/resume`, `/load`, `--session`, and
   `/clear`.
5. Bound visible transcript replay.
6. Keep `/export` redacted and report-like; exact replay remains private local
   session state.
7. Persist default permission mode and sandbox preference separately from
   per-session runtime state.
8. Add PTY tests:
   - old anchor after resume;
   - no saved sessions;
   - long transcript;
   - tool result followed by text then `ctrl+o`.
9. Add a stream-level regression where the renderer itself, not the test,
   computes the tail lines between tool result and final prompt.
10. Add degradation behavior:
   - if a saved session has no journal, rebuild from messages;
   - mark rebuilt transcript as approximate;
   - do not create tail duplicates when a historical row cannot be expanded.

Acceptance:

- No duplicate or stale expansion rows.
- Resume visually restores a bounded conversation thread.
- Resuming an old session does not silently overwrite that old session on exit.
- Expanding a non-last tool row happens at its original position when possible,
  or reports that no current expandable block is available.

## Phase D - P46 VPN Ownership

Priority: P1

Work:

1. Track pre-existing TUN interfaces before connect.
2. Prefer OpenVPN `--writepid`, `--status`, and explicit log paths.
3. Store SecOps-owned PID/config/log metadata.
4. Disconnect owned VPN process by default.
5. Add explicit high-risk option only for killing all OpenVPN processes.
6. Replace `nohup ... & echo $!` launching with a supervised or explicitly
   owned background service path.
7. Clean up owned child processes on cancellation and failed handshakes.
8. Distinguish states precisely:
   - `pre-existing`;
   - `starting`;
   - `pending-handshake`;
   - `connected`;
   - `failed`;
   - `stale`;
   - `disconnected`.
9. Add named tests:
   - `test_connect_vpn_config_refuses_to_start_when_openvpn_process_already_running`;
   - `test_connect_vpn_config_cleans_started_pid_on_cancellation`;
   - `test_disconnect_vpn_does_not_kill_untracked_openvpn_process`;
   - `test_connect_vpn_config_wait_limit_reports_pending_not_connected`.

Acceptance:

- Network/firewall failure is reported as handshake/connectivity failure.
- Pre-existing VPN does not produce false success.
- SecOps does not kill unrelated VPNs by default.
- Outer tool timeout or user cancellation does not orphan a SecOps-started VPN.

## Phase E - P47 Long-Running Tool Consistency

Priority: P1

Work:

1. Audit `_run_cmd` paths.
2. Promote `ExecutionSupervisor` into a declared runtime contract:
   - `max_runtime`;
   - `inactivity_timeout`;
   - `progress_interval`;
   - expected quiet phases;
   - cancel policy;
   - spool policy;
   - result parser;
   - structured error parser.
3. Move long or shell-spawning tools to supervisor/supervisor-light.
4. Preserve timeout metadata even when stdout exists.
5. Harmonize status markers by actual execution state.
6. Add cancellation/process-group tests.
7. Align the external `ToolRegistry.execute()` timeout with each tool's
   declared runtime budget so a 300s or 600s tool is not cut by the default
   120s registry timeout.
8. Emit useful quiet-period progress:
   - elapsed;
   - last output age;
   - process PID;
   - output lines/chars;
   - current phase;
   - cancel hint.
9. Harden `_run_cmd` for the remaining short commands:
   - `stdin=DEVNULL`;
   - process-group cleanup where needed;
   - `wait()` after kill;
   - no interactive sudo probes in non-interactive helpers.
10. Store recent progress messages in the active tool transcript so `ctrl+o`
    can show the current phase before the final result exists.
11. Add named tests:
    - `test_ctrl_o_during_running_tool_shows_latest_progress_detail`.

Acceptance:

- No "terminal frozen" long task without progress.
- Timeout is not parsed as success.
- Cancel updates task state and stops child processes.
- `ctrl+o` on a running long task shows latest progress, not only the static
  tool-call row.

## Phase F - P48 Engagement Context

Priority: P1

Work:

1. Persist `EngagementContext`.
2. Store platform hint separately from technical task.
3. Add authorization, in-scope, out-of-scope, allowed techniques, stop
   conditions, and data sensitivity.
4. Add strict pre-action scope checks for active network tools.
5. Convert textual RoE into structured constraints:
   - allow exploitation;
   - allow bulk download;
   - allow credential testing;
   - allow password spray;
   - rate limit;
   - time window;
   - data handling;
   - proof limits.
6. Add `RoEGuard` before planner ranking and before execution.
7. Add request-context matrix tests across CTF, HTB, Root-Me, private VM, and
   authorized assessment wording.
8. Extend the existing lab replay harness with interaction-level replays for:
   - local time/OS/IP narrow questions;
   - VPN connect/fail/retry/disconnect;
   - CTF questionnaire flow;
   - private VM port scan;
   - missing tool/wordlist;
   - sudo install/update request.
9. Add response-shape fixtures for narrow local questions:
   - time;
   - OS;
   - IP;
   - VPN status.
10. Expose `OUT_OF_SCOPE` from request classification when the current prompt
   names a target that matches `mission.scope.out_of_scope` or falls outside an
   explicit in-scope list.
11. Bind report claims to evidence records:
   - vulnerability category;
   - threat;
   - root cause when known;
   - testing technique;
   - remediation;
   - severity.
12. Add pre-report validation:
   - confirmed finding requires evidence;
   - evidence requires source, target, timestamp, and snippet;
   - methodology tool claim must appear in evidence or tool history;
   - reference-only CVE/exploit stays unconfirmed/reference.
13. Add report support levels:
   - observed;
   - inferred;
   - reference;
   - unsupported.
14. Calculate executive severity only from observed/confirmed affected findings.
15. Separate "Reference Intelligence" from "Affected Findings".
16. Add `support_level` for reportable claims:
   - observed;
   - inferred;
   - reference;
   - unsupported.
17. Compute executive highest severity only from confirmed/observed affected
    findings.
18. Add named tests:
   - `test_unconfirmed_critical_reference_does_not_raise_executive_severity`;
   - `test_report_separates_reference_intelligence_from_affected_findings`;
   - `test_confirmed_finding_without_evidence_fails_report_validation`;
   - `test_methodology_does_not_claim_tools_without_evidence_or_history`;
   - `test_public_report_export_uses_redaction_policy`.
19. Add parser-to-context safety tests:
   - `test_parser_derived_context_treats_tool_strings_as_untrusted`.

Acceptance:

- Same technical request behaves consistently across environments.
- Environment does not override scope.
- Out-of-scope is visible to the LLM and execution gate.
- Replays assert tool count, permission prompt shape, and stop-after-requested
  behavior.
- Narrow local answers do not append a generic mission-state block.
- Parser-derived strings cannot become trusted prompt instructions.

## Phase G - P49/P50/P51 Capability Maturity

Priority: P2

Only start after P43-P48.

Work:

1. Reviewed playbook layer from curated labs and experience memory.
2. Tool adapter contract for optional tools.
3. Vulnerability intelligence enrichment with candidate/validated separation.
4. Provider-schema compatibility tests for every new adapter.
5. Durable task tree for reviewed playbook execution:
   - objective;
   - evidence;
   - failed attempts;
   - proposed next action;
   - user approval state;
   - stop condition.
6. Add an internal evidence board before any future multi-agent/swarm feature:
   - confirmed facts;
   - hypotheses;
   - blockers;
   - attempted actions;
   - failed assumptions;
   - proposed next actions;
   - evidence references.
7. Compatibility gates before lesson/playbook influence:
   - service family;
   - port/protocol;
   - endpoint evidence;
   - failure mode;
   - risk class;
   - platform tag as weak metadata only.
8. Heavy-tool adapter conformance fixtures before registration:
   - passive observation;
   - active scan;
   - request mutation;
   - credentialed action;
   - password spray;
   - remote command execution;
   - file upload/download;
   - exploit/payload action.
9. Internal-network tools must expose credential handling, rate limits,
   retention policy, and evidence output before they can be proposed.
10. Add evaluation fixtures that avoid known-lab contamination:
   - synthetic transcripts;
   - isolated local services;
   - mocked tool outputs;
   - negative cases where a previous pattern must not apply;
   - scoring for stop point, evidence, and tool count.
11. Add adapter spec fields:
   - binary/API requirements;
   - version/provenance;
   - risk class;
   - target fields;
   - credential fields;
   - timeout/inactivity profile;
   - output format;
   - parser;
   - artifact outputs.
12. Parse structured adapter errors:
   - missing dependency;
   - timeout;
   - authentication required;
   - scope blocked;
   - rate-limit blocked.
13. Make install proposals OS/package-manager aware instead of apt-only.
14. Add conformance tests:
   - `test_every_builtin_tool_has_adapter_spec`;
   - `test_every_dangerous_tool_has_non_passive_risk_class`;
   - `test_file_tools_declare_local_path_resources`;
   - `test_provider_schema_groups_match_request_context_goals`;
   - `test_install_proposals_are_structured_package_intents`.

Acceptance:

- More capability without hidden autonomy.
- Missing tools produce install proposals, not sudden sudo actions.
- CVE/EPSS/KEV are prioritization signals, not exploit triggers.
- Playbooks explain why a pattern matches and what evidence is still missing.
- The evidence board is auditable and scope-bound before any swarm-like
  behavior is considered.

## Phase H - P54 Provider Reliability

Priority: P1 after P43-P48, or earlier if live testing keeps producing provider
errors.

Work:

1. Add retriable handling for provider `500 INTERNAL` / `internal` errors.
2. Keep tool-schema `400 INVALID_ARGUMENT` non-retriable.
3. Add response deduplication/anomaly detection for repeated paragraphs.
4. Disable SDK automatic function calling when SecOps uses manual tool
   orchestration.
5. Add a `ToolSchemaSelector` driven by `RequestDecision`:
   - local system questions expose no remote/pentest tools;
   - lab-readiness exposes setup/status tools only;
   - port scans expose scan tools only;
   - web directory enum exposes directory tools only;
   - reports expose reporting tools only;
   - unknown or high-risk prompts expose a minimal safe set or ask for scope.
6. Stop sending the full registry to the provider by default.
7. Add deterministic local-answer path for time, OS, IP, and VPN status where
   a local preflight can answer without waiting on the model.
8. Add provider compatibility matrix tests for:
   - function declarations;
   - Google Search grounding;
   - thinking config;
   - tool schema size;
   - malformed response handling.
9. Add replay tests for observed failures:
   - GoBuster directory request does not fail because unrelated tools were sent;
   - local time question works when provider is unavailable;
   - VPN status routes to `vpn_status`;
   - retry after provider `500` does not duplicate paragraphs.
10. Add named provider/schema tests:
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
11. Treat `INVALID_ARGUMENT` fallback as a special tool-schema recovery path,
    not as a generic retry policy:
   - one fallback maximum;
   - only with reduced or empty schema;
   - no tool execution before fallback response is reviewed.
12. Replace full raw tool output in the next provider turn with compact parsed
    summaries plus artifact references when a parser is available.
13. Enforce token-aware message trimming on the main provider-call path, not
    only in helper methods.
14. Collapse or suppress pre-tool narrative when the same model turn also emits
    tool calls.
15. Add focused answer cleanup for mission-state heading variants:
    - `Mission State`;
    - `Current Mission State`;
    - markdown heading variants;
    - localized equivalents used by the prompts.
16. Add named tests:
   - `test_second_llm_turn_receives_compact_parsed_tool_summary_not_full_raw_output`;
   - `test_agent_trims_messages_to_provider_budget_before_llm_call`;
   - `test_tool_turn_does_not_emit_duplicate_preamble_and_final_answer`;
   - `test_focused_answer_strips_markdown_mission_state_variants`.

Implemented slice:

- `ToolSchemaSelector` now limits provider tool schemas by `RequestDecision`;
- local system questions expose no provider tools;
- time, OS, IP, and hostname questions can be answered deterministically without
  calling the provider;
- VPN status/connect/disconnect still route through local preflight tools;
- port scan prompts expose only scan-relevant tools;
- web directory prompts expose only `dir_brute`;
- exploit-step prompts expose no function tools by default.

Acceptance:

- Simple local questions do not fail only because the provider is down.
- Provider instability is reported once, compactly.
- No repeated paragraph blocks reach the terminal unchecked.
- The provider receives only tools relevant to the current technical goal.
- Long tool output is kept in artifacts/transcripts while the provider receives
  compact, evidence-bound summaries.

## Phase I - P55 Data Retention And Secret Hygiene

Priority: P1 after P43-P48, or earlier before adding credentialed/internal
network adapters.

Work:

1. Centralize `SECOPS_HOME`.
2. Add shared private-storage helpers:
   - `secops_home()`;
   - `ensure_private_dir(path, mode=0o700)`;
   - `write_private_text(path, text, mode=0o600)`;
   - `append_private_jsonl(path, event, mode=0o600)`.
3. Create storage directories as `0700` and files as `0600`.
4. Validate session/export names as strict safe slugs.
5. Add common `RedactionPolicy` for:
   - sessions;
   - exports;
   - traces;
   - artifacts;
   - attachment previews;
   - tool summaries.
6. Separate exact private replay bundles from public redacted exports.
7. Add retention defaults and cleanup dry-run:
   - sessions: last N or 90 days;
   - spools/VPN logs: 7-14 days;
   - app logs/traces: 14 days;
   - experience lessons: bounded count or 180 days.
8. Add tests for path traversal rejection, file modes, redaction, raw export
   opt-in, and retention dry-run.
9. Add named tests:
   - `test_session_name_cannot_escape_sessions_directory`;
   - `test_export_name_cannot_escape_exports_directory`;
   - `test_storage_writes_private_file_modes`;
   - `test_secops_home_subdirs_are_private`;
   - `test_attachment_preview_redacts_obvious_secrets`;
   - `test_public_export_redacts_targets_and_secrets_by_default`;
   - `test_private_replay_export_keeps_exact_content_with_private_marker`.

Acceptance:

- No session/export name can escape the intended directory.
- Private logs are not world-readable under normal umask variants.
- Public export is redacted by default.
- Exact replay remains possible as a private local artifact.

## Phase J - P56 Reviewed Experience Learning

Priority: P0/P1 now, after the first P54 routing slice.

This phase is now a core intelligence workstream, not a late enhancement.
Storage hygiene from P55 still matters before long-term retention is enabled,
but the compatibility gates and review state can be implemented immediately
with private, bounded test fixtures.

Work:

1. Add review state to lessons:
   - unreviewed;
   - reviewed;
   - deprecated;
   - blocked.
2. Add provenance fields:
   - source session;
   - source type;
   - tool;
   - evidence references;
   - created and expiry timestamps.
3. Exclude raw flags, secrets, credentials, private keys, cookies, and exact
   challenge answers from experience memory.
4. Keep unreviewed lesson influence explanation-only.
5. Require compatibility gates before a lesson affects next-action ranking:
   - service;
   - port/protocol;
   - endpoint evidence;
   - failure mode;
   - risk class;
   - required credential state;
   - platform tag as weak metadata only.
6. Store failed attempts as useful lessons when they identify:
   - missing local tool;
   - blocked network;
   - missing wordlist;
   - timeout;
   - scope mismatch;
   - wrong exploit family.
7. Add replay evaluation:
   - synthetic lab transcripts;
   - private VM style tasks;
   - negative cases where a tempting lesson must not apply;
   - scoring for correct stop point and evidence-bound answer.
8. Display lesson influence in suggestions:
   - why it matches;
   - what evidence is missing;
   - why it is not executed automatically.

Implemented slice:

- lessons now have `review_status`, `source_type`, `evidence_refs`, and
  `expires_at`;
- unreviewed lessons are explanation-only and do not change action priority;
- reviewed lessons can influence ranking only after compatibility gates pass;
- blocked, deprecated, or expired lessons are ignored;
- service-family and endpoint gates prevent tempting but incompatible lessons;
- obvious flags, secrets, credentials, cookies, private keys, and exact
  challenge-answer patterns are redacted from lesson text.
- P56/B adds a local `review_lesson` API without new user commands;
- review metadata now stores why a lesson was reviewed;
- suggested actions can show `Lesson`, `Match`, and `Missing` context;
- influence details distinguish boost, downrank, and explanation-only lessons.
- P56/C adds deterministic replay scoring for stop point, evidence binding,
  tool count, scope binding, and CTF contamination checks.
- Scored replays now cover lab/CTF, private VM, and authorized client paths.
- Endpoint-specific lessons no longer influence generic actions before matching
  endpoint evidence exists.
- P56/D adds local suggestion-learning signals:
  `suggested`, `selected`, `ignored`, `succeeded`, and `failed`.
- P56/D adds a promotion gate: reviewed lesson, passing replays, and a matching
  successful selected action are required before stronger reuse.
- P56/E aggregates repeated signals to separate useful tactics, noise, ignored
  actions, and repeated failures.
- P56/E exposes these metrics through internal `ExperienceStore` audit data.
- P56/E applies only weak planner influence: limited boost, limited downrank,
  or explanation-only.
- P56/F defines controlled technical playbooks.
- P56/F creates playbooks only from reviewed lessons with passing replays,
  available evidence, and enough successful suggestion signals.
- P56/F keeps playbooks proposal-only with explicit safety constraints:
  scope, permission, evidence, and stop point remain mandatory.
- P56/G wires controlled playbooks into planner suggestions only.
- P56/G requires current technical evidence before suggesting a playbook:
  matching service family and endpoint hints must be visible in mission state.
- P56/G keeps playbooks behind the normal registry and scope filters.
- P56/G prevents proposal-only playbooks from entering automatic planner
  chaining, even when automatic planner execution is enabled.
- P56/G adds negative tests for out-of-scope playbooks, missing local tools,
  missing service evidence, and no auto-chain behavior.
- P56/H adds an internal planner learning audit via `learning_audit()`.
- P56/H records lesson/playbook decisions as applied, rejected, or
  explanation-only.
- P56/H records service match, endpoint match, scope result, registry result,
  proposal-only status, reasons, missing evidence, and priority delta.
- P56/H keeps the audit internal: no new slash command, artifact, MCP surface,
  or user-facing shortcut.
- P56/H adds tests proving rejected lessons/playbooks leave auditable reasons
  without changing ranking or execution.
- P56/I introduces a single `LessonMatchDecision` path for lesson
  compatibility, score, effect, and audit status.
- P56/I makes `retrieve_similar_lessons()`, `lesson_is_compatible()`,
  `lesson_influence_detail()`, planner ranking, and planner audit consume the
  same decision data.
- P56/I removes duplicated lesson service/endpoint/action-family audit logic
  from the planner.
- P56/I adds non-divergence tests for service mismatch, unreviewed lessons,
  blocked local tools, and registry-missing actions.
- P56/J adds risk/access compatibility gates before reviewed lessons influence
  ranking.
- P56/J records tool risk metadata on `ToolResult`, so generated lessons keep
  their risk class.
- P56/J blocks exploitation, authenticated, privilege-escalation, and
  post-exploitation lessons when the mission lacks matching access evidence.
- P56/J extends the internal learning audit with `risk_match`, `access_match`,
  `required_access`, and `current_access`.
- P56/J adds tests for risk mismatch, missing shell, shell present, and risk
  metadata persistence.
- P56/K applies risk/access metadata to controlled playbooks.
- P56/K stores risk class and required access on promoted playbook steps.
- P56/K rejects playbook suggestions when the mission lacks compatible access
  evidence.
- P56/K includes playbook risk/access state in internal planner audit entries.
- P56/K enriches suggestion signals with audit status and audit reasons, so
  signal aggregation can learn from applied/rejected planner decisions.
- P56/K keeps playbooks proposal-only and verifies they still cannot enter
  automatic execution.

Next slice:

- P56/L should make suggestion-signal learning context-bound:
  - include service, endpoint, risk, and access fingerprints in signal-family
    matching;
  - prevent repeated success for one tool from boosting unrelated targets or
    phases;
  - keep weak boosts only when current evidence matches the signal context;
  - keep rejected audit reasons as negative context, not generic permanent
    downranks.
- Keep this internal: no new commands, shortcuts, artifacts, MCP, or skills.

Acceptance:

- Experience improves proposals without hidden autonomy.
- Old CTF answers and flags are not memorized as reusable facts.
- A prior lesson cannot bypass scope, permission, evidence, risk, access, or
  stop conditions.

## Current Verification Baseline

Last observed after P56/K playbook risk/access and signal-audit slice:

```text
compileall: OK
unittest discover: 515 tests, OK
docs non-URL line length check: OK
git status: unavailable in this checkout, not a git repository
```
