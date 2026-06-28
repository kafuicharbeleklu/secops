# SecOps v2 Research Source Index

Date: 2026-06-05

This index maps external research sources to concrete SecOps v2 decisions.
It intentionally avoids turning every useful website into a new feature.

## Methodology And Scope Governance

### NIST SP 800-115

Source:

- https://csrc.nist.gov/pubs/sp/800/115/final

SecOps decision:

- Keep planning, authorization, evidence, findings, and reporting as first
  class mission objects.
- Do not let "CTF", "lab", or "private VM" become a shortcut around scope and
  rules of engagement.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### PTES

Source:

- https://www.pentest-standard.org/index.php/Main_Page

SecOps decision:

- Keep pre-engagement, intelligence gathering, threat modeling,
  vulnerability analysis, exploitation, post-exploitation, and reporting as
  distinct workflow stages.
- The agent can assist CTFs, labs, private VMs, and client work with the same
  technical workflow, but authorization and reporting fields must remain
  explicit.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### OWASP Web Security Testing Guide

Source:

- https://owasp.org/www-project-web-security-testing-guide/

SecOps decision:

- Use WSTG as a coverage vocabulary for web testing.
- A report can say a category was tested only when evidence exists.
- Web findings should keep vulnerability type, threat, root cause, testing
  technique, remediation, and severity as separate report fields.

Mapped tickets:

- P49 Reviewed Playbooks
- P50 Tool Adapter Contract

### OWASP ASVS

Source:

- https://owasp.org/www-project-application-security-verification-standard/

SecOps decision:

- Use ASVS as a control vocabulary for web/API verification and report
  coverage.
- Do not mark an ASVS control as verified without evidence from a tool,
  observation, or explicit user-provided fact.
- Keep ASVS mapping separate from CTF answer extraction.

Mapped tickets:

- P49 Reviewed Playbooks
- P51 Vulnerability Intelligence

### OWASP APTS Scope Enforcement

Sources:

- https://owasp.org/APTS/
- https://owasp.org/APTS/standard/1_Scope_Enforcement/
- https://owasp.org/APTS/standard/appendix/Rules_of_Engagement_Template.html

SecOps decision:

- Autonomous or assisted pentest actions need explicit scope enforcement before
  network activity.
- Scope must remain a deterministic execution gate, not only a prompt hint.
- Rules of engagement should be machine-readable enough to separate
  authorization, scope, safety controls, timing, prohibited techniques, and
  reporting requirements.

Mapped tickets:

- P43 Local Execution Security
- P48 Engagement Context

## Agentic Security

### OWASP AI Agent Security Cheat Sheet

Source:

- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

SecOps decision:

- Treat every tool, skill, hook, MCP server, and shell adapter as a privileged
  execution surface.
- Keep least privilege, human approval, audit logs, and environment isolation
  as product requirements.

Mapped tickets:

- P43 Local Execution Security
- P44 Agentic Extension Governance
- P56 Reviewed Experience Learning

### OWASP Prompt Injection Prevention Cheat Sheet

Source:

- https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

SecOps decision:

- Do not let page content, tool output, logs, or challenge text directly alter
  system behavior.
- Tool outputs should be parsed into structured evidence and blockers before
  they influence planning.

Mapped tickets:

- P49 Reviewed Playbooks
- P56 Reviewed Experience Learning
- P50 Tool Adapter Contract

### OWASP MCP Tool Poisoning

Source:

- https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
- https://owasp.org/www-project-mcp-top-10/

SecOps decision:

- Future MCP integration requires startup trust policy, tool declaration review,
  and permission separation from ordinary local tools.
- MCP security must cover the whole lifecycle: server startup, tool schema,
  prompt/context exposure, runtime execution, memory references, and audit.

Mapped tickets:

- P44 Agentic Extension Governance

### OWASP Top 10 For Agentic Applications

Source:

- https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/

SecOps decision:

- Treat goal hijack, tool misuse, identity abuse, supply-chain poisoning,
  unexpected code execution, memory poisoning, and cascading failures as
  first-class design threats.
- Do not expose broad tool schemas, hooks, MCP servers, or experience memory
  without trust, provenance, and user-visible control.

Mapped tickets:

- P43 Local Execution Security
- P44 Agentic Extension Governance
- P54 Provider Reliability
- P56 Reviewed Experience Learning

### OWASP Agentic Skills Top 10

Sources:

- https://owasp.org/www-project-agentic-skills-top-10/
- https://owasp.org/www-project-agentic-skills-top-10/checklist.html

SecOps decision:

- Skill/playbook reuse is useful only after review, provenance, scope binding,
  and audit logging.
- Experience memory must not become hidden autonomy.

Mapped tickets:

- P49 Reviewed Playbooks
- P44 Agentic Extension Governance

## Logs, Secrets, And Retention

### OWASP Logging Cheat Sheet

Source:

- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

SecOps decision:

- Sessions, tool outputs, spools, VPN logs, traces, exports, and artifacts are
  all log-like records and can contain sensitive data.
- Logging should exclude, mask, sanitize, hash, or encrypt secrets and sensitive
  values by default.

Mapped tickets:

- P55 Data Retention And Secret Hygiene

### OWASP Secrets Management Cheat Sheet

Source:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

SecOps decision:

- Credentials, API keys, cookies, private keys, VPN material, and tokens require
  lifecycle handling: creation, rotation, revocation, expiration, and audit.
- Secret values should not be persisted in transcripts, spools, or experience
  memory unless the user explicitly exports raw private evidence.

Mapped tickets:

- P43 Local Execution Security
- P55 Data Retention And Secret Hygiene

### NIST SP 800-92 Log Management

Source:

- https://csrc.nist.gov/pubs/sp/800/92/final

SecOps decision:

- Treat log generation, storage, access, analysis, and disposal as product
  requirements.
- Retention windows should be explicit and configurable; disposal is part of the
  feature, not a manual cleanup afterthought.

Mapped tickets:

- P55 Data Retention And Secret Hygiene

## CLI And Long Running Execution

### OpenAI Codex CLI

Sources:

- https://developers.openai.com/codex/cli
- https://developers.openai.com/codex/security

SecOps decision:

- Treat approvals, sandboxing, web search, MCP, skills, and subagents as
  separate product surfaces with explicit policy.
- Do not solve long-running operations only with larger timeouts; combine
  sandbox state, approval state, progress, cancellation, and resumable task
  state.
- Exact replay and private/local session state should be distinct from public
  export.

Mapped tickets:

- P43 Local Execution Security
- P45 Resume And ctrl+o
- P47 Long Running Tool Consistency
- P55 Data Retention And Secret Hygiene

### Antigravity CLI Permissions

Source:

- https://antigravity.google/docs/cli-permissions?hl=ko

SecOps decision:

- Permission prompts should be based on explicit resources such as
  `command(target)`, `file(path)`, `url(target)`, or `mcp(server/tool)`.
- Deny, ask, and allow lists should be evaluated with clear precedence.
- Approval prompts should allow a meaningful scope, not a raw accidental full
  shell string.

Mapped tickets:

- P43 Local Execution Security
- P46 VPN Ownership
- P44 Agentic Extension Governance

### Claude Code CLI Reference

Source:

- https://docs.claude.com/en/docs/claude-code/cli-reference

SecOps decision:

- Resume/session management and background session controls should be treated
  as product primitives, not as transcript side effects.
- PTY-backed background execution is a useful pattern for long-running shell
  jobs, but SecOps should still keep sudo/password handling explicit and local.

Mapped tickets:

- P45 Resume And ctrl+o
- P47 Long Running Tool Consistency

### GitHub Copilot CLI Best Practices

Source:

- https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/copilot-cli/cli-best-practices

SecOps decision:

- Allow/deny tool patterns and "allow once vs allow for session" are the right
  mental model for permission prompts.
- Planning mode reinforces SecOps' proposal-first stance.
- Custom providers must support streaming and tool calling; SecOps provider
  compatibility tests should make this explicit.

Mapped tickets:

- P43 Local Execution Security
- P47 Long Running Tool Consistency
- P50 Tool Adapter Contract

### Command Line Interface Guidelines

Source:

- https://clig.dev/

SecOps decision:

- Keep the default screen sparse.
- Provide useful status for long operations.
- Put large detail behind explicit expansion or review commands.

Mapped tickets:

- P45 Resume And ctrl+o
- P47 Long Running Tool Consistency

### Rich Progress

Source:

- https://rich.readthedocs.io/en/latest/progress.html

SecOps decision:

- A long task should have an explicit task state: queued, running, completed,
  failed, cancelled, timed out.
- Progress rendering should be driven by task state, not by permission state.

Mapped tickets:

- P47 Long Running Tool Consistency

### OpenVPN Process Control

Source:

- https://openvpn.net/community-resources/controlling-a-running-openvpn-process/

SecOps decision:

- Use OpenVPN process ownership metadata such as PID and status files.
- Disconnect should target SecOps-owned OpenVPN processes by default, not every
  OpenVPN process on the host.

Mapped tickets:

- P46 VPN Ownership

## Pentest Tools And Structured Output

### DFIR And Detection Tooling

Sources:

- https://github.com/volatilityfoundation/volatility3
- https://volatilityfoundation.org/the-volatility-framework/
- https://docs.velociraptor.app/docs/
- https://github.com/SigmaHQ/sigma
- https://sigmahq.io/docs/guide/about
- https://yara.readthedocs.io/en/latest/

SecOps decision:

- Forensics and detection tooling should be treated as evidence collection and
  analysis adapters, not as hidden autonomous remediation.
- Volatility and Velociraptor outputs should produce structured evidence,
  artifacts, and retention-sensitive logs.
- Sigma and YARA support should be review-first: rule provenance, rule quality,
  and false-positive handling matter before automatic conclusions.

Mapped tickets:

- P50 Tool Adapter Contract
- P55 Data Retention And Secret Hygiene

### ProjectDiscovery Docs And Repositories

Sources:

- https://docs.projectdiscovery.io/
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/naabu

SecOps decision:

- Prefer JSON/JSONL-capable tools when adding optional adapters.
- Do not wrap these as raw shell strings only; define parser, risk profile,
  timeout profile, scope extraction, and install detection.
- Start with official JSON/JSONL flags:
  - `httpx -json`;
  - `subfinder -oJ`;
  - `katana -json` / JSONL output;
  - `nuclei -jsonl`.

Mapped tickets:

- P50 Tool Adapter Contract

### Content Discovery Tools

Sources:

- https://github.com/ffuf/ffuf
- https://github.com/OJ/gobuster
- https://github.com/epi052/feroxbuster
- https://github.com/danielmiessler/SecLists

SecOps decision:

- Directory discovery must be bounded, supervised, and wordlist-aware.
- Missing wordlists should produce a proposal, not a silent failure or hidden
  install command.

Mapped tickets:

- P47 Long Running Tool Consistency
- P50 Tool Adapter Contract

### Web Proxy And Manual Testing Tools

Sources:

- https://portswigger.net/burp/documentation
- https://www.zaproxy.org/

SecOps decision:

- Web testing should support a manual/proxy-assisted workflow in addition to
  automated scans.
- Adapter output should distinguish observation, request mutation, active scan,
  and exploit attempt.

Mapped tickets:

- P48 Engagement Context
- P50 Tool Adapter Contract
- P49 Reviewed Playbooks

### Exploit Frameworks

Sources:

- https://www.metasploit.com/
- https://github.com/rapid7/metasploit-framework

SecOps decision:

- Exploit frameworks are high-impact adapters, not ordinary commands.
- SecOps should support evidence-backed vulnerability validation before an
  exploit module is proposed, and should require explicit authorization before
  payload or session creation.

Mapped tickets:

- P43 Local Execution Security
- P50 Tool Adapter Contract
- P51 Vulnerability Intelligence

### Internal Network And Identity Tooling

Sources:

- https://github.com/fortra/impacket
- https://www.netexec.wiki/
- https://www.netexec.wiki/getting-started/installation
- https://specterops.io/bloodhound-community-edition/
- https://github.com/specterops/bloodhound

SecOps decision:

- Internal network and identity tools require credential handling, rate limits,
  data retention, and explicit authorization controls.
- For AD or identity attack paths, prefer graph/evidence records over long
  unstructured terminal output.
- Password spraying, command execution, file upload, and collector ingestion must
  be separate risk classes.

Mapped tickets:

- P43 Local Execution Security
- P48 Engagement Context
- P50 Tool Adapter Contract
- P51 Vulnerability Intelligence

### Privilege Escalation Knowledge Bases

Sources:

- https://gtfobins.github.io/
- https://github.com/peass-ng/PEASS-ng
- https://github.com/swisskyrepo/PayloadsAllTheThings

SecOps decision:

- Treat these as reviewed reference/playbook sources, not automatic command
  generators.
- Local privilege escalation guidance must be tied to evidence from the target
  shell and authorization context.

Mapped tickets:

- P49 Reviewed Playbooks
- P51 Vulnerability Intelligence

### Awesome Pentest Resource Inventory

Source:

- https://github.com/enaqx/awesome-pentest

SecOps decision:

- Use curated inventories to discover candidate adapters, but never add a tool
  just because it appears in a list.
- Each new candidate must pass the adapter contract: scope extraction, risk
  class, install detection, execution profile, parser, evidence model, and
  report mapping.

Mapped tickets:

- P43 Local Execution Security
- P50 Tool Adapter Contract

## Learning Platforms And Course Material

### PortSwigger Web Security Academy

Source:

- https://portswigger.net/web-security/all-topics

SecOps decision:

- Use as a structured web-vulnerability curriculum and test matrix source.
- File upload, command injection, path traversal, SSRF, authentication, access
  control, and business logic should become evidence-backed playbook modules.

Mapped tickets:

- P49 Reviewed Playbooks

### TryHackMe Learning Paths

Sources:

- https://tryhackme.com/paths
- https://tryhackme.com/module/penetration-testing-foundations

SecOps decision:

- Use platform hints to support lab setup and question-answer flow, but never
  to override technical scope.
- Build scenario replay tests from common lab requests: scan ports, identify
  service, find hidden directory, upload form, get user flag, enumerate SUID.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### Hack The Box Academy

Sources:

- https://academy.hackthebox.com/course/preview/penetration-testing-process/academy-modules-layout
- https://www.hackthebox.com/hacker/

SecOps decision:

- Include note taking, documentation, client communication, and report quality
  in the agent workflow, not only command execution.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### TCM Security Practical Ethical Hacking

Source:

- https://tcm-sec.com/academy/practical-ethical-hacking/

SecOps decision:

- Use as broad methodology coverage for recon, scanning, enumeration, web
  testing, exploitation basics, Active Directory, post-exploitation, and notes.
- Keep brute force, credential stuffing, password spraying, Metasploit, and
  post-exploitation steps under explicit authorization and risk classes.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks
- P50 Tool Adapter Contract

### Root-Me

Source:

- https://www.root-me.org/?lang=en

SecOps decision:

- Treat Root-Me as another authorized challenge platform, not a separate
  execution mode.
- Keep environment metadata separate from technical action classification.

Mapped tickets:

- P48 Engagement Context

## Video And Walkthrough Sources

### 13Cubed

Sources:

- https://training.13cubed.com/about-us
- https://www.youtube.com/@13Cubed

SecOps decision:

- Use as a DFIR and evidence-handling reference for forensic workflows.
- Forensics playbooks should preserve provenance, timestamps, hashes, and
  minimal evidence extraction.

Mapped tickets:

- P49 Reviewed Playbooks
- P55 Data Retention And Secret Hygiene

### HackerSploit

Sources:

- https://hackersploit.org/exploitation-tutorials/
- https://www.youtube.com/@HackerSploit

SecOps decision:

- Use as a practical demonstration source for tool workflows and lab
  walkthroughs.
- Convert lessons into reviewed patterns with scope, evidence, and stop
  conditions; do not copy exploit chains into autonomous execution.

Mapped tickets:

- P49 Reviewed Playbooks
- P50 Tool Adapter Contract

### IppSec

Sources:

- https://ippsec.rocks/
- https://www.youtube.com/@ippsec

SecOps decision:

- Use as a source for methodology sequencing and searchable technique tags.
- Do not scrape or memorize flags. Extract general patterns: enumeration,
  validation, exploit path, privesc evidence, reportable findings.

Mapped tickets:

- P49 Reviewed Playbooks
- P56 Reviewed Experience Learning

### John Hammond

Sources:

- https://www.johnhammond.llc/
- https://www.johnhammond.llc/bio
- https://www.youtube.com/@_JohnHammond

SecOps decision:

- Use as a CTF/lab reasoning source for explaining dead ends and iterative
  hypotheses to the user.

Mapped tickets:

- P49 Reviewed Playbooks

### LiveOverflow

Sources:

- https://liveoverflow.com/
- https://www.youtube.com/@LiveOverflow
- https://github.com/liveoverflow

SecOps decision:

- Use as a reference for exploit education, binary exploitation, and careful
  explanation of exploit mechanics.
- Keep exploit development features gated behind explicit authorization and
  evidence.

Mapped tickets:

- P49 Reviewed Playbooks
- P51 Vulnerability Intelligence

### NahamSec

Sources:

- https://www.nahamsec.com/
- https://www.nahamsec.com/about
- https://www.youtube.com/@NahamSec

SecOps decision:

- Use as recon, web hacking, and bug bounty methodology reference.
- Keep bug bounty and authorized assessment scope stricter than CTF-style
  targets.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### Curated YouTube Channel Lists

Sources:

- https://securityboulevard.com/2026/05/the-top-cybersecurity-youtube-channels-to-learn-from-in-2026/
- https://www.pentesting.org/youtube-channel-guide/
- https://vidpros.com/best-cybersecurity-youtube-channels/
- https://learnwithpath.com/blog/best-youtube-channels-for-cybersecurity-2026

SecOps decision:

- Use curated channel lists only as discovery leads, not as authority.
- Prefer channels with repeatable methodology, visible commands, explicit
  evidence, and reusable reasoning patterns.
- Convert video lessons into reviewed playbooks with source notes, not into
  hidden automation or memorized flags.

Mapped tickets:

- P49 Reviewed Playbooks
- P56 Reviewed Experience Learning

### Training And Walkthrough Synthesis

Sources:

- https://portswigger.net/web-security
- https://portswigger.net/web-security/learning-paths
- https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-methodology.html
- https://ippsec.rocks/
- https://www.youtube.com/@ippsec
- https://www.youtube.com/@HackerSploit
- https://www.youtube.com/@LiveOverflow
- https://www.youtube.com/@_JohnHammond
- https://www.youtube.com/@NahamSec

SecOps decision:

- Treat training and walkthrough material as methodology calibration, not as
  answer memory.
- Extract reusable structures:
  - enumeration checklist;
  - evidence required before exploit;
  - failed attempt classification;
  - privilege escalation preconditions;
  - report wording and remediation mapping.
- Never store platform flags, exact hidden paths, challenge-specific answers, or
  exploit chains as reusable facts.
- A reviewed lesson can influence proposals only when the current target has
  matching technical evidence, not only the same platform name.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks
- P50 Tool Adapter Contract
- P56 Reviewed Experience Learning

## Pentest Agent Research

### PentestGPT

Sources:

- https://github.com/GreyDGL/PentestGPT
- https://www.usenix.org/conference/usenixsecurity24/presentation/deng

SecOps decision:

- Preserve task state and reasoning phases, but avoid pretending fully
  autonomous pentesting is solved.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### Current Open Source Pentest Agent Repositories

Sources:

- https://github.com/GreyDGL/PentestGPT
- https://github.com/Armur-Ai/Pentest-Swarm-AI
- https://github.com/Armur-Ai/Pentest-Swarm-AI/blob/main/IMPLEMENTATION_PLAN.md
- https://pentestai.xyz/

SecOps decision:

- Competing agents emphasize live walkthroughs, persistent sessions,
  containerized tool environments, local LLM routing, playbooks, blackboards,
  and many adapters.
- SecOps should not copy the "more autonomy" marketing claim. The durable
  lesson is to separate:
  - task state;
  - evidence board;
  - adapter catalog;
  - execution policy;
  - user approvals;
  - replay and reporting.
- If multi-agent behavior is added later, shared state must be auditable and
  scope-bound, not an invisible swarm.
- Research agents and pentest-agent repos are useful as architecture signals,
  but their main lesson for SecOps is not "execute more"; it is to make task
  state, adapter contracts, evidence state, and approvals first-class.

Mapped tickets:

- P44 Agentic Extension Governance
- P45 Resume And ctrl+o
- P49 Reviewed Playbooks
- P50 Tool Adapter Contract
- P56 Reviewed Experience Learning

### Cybench

Source:

- https://ee.stanford.edu/cybench-framework-evaluating-cybersecurity-capabilities-and-risks-language-models

SecOps decision:

- Evaluation should break complex CTF/pentest tasks into subtasks.
- PTY, structured bash, and web-search scaffolds are evaluation variables,
  not afterthoughts.
- Human-readable task state should survive long sessions.

Mapped tickets:

- P45 Resume And ctrl+o
- P47 Long Running Tool Consistency
- P49 Reviewed Playbooks

### CTFusion

Source:

- https://arxiv.org/abs/2605.11504

SecOps decision:

- Static CTF benchmarks can be contaminated by existing writeups, memorized
  challenge content, or web-search-assisted shortcuts.
- SecOps evaluation should prefer live or replay-isolated tasks with clean
  evidence, bounded tool access, and deterministic scoring of each subtask.

Mapped tickets:

- P49 Reviewed Playbooks
- P54 Provider Reliability
- P56 Reviewed Experience Learning

### CVE-Bench

Source:

- https://arxiv.org/abs/2503.17332

SecOps decision:

- Real-world vulnerability exploitation remains hard even for state-of-the-art
  agents; confirmed evidence and sandboxed validation matter more than claimed
  CVE matches.
- CVE intelligence should not become an exploit trigger.

Mapped tickets:

- P49 Reviewed Playbooks
- P51 Vulnerability Intelligence

### CyberGym

Source:

- https://arxiv.org/abs/2506.02548

SecOps decision:

- Evaluation should include codebase-wide reasoning and proof-of-concept
  validation, but only in controlled environments.
- Experience memory should store reproducible evidence patterns, not raw
  exploit transcripts.

Mapped tickets:

- P49 Reviewed Playbooks
- P51 Vulnerability Intelligence

### ExploitGym

Source:

- https://arxiv.org/abs/2605.11086

SecOps decision:

- Exploitation tasks require sustained progress over long horizons, runtime
  adaptation, and strict dual-use gating.
- SecOps should treat exploitation as a proposal/verification workflow with
  explicit user intent and scope, not as a default next step.

Mapped tickets:

- P47 Long Running Tool Consistency
- P49 Reviewed Playbooks

### CTFAgent

Source:

- https://www.sciencedirect.com/science/article/abs/pii/S2214212625003424

SecOps decision:

- Plan-and-execute and task-tree memory are useful for CTF challenge solving.
- SecOps should adapt the task-tree idea into reviewed playbooks and mission
  state, while avoiding hidden autonomous chains.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks

### RapidPen, HackSynth, PentestEval, xOffense

Sources:

- https://arxiv.org/abs/2502.16730
- https://arxiv.org/abs/2412.01778
- https://arxiv.org/abs/2512.14233
- https://arxiv.org/abs/2509.13021

SecOps decision:

- Benchmarks and research support staged evaluation: information collection,
  weakness filtering, attack decision, exploit revision, post-exploitation, and
  reporting.
- The product should expose reviewed proposals and evidence, not hidden
  autonomous chains.

Mapped tickets:

- P48 Engagement Context
- P49 Reviewed Playbooks
- P50 Tool Adapter Contract

## Vulnerability Intelligence

### NVD, CISA KEV, FIRST EPSS

Sources:

- https://nvd.nist.gov/developers/vulnerabilities
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.first.org/epss/

SecOps decision:

- Use CVE metadata, known exploited status, and exploit probability only as
  prioritization signals.
- Do not turn a CVE match into a confirmed finding without target evidence.

Mapped tickets:

- P51 Vulnerability Intelligence
