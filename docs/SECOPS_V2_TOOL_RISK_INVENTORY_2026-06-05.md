# SecOps v2 Tool Risk Inventory

Date: 2026-06-05

This inventory is a planning artifact. It does not change runtime behavior.

## Why This Exists

The current binary `dangerous=True/False` flag is too coarse for a pentest
agent. Several tools marked non-dangerous still execute local commands, touch
network targets, read local files, or generate offensive payload material.

The next permission model should classify tools by action type and resource,
not only by a static danger flag.

## Proposed Risk Classes

### R0 - Pure Local Computation

Definition:

- No subprocess.
- No network.
- No filesystem reads outside ordinary application state.

Examples:

- `hash_identify`
- `hash_generate`
- `password_strength`

Default handling:

- Can run without approval.

### R1 - Local Observation

Definition:

- Reads local OS/process/network state.
- Uses bounded commands.
- No privileged action.
- No sensitive file reads.

Examples:

- `sysinfo(os)`
- `sysinfo(network)`
- `vpn_status`

Default handling:

- Usually allowed, but output should be compact and non-secret by default.

Required cleanup:

- `sysinfo(users)` currently attempts `sudo -l` through a non-dangerous path.
  Remove or gate that probe.

### R2 - Network Observation

Definition:

- Sends low-impact network requests to an explicit target.
- Does not brute force, fuzz, exploit, upload, or mutate state.

Examples:

- `ping_host`
- `dns_lookup`
- `whois_lookup`
- `http_headers`
- `tech_detect`
- `ssl_check`

Default handling:

- Needs scope validation.
- Can be auto-allowed only when target is explicitly in scope and permission
  mode allows low-risk observation.

Required cleanup:

- `ssl_check` uses direct subprocess piping and is safer than `ssl_audit`, but
  still needs target normalization tests.

### R3 - Active Enumeration

Definition:

- Scans, crawls, brute-forces, probes many paths, or increases traffic volume.

Examples:

- `nmap_scan`
- `dir_brute`
- `subdomain_enum(method="brute")`
- `nikto_scan`
- `sql_injection_test`
- `xss_test`

Default handling:

- Requires explicit user approval unless permission policy says otherwise.
- Must be supervised with progress, timeout, cancellation, and spool metadata.
- Must be scope-gated before execution.

Required cleanup:

- Long-running tools need declared runtime budgets in the tool contract so the
  outer registry does not conflict with the internal supervisor budget.

### R4 - Local File Access

Definition:

- Reads local files or searches local filesystem paths.

Examples:

- `file_analyze`
- `log_analyze`
- `find_files`
- `exploit_info` reading local ExploitDB files.

Default handling:

- Must be path-policy checked before execution.
- Sensitive paths such as `/etc/shadow`, SSH keys, browser profiles, tokens,
  and non-workspace secrets should ask or deny depending on policy.

Required cleanup:

- The existing file path permission policy must be connected to the agent
  execution path before these tools read files.

### R5 - Privileged Local Action

Definition:

- Uses or may require sudo/root.
- Changes networking, packages, services, mounts, permissions, or system state.

Examples:

- `connect_vpn_config`
- `disconnect_vpn`
- `run_shell` commands containing sudo
- system update/install commands through `run_shell`

Default handling:

- Requires explicit approval.
- Must not show a sudo password prompt when sandbox policy will block sudo.
- Must use shared sudo detection and local authentication flow.
- Must record owned processes for background services.

Required cleanup:

- VPN connect/disconnect needs owned PID/config/log/status metadata.
- Privileged internal tools must share the same permission vocabulary as
  `run_shell`.

### R6 - Offensive Payload Or Exploit Assistance

Definition:

- Generates payloads, exploit commands, or direct exploitation material.

Examples:

- `generate_payload`
- future exploit adapters
- future PEASS/GTFOBins guided privesc actions

Default handling:

- Requires explicit user intent, scope, and approval.
- Should normally produce a proposal or playbook step, not execute.

Required cleanup:

- Payload generation should be tied to authorization context and target
  evidence, especially outside CTF/lab contexts.

### R7 - Extension And Supply-Chain Execution

Definition:

- Loads or executes external instructions/code from workspace/global config or
  remote tool servers.

Examples:

- Markdown skills injected into system context.
- Hooks executing configured commands.
- MCP servers and MCP tools.

Default handling:

- Disabled, read-only, or explicitly reviewed until provenance is known.
- Requires source/path/hash display.
- Requires an allowlist/trust store for execution surfaces.

Required cleanup:

- Add provenance records for skills.
- Add hook approval or disabled-by-default shell hooks.
- Add MCP startup approval and response validation.

### R8 - Credentialed Remote Or Identity Action

Definition:

- Uses credentials, hashes, tickets, cookies, API keys, or collected identity
  data against a remote service.
- May spray, authenticate, upload/download, execute remote commands, collect
  directory graph data, or ingest identity evidence.

Examples:

- Future Impacket adapters.
- Future NetExec adapters.
- Future BloodHound/SharpHound/AzureHound collection workflows.
- Credentialed SMB/LDAP/WinRM/SSH enumeration.
- Password spraying or login validation.

Default handling:

- Requires explicit engagement authorization and scope.
- Requires credential source and storage policy.
- Requires rate limits and lockout safety.
- Requires redaction before transcript/export.
- Must distinguish:
  - credential validation;
  - password spraying;
  - remote command execution;
  - file transfer;
  - collector ingestion;
  - graph analysis.

Required cleanup:

- Add credential and secret hygiene before adding these adapters.
- Add separate permission resources for credential use, spray, file transfer,
  remote execution, and collector ingestion.
- Add evidence records that can support graph/reporting claims without dumping
  raw secrets.

## Immediate Planning Consequences

1. Replace `dangerous` with a richer risk profile while preserving the current
   boolean for compatibility.
2. Make approval prompts explain the risk class and resource:
   - tool name;
   - target/path/command;
   - risk class;
   - permission scope options.
3. Keep proposal-first behavior: active enumeration, privileged actions, and
   exploit assistance should not chain invisibly.
4. Add tests for every risk class before changing permission prompts.
5. Treat credentialed internal actions as a distinct risk class, not just
   "active scan" or "exploit".
