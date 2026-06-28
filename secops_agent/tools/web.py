"""
Web application security testing tools.
Wraps: gobuster, nikto, sqlmap, and custom web testing functions.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import tempfile
from typing import Optional

from secops_agent.core.tools import report_progress, tool, ToolCategory
from secops_agent.utils.helpers import run_cmd as _run_cmd, run_cmd_streaming as _run_cmd_streaming


_WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)
_FALLBACK_WORDLIST = (
    "admin",
    "backup",
    "config",
    "css",
    "dev",
    "images",
    "js",
    "login",
    "panel",
    "server-status",
    "uploads",
)


def _existing_wordlist(preferred: str) -> tuple[str, tempfile.NamedTemporaryFile | None, str]:
    preferred_path = Path(str(preferred or "")).expanduser()
    if preferred_path.is_file():
        return str(preferred_path), None, "configured wordlist"

    for candidate in _WORDLIST_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return str(path), None, "system wordlist"

    temp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    temp.write("\n".join(_FALLBACK_WORDLIST) + "\n")
    temp.flush()
    return temp.name, temp, "built-in fallback wordlist"


@tool(
    name="dir_brute",
    description="Brute-force directories and files on a web server using gobuster or dirb.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL (e.g., http://target.com)", "required": True},
        "wordlist": {"type": "string", "description": "Path to wordlist file. Common: /usr/share/wordlists/dirb/common.txt, /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt", "required": False, "default": "/usr/share/wordlists/dirb/common.txt"},
        "extensions": {"type": "string", "description": "File extensions to search for (comma-separated, e.g., 'php,html,txt,bak')", "required": False},
        "threads": {"type": "integer", "description": "Number of threads (default: 10)", "required": False, "default": 10},
    },
    dangerous=True,
)
async def dir_brute(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: Optional[str] = None, threads: int = 10) -> str:
    """Brute-force web directories."""
    await report_progress("checking prerequisites", "gobuster or dirb", percent=5)
    wordlist_path, temp_wordlist, wordlist_source = _existing_wordlist(wordlist)
    if wordlist_source != "configured wordlist":
        await report_progress("selecting wordlist", wordlist_source, percent=10)

    if shutil.which("gobuster"):
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_path, "-t", str(threads), "-q", "--no-color"]
        if extensions:
            cmd.extend(["-x", extensions])
        engine = "gobuster"
    elif shutil.which("dirb"):
        cmd = ["dirb", url, wordlist_path, "-S", "-r"]
        engine = "dirb"
    else:
        if temp_wordlist is not None:
            temp_path = temp_wordlist.name
            temp_wordlist.close()
            Path(temp_path).unlink(missing_ok=True)
        return "❌ Neither gobuster nor dirb is installed."

    try:
        detail = f"{engine} · {threads} threads" if engine == "gobuster" else engine
        await report_progress("running content discovery", f"{detail} · timeout 300s", percent=20)
        stdout, stderr, rc = await _run_cmd_streaming(
            cmd,
            timeout=300,
            inactivity_timeout=120,
            progress=lambda progress_detail, percent=None: report_progress(
                "receiving content discovery output",
                progress_detail,
                percent=percent,
            ),
            progress_percent=50,
        )
        await report_progress("summarizing discovered paths", f"{len(stdout.splitlines()):,} output lines", percent=95)
        await report_progress("content discovery completed", f"rc {rc}", percent=100)
        prefix = ""
        if wordlist_source == "built-in fallback wordlist":
            prefix = "Using built-in fallback wordlist because no system wordlist was found.\n\n"
        elif wordlist_source == "system wordlist":
            prefix = f"Using wordlist: {wordlist_path}\n\n"
        return prefix + (stdout if stdout else f"No results. {stderr}")
    finally:
        if temp_wordlist is not None:
            temp_path = temp_wordlist.name
            temp_wordlist.close()
            Path(temp_path).unlink(missing_ok=True)


@tool(
    name="nikto_scan",
    description="Run a Nikto web vulnerability scan against a target web server.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL to scan", "required": True},
        "tuning": {"type": "string", "description": "Scan tuning: '1' (interesting files), '2' (misconfig), '3' (info disclosure), '4' (XSS/injection), '5' (remote retrieval), '6' (denial of service), '7' (remote source), '8' (command exec), '9' (SQL injection), '0' (file upload)", "required": False},
    },
    dangerous=True,
)
async def nikto_scan(url: str, tuning: Optional[str] = None) -> str:
    """Run Nikto web vulnerability scanner."""
    await report_progress("checking prerequisites", "nikto", percent=5)
    if not shutil.which("nikto"):
        return "❌ Nikto is not installed. Install with: sudo apt install nikto"

    cmd = ["nikto", "-h", url, "-nointeractive", "-C", "all"]
    if tuning:
        cmd.extend(["-T", tuning])

    await report_progress("running web vulnerability scan", f"{url} · timeout 600s", percent=20)
    stdout, stderr, rc = await _run_cmd_streaming(
        cmd,
        timeout=600,
        inactivity_timeout=180,
        progress=lambda detail, percent=None: report_progress(
            "receiving nikto output",
            detail,
            percent=percent,
        ),
        progress_percent=50,
    )
    await report_progress("summarizing nikto findings", f"{len(stdout.splitlines()):,} output lines", percent=95)
    await report_progress("nikto scan completed", f"rc {rc}", percent=100)
    return stdout if stdout else f"No output. {stderr}"


@tool(
    name="sql_injection_test",
    description="Test a URL parameter for SQL injection vulnerabilities using sqlmap.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL with injectable parameter (e.g., 'http://target.com/page?id=1')", "required": True},
        "level": {"type": "integer", "description": "Test level 1-5 (higher = more tests, default: 1)", "required": False, "default": 1},
        "risk": {"type": "integer", "description": "Risk level 1-3 (higher = more risky tests, default: 1)", "required": False, "default": 1},
        "technique": {"type": "string", "description": "SQL injection techniques: B (boolean-based), E (error-based), U (union), S (stacked), T (time-based). Combine like 'BEUST'", "required": False},
    },
    dangerous=True,
)
async def sql_injection_test(url: str, level: int = 1, risk: int = 1, technique: Optional[str] = None) -> str:
    """Test for SQL injection using sqlmap."""
    await report_progress("checking prerequisites", "sqlmap", percent=5)
    if not shutil.which("sqlmap"):
        return "❌ sqlmap is not installed. Install with: sudo apt install sqlmap"

    cmd = [
        "sqlmap", "-u", url,
        "--batch", "--random-agent",
        f"--level={level}", f"--risk={risk}",
    ]
    if technique:
        cmd.extend([f"--technique={technique}"])

    detail = f"level {level} · risk {risk}"
    if technique:
        detail += f" · {technique}"
    await report_progress("running injection checks", f"{detail} · timeout 300s", percent=20)
    stdout, stderr, rc = await _run_cmd_streaming(
        cmd,
        timeout=300,
        inactivity_timeout=180,
        progress=lambda progress_detail, percent=None: report_progress(
            "receiving sqlmap output",
            progress_detail,
            percent=percent,
        ),
        progress_percent=50,
    )
    await report_progress("summarizing sqlmap output", f"{len(stdout.splitlines()):,} output lines", percent=95)
    await report_progress("sqlmap checks completed", f"rc {rc}", percent=100)
    return stdout if stdout else f"No output. {stderr}"


@tool(
    name="xss_test",
    description="Test a URL for Cross-Site Scripting (XSS) vulnerabilities with common payloads.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL with parameter (e.g., 'http://target.com/search?q=test')", "required": True},
        "parameter": {"type": "string", "description": "Parameter name to test for XSS", "required": True},
    },
    dangerous=True,
)
async def xss_test(url: str, parameter: str) -> str:
    """Test for XSS vulnerabilities with common payloads."""
    await report_progress("checking prerequisites", "curl")
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(1);//",
        '<svg onload=alert(1)>',
        '{{7*7}}',  # SSTI test
        '${7*7}',  # Template injection
        '<img src=x onerror=prompt(1)>',
    ]

    if not shutil.which("curl"):
        return "❌ curl not installed."

    results = []
    for i, payload in enumerate(payloads, 1):
        await report_progress(
            "testing XSS payloads",
            f"{i}/{len(payloads)}",
            percent=10 + (i - 1) / len(payloads) * 80,
        )
        # Build URL with payload
        test_url = url.replace(f"{parameter}=", f"{parameter}={payload}", 1)
        if f"{parameter}=" not in url:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{parameter}={payload}"

        cmd = ["curl", "-sL", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}", test_url]
        stdout, _, rc = await _run_cmd(cmd, timeout=15)

        if stdout:
            parts = stdout.split("|")
            status = parts[0] if parts else "?"
            size = parts[1] if len(parts) > 1 else "?"
            results.append(f"  [{i}] Payload: {payload[:40]}... → HTTP {status}, Size: {size}B")

    # Fetch a baseline for comparison
    await report_progress("fetching baseline response", url, percent=95)
    base_cmd = ["curl", "-sL", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}", url]
    base_out, _, _ = await _run_cmd(base_cmd, timeout=10)
    await report_progress("summarizing XSS responses", f"{len(results)} payloads", percent=100)

    output = f"🔍 XSS Testing Results for {url} (parameter: {parameter})\n"
    output += f"📊 Baseline: {base_out}\n\n"
    output += "Payload Responses:\n" + "\n".join(results)
    output += "\n\n⚠️  Note: Compare response sizes with baseline. Significant differences may indicate reflection."
    output += "\n💡 Tip: Use browser dev tools to verify if payloads are reflected unescaped in the response."

    return output


@tool(
    name="waf_detect",
    description="Detect Web Application Firewall (WAF) presence on a target.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL to test", "required": True},
    },
    dangerous=True,
)
async def waf_detect(url: str) -> str:
    """Detect WAF presence by analyzing responses."""
    if not shutil.which("curl"):
        return "❌ curl not installed."

    # Normal request
    cmd_normal = ["curl", "-sI", "-m", "10", url]
    normal_out, _, _ = await _run_cmd(cmd_normal, timeout=15)

    # Malicious-looking request
    cmd_attack = ["curl", "-sI", "-m", "10", "-A",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        f"{url}?id=1' OR '1'='1"]
    attack_out, _, _ = await _run_cmd(cmd_attack, timeout=15)

    # Analyze headers for WAF signatures
    waf_signatures = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "incapsula": "Incapsula/Imperva",
        "sucuri": "Sucuri",
        "f5": "F5 BIG-IP",
        "barracuda": "Barracuda",
        "aws": "AWS WAF",
        "mod_security": "ModSecurity",
        "mod_sec": "ModSecurity",
        "deny": "Generic WAF",
        "block": "Generic WAF",
        "firewall": "Generic WAF",
        "x-sucuri": "Sucuri",
        "x-cdn": "CDN/WAF",
    }

    combined = (normal_out + attack_out).lower()
    detected = []
    for sig, waf in waf_signatures.items():
        if sig in combined:
            detected.append(waf)

    detected = list(set(detected))

    result = f"🛡️ WAF Detection for {url}\n\n"
    if detected:
        result += "⚠️  WAF/CDN Detected:\n"
        result += "\n".join(f"  • {w}" for w in detected)
    else:
        result += "✅ No WAF explicitly detected (may still be present with custom rules)"

    result += f"\n\n📡 Normal Response Headers:\n{normal_out[:500]}"
    result += f"\n📡 Attack Response Headers:\n{attack_out[:500]}"

    return result


@tool(
    name="ffuf_scan",
    description="Fuzz web endpoints using ffuf. Supports directory/file discovery, parameter fuzzing, and virtual host enumeration. Place the FUZZ keyword in the URL where you want to inject wordlist entries.",
    category=ToolCategory.WEB,
    parameters={
        "url": {"type": "string", "description": "Target URL with FUZZ keyword (e.g., 'http://target.com/FUZZ')", "required": True},
        "wordlist": {"type": "string", "description": "Path to wordlist file. Common: /usr/share/wordlists/dirb/common.txt", "required": False, "default": "/usr/share/wordlists/dirb/common.txt"},
        "method": {"type": "string", "description": "HTTP method: GET, POST, PUT (default: GET)", "required": False, "default": "GET"},
        "filter_code": {"type": "string", "description": "Filter out HTTP status codes (e.g., '404,403')", "required": False},
        "match_code": {"type": "string", "description": "Match only these HTTP status codes (e.g., '200,301')", "required": False},
        "extensions": {"type": "string", "description": "File extensions to append (e.g., 'php,html,txt')", "required": False},
        "threads": {"type": "integer", "description": "Number of concurrent threads (default: 40)", "required": False, "default": 40},
        "headers": {"type": "string", "description": "Custom header (e.g., 'Host: FUZZ.target.com')", "required": False},
    },
    dangerous=True,
)
async def ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    filter_code: Optional[str] = None,
    match_code: Optional[str] = None,
    extensions: Optional[str] = None,
    threads: int = 40,
    headers: Optional[str] = None,
) -> str:
    """Fuzz web endpoints using ffuf."""
    await report_progress("checking prerequisites", "ffuf", percent=5)
    if not shutil.which("ffuf"):
        return "❌ ffuf is not installed. Install with: go install github.com/ffuf/ffuf/v2@latest"

    wordlist_path, temp_wordlist, wordlist_source = _existing_wordlist(wordlist)
    if wordlist_source != "configured wordlist":
        await report_progress("selecting wordlist", wordlist_source, percent=10)

    cmd = ["ffuf", "-u", url, "-w", wordlist_path, "-t", str(threads), "-c", "-v", "-noninteractive"]

    if method and method.upper() != "GET":
        cmd.extend(["-X", method.upper()])
    if filter_code:
        cmd.extend(["-fc", filter_code])
    if match_code:
        cmd.extend(["-mc", match_code])
    if extensions:
        cmd.extend(["-e", extensions])
    if headers:
        cmd.extend(["-H", headers])

    try:
        detail = f"ffuf · {threads} threads · {method.upper()}"
        await report_progress("running web fuzzing", f"{detail} · timeout 300s", percent=20)
        stdout, stderr, rc = await _run_cmd_streaming(
            cmd,
            timeout=300,
            inactivity_timeout=120,
            progress=lambda progress_detail, percent=None: report_progress(
                "receiving ffuf output",
                progress_detail,
                percent=percent,
            ),
            progress_percent=50,
        )
        await report_progress("summarizing ffuf results", f"{len(stdout.splitlines()):,} output lines", percent=95)
        await report_progress("ffuf scan completed", f"rc {rc}", percent=100)
        prefix = ""
        if wordlist_source == "built-in fallback wordlist":
            prefix = "Using built-in fallback wordlist because no system wordlist was found.\n\n"
        elif wordlist_source == "system wordlist":
            prefix = f"Using wordlist: {wordlist_path}\n\n"
        return prefix + (stdout if stdout else f"No results. {stderr}")
    finally:
        if temp_wordlist is not None:
            temp_path = temp_wordlist.name
            temp_wordlist.close()
            Path(temp_path).unlink(missing_ok=True)


_NUCLEI_BLOCKED_PREFIXES = (
    "-o", "-output", "-oA",       # output to file
    "--proxy",                     # proxy (data exfiltration risk)
    "--interactsh",                # OOB interaction server
    "-iserver",                    # custom interactsh
    "-config",                     # custom config file
)
_NUCLEI_SHELL_META = set(";&|`$(){}[]<>'\"\\\n\r")


@tool(
    name="nuclei_scan",
    description="Run Nuclei vulnerability scanner with community templates against a target. Detects CVEs, misconfigurations, exposures, and default credentials.",
    category=ToolCategory.WEB,
    parameters={
        "target": {"type": "string", "description": "Target URL or host to scan (e.g., 'http://target.com')", "required": True},
        "templates": {"type": "string", "description": "Template tags to use (e.g., 'cve', 'misconfig', 'exposure', 'default-login'). Comma-separated.", "required": False},
        "severity": {"type": "string", "description": "Filter by severity: info, low, medium, high, critical. Comma-separated.", "required": False},
        "rate_limit": {"type": "integer", "description": "Requests per second limit (default: 150)", "required": False, "default": 150},
        "extra_args": {"type": "string", "description": "Additional nuclei arguments", "required": False},
    },
    dangerous=True,
)
async def nuclei_scan(
    target: str,
    templates: Optional[str] = None,
    severity: Optional[str] = None,
    rate_limit: int = 150,
    extra_args: Optional[str] = None,
) -> str:
    """Run Nuclei vulnerability scanner against a target."""
    await report_progress("checking prerequisites", "nuclei", percent=5)
    if not shutil.which("nuclei"):
        return "❌ nuclei is not installed. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    cmd = ["nuclei", "-u", target, "-nc", "-rl", str(rate_limit)]

    if templates:
        cmd.extend(["-tags", templates])
    if severity:
        cmd.extend(["-severity", severity])

    # Validate extra_args against safety blocklist (same pattern as nmap)
    if extra_args:
        rejected: list[str] = []
        for arg in extra_args.split():
            has_meta = any(ch in _NUCLEI_SHELL_META for ch in arg)
            is_blocked = any(
                arg == prefix or arg.startswith(prefix)
                for prefix in _NUCLEI_BLOCKED_PREFIXES
            )
            if has_meta or is_blocked:
                rejected.append(arg)
            else:
                cmd.append(arg)
        if rejected:
            cmd.extend(["#", "blocked-args:", *rejected])

    scan_desc = templates or "all templates"
    sev_desc = f" · severity {severity}" if severity else ""
    await report_progress(
        "running vulnerability scan",
        f"nuclei · {scan_desc}{sev_desc} · timeout 600s",
        percent=15,
    )
    stdout, stderr, rc = await _run_cmd_streaming(
        cmd,
        timeout=600,
        inactivity_timeout=180,
        progress=lambda detail, percent=None: report_progress(
            "receiving nuclei output",
            detail,
            percent=percent,
        ),
        progress_percent=50,
    )
    await report_progress(
        "summarizing nuclei findings",
        f"{len(stdout.splitlines()):,} output lines",
        percent=95,
    )
    await report_progress("nuclei scan completed", f"rc {rc}", percent=100)
    return stdout if stdout else f"No output from nuclei. {stderr}"
