"""
Reconnaissance and OSINT tools.
Wraps: whois, subfinder, theHarvester, and custom recon functions.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Optional

from secops_agent.core.tools import report_progress, tool, ToolCategory
from secops_agent.utils.helpers import run_cmd as _run_cmd


@tool(
    name="whois_lookup",
    description="Perform a WHOIS lookup on a domain or IP address to get registration information, nameservers, and contact details.",
    category=ToolCategory.RECON,
    parameters={
        "target": {"type": "string", "description": "Domain name or IP address to look up", "required": True},
    },
    dangerous=False,
)
async def whois_lookup(target: str) -> str:
    """Perform WHOIS lookup."""
    if not shutil.which("whois"):
        return "❌ Error: whois is not installed. Install with: sudo apt install whois"

    stdout, stderr, rc = await _run_cmd(["whois", target], timeout=30)
    if rc != 0:
        return f"❌ WHOIS lookup failed: {stderr}"
    return stdout


@tool(
    name="subdomain_enum",
    description="Enumerate subdomains for a target domain using subfinder or basic DNS brute-forcing.",
    category=ToolCategory.RECON,
    parameters={
        "domain": {"type": "string", "description": "Target domain to enumerate subdomains for", "required": True},
        "method": {"type": "string", "description": "Method: 'passive' (subfinder/API), 'brute' (DNS brute force with common list)", "required": False, "default": "passive"},
    },
    # r3 active enumeration hits a real target (esp. `brute`): dangerous=True so the
    # dangerous flag agrees with risk_class and it routes through approval (audit T2.7).
    dangerous=True,
)
async def subdomain_enum(domain: str, method: str = "passive") -> str:
    """Enumerate subdomains for a domain."""
    await report_progress("checking enumeration method", method)
    if method == "passive" and shutil.which("subfinder"):
        cmd = ["subfinder", "-d", domain, "-silent"]
        await report_progress("running passive enumeration", domain)
        stdout, stderr, rc = await _run_cmd(cmd, timeout=120)
        await report_progress("summarizing subdomains", f"{len(stdout.splitlines()):,} candidates")
        if stdout:
            subs = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
            return f"Found {len(subs)} subdomains:\n" + "\n".join(f"  • {s}" for s in subs)
        return f"No subdomains found via subfinder. {stderr}"

    # Fallback: basic DNS brute force with common subdomains
    common_subs = [
        "www", "mail", "ftp", "admin", "blog", "dev", "staging", "api",
        "app", "test", "ns1", "ns2", "mx", "smtp", "pop", "imap",
        "vpn", "cdn", "media", "static", "assets", "portal", "login",
        "dashboard", "docs", "support", "help", "status", "monitor",
        "git", "gitlab", "github", "ci", "jenkins", "jira", "wiki",
    ]

    found = []
    tasks = []

    async def check_sub(sub: str):
        cmd = ["dig", "+short", f"{sub}.{domain}", "A"]
        stdout, _, rc = await _run_cmd(cmd, timeout=5)
        if stdout.strip():
            found.append(f"{sub}.{domain} -> {stdout.strip()}")

    if shutil.which("dig"):
        await report_progress("running DNS brute force", f"{len(common_subs)} candidates")
        for sub in common_subs:
            tasks.append(check_sub(sub))
        await asyncio.gather(*tasks, return_exceptions=True)
        await report_progress("summarizing DNS results", f"{len(found)} found")

        if found:
            return f"Found {len(found)} subdomains (brute-force):\n" + "\n".join(f"  • {f}" for f in sorted(found))
        return "No subdomains found via DNS brute-force."

    return "❌ Neither subfinder nor dig is available for subdomain enumeration."


@tool(
    name="http_headers",
    description="Fetch HTTP headers from a URL to analyze server configuration, security headers, and technology stack.",
    category=ToolCategory.RECON,
    parameters={
        "url": {"type": "string", "description": "Target URL (e.g., https://example.com)", "required": True},
        "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects", "required": False, "default": True},
    },
    dangerous=False,
)
async def http_headers(url: str, follow_redirects: bool = True) -> str:
    """Fetch and analyze HTTP headers."""
    cmd = ["curl", "-sI", "-o", "/dev/null", "-D", "-", "-m", "10"]
    if follow_redirects:
        cmd.append("-L")
    cmd.append(url)

    if not shutil.which("curl"):
        return "❌ Error: curl is not installed."

    stdout, stderr, rc = await _run_cmd(cmd, timeout=15)
    if rc != 0:
        return f"❌ Failed to fetch headers: {stderr}"

    # Analyze security headers
    analysis = []
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "X-XSS-Protection": "XSS Filter",
        "Referrer-Policy": "Referrer Control",
        "Permissions-Policy": "Feature Policy",
    }

    headers_lower = stdout.lower()
    missing = []
    present = []
    for header, desc in security_headers.items():
        if header.lower() in headers_lower:
            present.append(f"  ✅ {header} ({desc})")
        else:
            missing.append(f"  ⚠️  {header} ({desc}) - MISSING")

    analysis_str = ""
    if present:
        analysis_str += "\n🔒 Security Headers Present:\n" + "\n".join(present)
    if missing:
        analysis_str += "\n\n⚠️  Missing Security Headers:\n" + "\n".join(missing)

    return f"📡 HTTP Headers for {url}:\n{stdout}\n{analysis_str}"


@tool(
    name="tech_detect",
    description="Detect technologies used by a website (web server, CMS, frameworks, etc.) using HTTP response analysis.",
    category=ToolCategory.RECON,
    parameters={
        "url": {"type": "string", "description": "Target URL to analyze", "required": True},
    },
    dangerous=False,
)
async def tech_detect(url: str) -> str:
    """Detect web technologies."""
    if not shutil.which("curl"):
        return "❌ curl is not installed."

    # Fetch headers and body
    cmd = ["curl", "-sL", "-m", "15", "-D", "-", url]
    stdout, stderr, rc = await _run_cmd(cmd, timeout=20)

    if rc != 0:
        return f"❌ Failed to fetch URL: {stderr}"

    findings = []
    body_lower = stdout.lower()

    # Server detection from headers
    for line in stdout.split("\n"):
        line_lower = line.lower().strip()
        if line_lower.startswith("server:"):
            findings.append(f"🖥️  Server: {line.split(':', 1)[1].strip()}")
        elif line_lower.startswith("x-powered-by:"):
            findings.append(f"⚡ Powered By: {line.split(':', 1)[1].strip()}")
        elif line_lower.startswith("set-cookie:"):
            cookie = line.split(":", 1)[1].strip()
            if "phpsessid" in cookie.lower():
                findings.append("🐘 PHP detected (PHPSESSID cookie)")
            elif "asp.net" in cookie.lower():
                findings.append("🔷 ASP.NET detected")

    # CMS detection from body
    cms_signatures = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "magento": "Magento",
        "shopify": "Shopify",
        "wix.com": "Wix",
        "squarespace": "Squarespace",
    }

    for sig, cms in cms_signatures.items():
        if sig in body_lower:
            findings.append(f"📦 CMS: {cms}")
            break

    # Framework detection
    frameworks = {
        "react": "React",
        "vue.js": "Vue.js",
        "angular": "Angular",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "svelte": "Svelte",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "tailwind": "Tailwind CSS",
    }

    for sig, fw in frameworks.items():
        if sig in body_lower:
            findings.append(f"🔧 Framework: {fw}")

    if not findings:
        return f"🔍 Could not detect specific technologies for {url}"

    return f"🔍 Technology Detection for {url}:\n" + "\n".join(f"  {f}" for f in findings)


@tool(
    name="ssl_check",
    description="Check SSL/TLS certificate details and security for a domain.",
    category=ToolCategory.RECON,
    parameters={
        "domain": {"type": "string", "description": "Domain to check SSL certificate for", "required": True},
        "port": {"type": "integer", "description": "Port number (default: 443)", "required": False, "default": 443},
    },
    dangerous=False,
)
async def ssl_check(domain: str, port: int = 443) -> str:
    """Check SSL/TLS certificate."""
    if not shutil.which("openssl"):
        return "❌ openssl not installed."

    # Get certificate info
    cmd_cert = [
        "openssl", "s_client", "-connect", f"{domain}:{port}",
        "-servername", domain, "-showcerts",
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd_cert,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=b"Q\n"), timeout=15
    )
    cert_output = stdout.decode("utf-8", errors="replace")

    # Get certificate dates — piped via subprocess (no shell interpolation)
    try:
        s_client = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-connect", f"{domain}:{port}",
            "-servername", domain,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        x509 = await asyncio.create_subprocess_exec(
            "openssl", "x509", "-noout",
            "-subject", "-issuer", "-dates", "-fingerprint", "-serial",
            stdin=s_client.stdout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        s_client.stdin.write(b"\n")
        await s_client.stdin.drain()
        s_client.stdin.close()
        x509_out, _ = await asyncio.wait_for(x509.communicate(), timeout=15)
        await s_client.wait()
        stdout2 = x509_out.decode("utf-8", errors="replace") if x509_out else ""
    except (asyncio.TimeoutError, OSError):
        stdout2 = ""

    result = f"🔐 SSL/TLS Certificate for {domain}:{port}\n"
    if stdout2:
        result += stdout2
    else:
        result += cert_output[:2000]

    return result
