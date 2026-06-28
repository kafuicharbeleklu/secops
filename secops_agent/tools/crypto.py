"""
Cryptography and hash analysis tools.
Hash cracking, identification, and SSL/TLS auditing.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import shutil
from typing import Optional

from secops_agent.core.tools import report_progress, tool, ToolCategory
from secops_agent.utils.helpers import run_cmd as _run_cmd

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TLS_TARGET_FORBIDDEN = set(" \t\r\n;&|`$()<>\\'\"")


def _parse_tls_target(target: str) -> tuple[str, int, str]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("target is required")
    if any(char in _TLS_TARGET_FORBIDDEN for char in raw):
        raise ValueError("target contains unsupported characters")

    host = raw
    port_text = "443"
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError("IPv6 target must use [addr]:port syntax")
        host = raw[1:end]
        remainder = raw[end + 1:]
        if remainder:
            if not remainder.startswith(":"):
                raise ValueError("target must be host or host:port")
            port_text = remainder[1:]
    elif raw.count(":") == 1:
        host, port_text = raw.rsplit(":", 1)
    elif ":" in raw:
        host = raw

    if not host:
        raise ValueError("host is required")
    if not port_text.isdigit():
        raise ValueError("port must be numeric")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if not labels or any(not _HOST_LABEL_RE.match(label) for label in labels):
            raise ValueError("host must be a valid hostname or IP address")

    connect_host = f"[{host}]" if ":" in host else host
    return host, port, f"{connect_host}:{port}"


def _first_lines(text: str, count: int = 5) -> str:
    return "\n".join(text.splitlines()[:count])


@tool(
    name="hash_identify",
    description="Identify the type of a hash value (MD5, SHA1, SHA256, bcrypt, etc.).",
    category=ToolCategory.CRYPTO,
    parameters={
        "hash_value": {"type": "string", "description": "The hash string to identify", "required": True},
    },
    dangerous=False,
)
async def hash_identify(hash_value: str) -> str:
    """Identify hash type by length and format."""
    h = hash_value.strip()
    results = []

    # Length-based identification
    hash_types = {
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA-1", "MySQL5 (SHA1(SHA1()))"],
        56: ["SHA-224"],
        64: ["SHA-256", "Keccak-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "Keccak-512", "Whirlpool"],
    }

    length = len(h)

    # Check for specific formats
    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        results.append("bcrypt")
    elif h.startswith("$6$"):
        results.append("SHA-512 Crypt (Unix)")
    elif h.startswith("$5$"):
        results.append("SHA-256 Crypt (Unix)")
    elif h.startswith("$1$"):
        results.append("MD5 Crypt (Unix)")
    elif h.startswith("$apr1$"):
        results.append("Apache APR1 MD5")
    elif h.startswith("$argon2"):
        results.append("Argon2")
    elif h.startswith("pbkdf2"):
        results.append("PBKDF2")
    elif ":" in h and len(h.split(":")[0]) == 32:
        results.append("MD5 with salt (hash:salt)")
    elif length in hash_types:
        results.extend(hash_types[length])

    if not results:
        results.append(f"Unknown hash type (length: {length})")

    # Check if hex
    is_hex = all(c in "0123456789abcdefABCDEF" for c in h.replace("$", "").replace("/", "").replace(".", ""))

    output = f"🔐 Hash Analysis\n"
    output += f"  Hash: {h}\n"
    output += f"  Length: {length} chars\n"
    output += f"  Hex charset: {'Yes' if is_hex else 'No'}\n"
    output += f"  Possible types:\n"
    for t in results:
        output += f"    • {t}\n"

    return output


@tool(
    name="hash_generate",
    description="Generate various hash types for a given input string.",
    category=ToolCategory.CRYPTO,
    parameters={
        "text": {"type": "string", "description": "Input text to hash", "required": True},
        "algorithm": {"type": "string", "description": "Hash algorithm: md5, sha1, sha256, sha512, all", "required": False, "default": "all"},
    },
    dangerous=False,
)
async def hash_generate(text: str, algorithm: str = "all") -> str:
    """Generate hashes for input text."""
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    data = text.encode("utf-8")
    result = f"🔑 Hash Generation for: '{text}'\n\n"

    if algorithm == "all":
        for name, func in algorithms.items():
            result += f"  {name.upper():>8}: {func(data).hexdigest()}\n"
    elif algorithm in algorithms:
        result += f"  {algorithm.upper()}: {algorithms[algorithm](data).hexdigest()}\n"
    else:
        return f"❌ Unknown algorithm: {algorithm}. Available: md5, sha1, sha256, sha512, all"

    return result


@tool(
    name="ssl_audit",
    description="Perform an SSL/TLS audit on a target using testssl.sh or openssl to check for weak ciphers, protocol versions, and vulnerabilities.",
    category=ToolCategory.CRYPTO,
    parameters={
        "target": {"type": "string", "description": "Target host:port (e.g., 'example.com:443')", "required": True},
        "quick": {"type": "boolean", "description": "Quick scan (only critical checks)", "required": False, "default": True},
    },
    dangerous=False,
)
async def ssl_audit(target: str, quick: bool = True) -> str:
    """Audit SSL/TLS configuration."""
    await report_progress("normalizing TLS target", target)
    try:
        host, port, connect_target = _parse_tls_target(target)
    except ValueError as exc:
        return f"❌ Invalid TLS target: {exc}"

    await report_progress("checking TLS tooling", "testssl.sh or openssl")
    if shutil.which("testssl.sh") or shutil.which("testssl"):
        tool_name = "testssl.sh" if shutil.which("testssl.sh") else "testssl"
        cmd = [tool_name, "--color", "0"]
        if quick:
            cmd.extend(["--fast", "--protocols", "--server-defaults", "--vulnerabilities"])
        cmd.append(connect_target)

        mode = "quick audit" if quick else "full audit"
        await report_progress("running TLS audit", f"{tool_name} · {mode}")
        stdout, stderr, rc = await _run_cmd(cmd, timeout=300)
        await report_progress("summarizing TLS findings", f"{len(stdout.splitlines()):,} output lines")
        return stdout if stdout else f"No output. {stderr}"

    # Fallback: basic openssl checks
    if not shutil.which("openssl"):
        return "❌ Neither testssl.sh nor openssl is installed."

    result = f"🔐 Basic SSL/TLS Audit for {connect_target}\n\n"

    # Check supported protocols
    protocols = {
        "TLSv1": "-tls1",
        "TLSv1.1": "-tls1_1",
        "TLSv1.2": "-tls1_2",
        "TLSv1.3": "-tls1_3",
    }

    for proto_name, proto_flag in protocols.items():
        index = list(protocols).index(proto_name) + 1
        await report_progress(
            "checking protocol support",
            proto_name,
            percent=(index - 1) / len(protocols) * 100,
        )
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            connect_target,
            "-servername",
            host,
            proto_flag,
        ]
        stdout, stderr, rc = await _run_cmd(cmd, timeout=10)
        combined = (stdout + "\n" + stderr).strip()
        summary = _first_lines(combined)
        if rc == 0 and (
            "CONNECTED" in combined
            or "CONNECTION ESTABLISHED" in combined
            or "Protocol" in combined
        ) and "error" not in combined.lower():
            result += f"  {'⚠️ ' if proto_name in ['TLSv1', 'TLSv1.1'] else '✅'} {proto_name}: Supported\n"
        else:
            result += f"  {'✅' if proto_name in ['TLSv1', 'TLSv1.1'] else '⚠️ '} {proto_name}: Not supported\n"
        if summary:
            result += "\n".join(f"    {line}" for line in summary.splitlines())
            result += "\n"

    await report_progress("summarizing TLS findings", "basic openssl checks", percent=100)
    return result


@tool(
    name="password_strength",
    description="Analyze the strength of a password and suggest improvements.",
    category=ToolCategory.CRYPTO,
    parameters={
        "password": {"type": "string", "description": "Password to analyze", "required": True},
    },
    dangerous=False,
)
async def password_strength(password: str) -> str:
    """Analyze password strength."""
    import math
    import re

    p = password
    score = 0
    feedback = []
    charset_size = 0

    # Length
    if len(p) >= 16:
        score += 3
        feedback.append("✅ Excellent length (16+)")
    elif len(p) >= 12:
        score += 2
        feedback.append("✅ Good length (12+)")
    elif len(p) >= 8:
        score += 1
        feedback.append("⚠️  Minimum length met (8+)")
    else:
        feedback.append("❌ Too short (< 8 chars)")

    # Character classes
    if re.search(r"[a-z]", p):
        score += 1
        charset_size += 26
    else:
        feedback.append("⚠️  No lowercase letters")

    if re.search(r"[A-Z]", p):
        score += 1
        charset_size += 26
    else:
        feedback.append("⚠️  No uppercase letters")

    if re.search(r"\d", p):
        score += 1
        charset_size += 10
    else:
        feedback.append("⚠️  No digits")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", p):
        score += 2
        charset_size += 32
    else:
        feedback.append("⚠️  No special characters")

    # Common patterns
    common_patterns = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
    if p.lower() in common_patterns or any(cp in p.lower() for cp in common_patterns):
        score -= 3
        feedback.append("❌ Contains common password pattern")

    # Entropy calculation
    if charset_size > 0:
        entropy = len(p) * math.log2(charset_size)
    else:
        entropy = 0

    # Rating
    if score >= 7:
        rating = "🟢 STRONG"
    elif score >= 5:
        rating = "🟡 MODERATE"
    elif score >= 3:
        rating = "🟠 WEAK"
    else:
        rating = "🔴 VERY WEAK"

    result = f"🔒 Password Strength Analysis\n\n"
    result += f"  Rating: {rating}\n"
    result += f"  Score: {score}/8\n"
    result += f"  Length: {len(p)} characters\n"
    result += f"  Entropy: ~{entropy:.1f} bits\n"
    result += f"  Charset: {charset_size} possible characters\n\n"
    result += "  Analysis:\n"
    for f in feedback:
        result += f"    {f}\n"

    return result
