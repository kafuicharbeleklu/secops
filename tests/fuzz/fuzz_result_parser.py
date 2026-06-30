#!/usr/bin/env python3
"""Pure-stdlib mutational fuzzer for ``secops_agent.core.result_parser``.

Phase 0.2 of ``docs/IMPROVEMENT_PLAN_2026-06-29.md``. No external dependency:
``atheris`` ships no py3.14 wheel and these parsers are pure Python anyway, so a
small mutational harness over the stdlib ``random`` module is the right tool.

Invariant under test — the parser ingests **attacker-controlled** tool output
(``agent.py`` passes ``res.output`` straight in), so:

    ToolResultParser().parse(tool, raw, args) MUST always return a ParsedResult
    and MUST NOT raise, for ANY ``raw`` string and any realistic ``args``.

``run_campaign`` is imported by ``tests/test_result_parser_fuzz.py`` as a
deterministic regression test; the CLI below runs longer ad-hoc campaigns.

Usage:
    .venv/bin/python tests/fuzz/fuzz_result_parser.py --iters 20000 [--seed 1337]

Exit code 0 = clean, 1 = crashes found. Reproducers are written to
``tests/fuzz/crashes/`` for triage and regression.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from secops_agent.core.result_parser import ToolResultParser  # noqa: E402

CRASH_DIR = Path(__file__).resolve().parent / "crashes"

# Realistic (but mutilatable) samples of each supported tool's output.
SEEDS = [
    "Nmap scan report for 10.10.10.5\n80/tcp  open  http  Apache httpd 2.4.49\n"
    "22/tcp open ssh OpenSSH 7.6\nOS details: Linux 4.15\nNmap done: 1 IP address",
    "Host seems down. If it is really up, try -Pn\nNmap done: 0 hosts up",
    '{"results":[{"url":"http://x/a","status":200,"length":12}]}',          # ffuf
    '{"template-id":"cve-x","info":{"severity":"high"},"matched-at":"http://x"}',  # nuclei
    "Type: boolean-based blind\nParameter: id (GET)\navailable databases [2]:\n"
    "[*] information_schema\n[*] app",                                       # sqlmap
    "/admin (Status: 301) [Size: 0]\n/index.html (Status: 200) [Size: 4096]",  # dir brute
    "+ Server: Apache/2.4.49\n+ OSVDB-3268: /icons/: Directory indexing found.",  # nikto
    "subject=/CN=example.com\nissuer=/CN=R3\nNot After : Jan  1 00:00:00 2020 GMT",  # ssl
    "HTTP/1.1 200 OK\nServer: nginx\nContent-Length: 5\nX-Powered-By: PHP/7.2",  # headers
    "example.com has address 93.184.216.34\nexample.com mail is handled by 10 mx",  # dns
    "Domain Name: EXAMPLE.COM\nRegistrar: Foo\nRegistrant Email: a@b.com\n"
    "Creation Date: 1995-08-14",                                            # whois
    "Exploit Title | Path\nApache 2.4.49 - Path Traversal | php/webapps/1.py",  # searchsploit
    "CVE-2021-41773 9.8 CRITICAL Path traversal in Apache",                  # cve
    "uid=0(root) gid=0(root) groups=0(root)",                               # run_shell
    "",
]

# Control / special chars are built via chr() so the SOURCE stays pure ASCII
# (no literal null/ESC/surrogate bytes, which Python forbids in source files).
CONTROL = "".join(chr(c) for c in range(0, 32)) + "".join(chr(c) for c in (0x7F, 0x9B))
WEIRD = "".join(chr(c) for c in (
    0x20, 0x00, 0x09, 0xA0, 0x1B, 0x07, 0x7F,           # space, null, tab, nbsp, ESC, BEL, DEL
    0xE9, 0x202E, 0xFEFF, 0xFFFF, 0xD800, 0xDFFF,       # accented, RTL-override, BOM, noncharacter, surrogates
    0x2028, 0x1F4A9,                                    # line-separator, astral emoji
))
TOKENS = [
    "/tcp", "/udp", "open", "filtered", "Status:", "Size:", "{", "}", "[", "]", ":",
    "200", "99999999999999999999", "-1", "1e999", "OS details:", "Running:", "CVE-",
    "NaN", "%s", "\\x00", "Not After :", "Content-Length:", "has address", "@", "Email:",
]


def rand_str(rng: random.Random, n: int) -> str:
    parts = []
    for _ in range(max(1, n)):
        parts.append(rng.choice([
            rng.choice(SEEDS),
            CONTROL,
            WEIRD,
            rng.choice(TOKENS),
            "".join(chr(rng.randint(0, 0xFFFF)) for _ in range(rng.randint(0, 6))),
        ]))
    return "".join(parts)


def mutate(rng: random.Random, s: str) -> str:
    if not s:
        return rng.choice(SEEDS)
    chars = list(s)
    for _ in range(rng.randint(1, 5)):
        if not chars:
            break
        op = rng.randint(0, 5)
        i = rng.randrange(len(chars))
        if op == 0:
            chars[i] = rng.choice(CONTROL + WEIRD)
        elif op == 1:
            del chars[i]
        elif op == 2:
            chars.insert(i, rng.choice(TOKENS))
        elif op == 3:
            chars[i:i] = list(rng.choice(SEEDS))
        elif op == 4:
            chars[i] = chars[i] * rng.randint(1, 50)
        else:
            chars.insert(i, rng.choice(WEIRD))
    return "".join(chars)


def gen_raw(rng: random.Random) -> str:
    mode = rng.randint(0, 4)
    if mode == 0:
        return mutate(rng, rng.choice(SEEDS))
    if mode == 1:
        return rand_str(rng, rng.randint(1, 12))
    if mode == 2:  # arbitrary bytes -> arbitrary str
        return bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 64))).decode("latin-1")
    if mode == 3:
        return "\n".join(rng.choice(SEEDS) for _ in range(rng.randint(0, 8)))
    return rng.choice(SEEDS) + rng.choice(TOKENS) * rng.randint(0, 40)


ARG_POOL = [
    {}, {"target": "10.10.10.5"}, {"target": ""}, {"target": "::1"},
    {"url": "http://x/"}, {"target": "a" * 300}, {"host": "x", "port": "80"},
    {"target": "10.10.10.5", "url": "http://x"},
]


def gen_args(rng: random.Random) -> dict:
    a = dict(rng.choice(ARG_POOL))
    if rng.random() < 0.3:
        a[rng.choice(["target", "url", "extra"])] = gen_raw(rng)[:50]
    return a


def _crash_site(tb) -> str:
    for fr in reversed(tb):
        base = os.path.basename(fr.filename)
        if base in ("result_parser.py", "structured_memory.py", "mission.py"):
            return f"{base}:{fr.lineno}"
    return (os.path.basename(tb[-1].filename) + f":{tb[-1].lineno}") if tb else "?"


def run_campaign(iters: int, seed: int) -> dict[tuple[str, str, str], tuple[str, dict, str]]:
    """Run a deterministic fuzz campaign; return {crash_signature: reproducer}.

    A crash signature is ``(tool, exception_type, crash_site)``; the reproducer is
    ``(raw_input, args, formatted_traceback)``. An empty dict means the parser
    survived every input.
    """
    rng = random.Random(seed)
    parser = ToolResultParser()  # mission=None -> isolate the pure parsing path
    supported = ToolResultParser.supported_tools()
    tools = supported + ["unknown_tool", "", "nmap_scan"]

    crashes: dict[tuple[str, str, str], tuple[str, dict, str]] = {}
    for _ in range(iters):
        tool = rng.choice(tools)
        raw = gen_raw(rng)
        a = gen_args(rng)
        try:
            res = parser.parse(tool, raw, a)
            _ = res.findings  # touch the result so a malformed ParsedResult also trips
        except Exception as exc:  # noqa: BLE001 — catching everything is the point
            tb = traceback.extract_tb(sys.exc_info()[2])
            key = (tool if tool in supported else "<generic>", type(exc).__name__, _crash_site(tb))
            crashes.setdefault(key, (raw, a, traceback.format_exc()))
    return crashes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iters", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1337)
    opts = ap.parse_args()

    crashes = run_campaign(opts.iters, opts.seed)

    if not crashes:
        print(f"OK — {opts.iters} iters, seed={opts.seed}: no uncaught exceptions.")
        return 0

    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    print(f"FOUND {len(crashes)} unique crash signature(s) in {opts.iters} iters "
          f"(seed={opts.seed}):\n")
    for n, (key, (raw, a, tb)) in enumerate(sorted(crashes.items())):
        tool, exc, site = key
        fn = CRASH_DIR / f"crash_{n:02d}_{exc}_{site.replace(':', '_').replace('.', '_')}.txt"
        fn.write_text(f"tool={tool!r}\nargs={a!r}\nraw={raw!r}\n\n{tb}", encoding="utf-8")
        print(f"  [{n:02d}] {exc:22} at {site:26} via tool={tool:16} -> {fn.name}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
