"""Security regression tests for result_parser hardening (Phase 0.2).

Covers:
  * the mutational fuzz campaign finds no uncaught exception — attacker-controlled
    tool output must never crash the parser;
  * ``parse_whois_output`` resists the ReDoS in its e-mail regex (regression for
    the quadratic ``re.findall`` blow-up the fuzzer's length-probe uncovered);
  * legitimate e-mails are still extracted after the regex hardening.

Note: the ReDoS guard uses ``signal.setitimer`` and therefore must run on the
main thread (the canonical ``unittest discover`` runner does).
"""
from __future__ import annotations

import signal
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests" / "fuzz"))

from secops_agent.core.result_parser import ToolResultParser, parse_whois_output  # noqa: E402
from fuzz_result_parser import run_campaign  # noqa: E402


class _Timeout(Exception):
    pass


def _raise_timeout(_signum, _frame):
    raise _Timeout()


class ResultParserFuzzRegression(unittest.TestCase):
    def test_fuzz_campaign_finds_no_uncaught_exception(self):
        crashes = run_campaign(iters=4000, seed=20260629)
        self.assertEqual(crashes, {}, f"fuzz found uncaught exceptions: {sorted(crashes)}")

    def test_whois_parser_resists_redos(self):
        # A long run of local-part characters with no '@' made the e-mail regex
        # backtrack quadratically (>80s at 200k chars). A hard alarm makes a
        # regression fail fast instead of hanging the suite.
        evil = "a" * 200_000
        parser = ToolResultParser()
        prev = signal.signal(signal.SIGALRM, _raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, 3.0)
        timed_out = False
        start = time.perf_counter()
        try:
            parser.parse("whois_lookup", evil, {"target": "x"})
        except _Timeout:
            timed_out = True
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prev)
        elapsed = time.perf_counter() - start
        self.assertFalse(timed_out, "whois parse did not finish within 3s — ReDoS present")
        self.assertLess(elapsed, 1.0, f"whois parse took {elapsed:.2f}s — possible ReDoS regression")

    def test_whois_extracts_legitimate_emails(self):
        raw = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Foo\n"
            "Registrant Email: admin@example.com\n"
            "Tech Email: a.b+c@sub.example.co.uk\n"
            "Abuse: abuse-team@corp-x.org\n"
        )
        parsed = parse_whois_output(raw, {"target": "example.com"})
        self.assertEqual(
            sorted(parsed.data["emails"]),
            ["a.b+c@sub.example.co.uk", "abuse-team@corp-x.org", "admin@example.com"],
        )


if __name__ == "__main__":
    unittest.main()
