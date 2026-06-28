from __future__ import annotations

import unittest

try:
    from scratch.live_model_qa import (
        build_qa_registry,
        redact_sensitive,
        validate_terminal_response_contract,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard for bare system Python.
    raise unittest.SkipTest("Live model QA dependencies are not installed") from exc


class LiveModelQATests(unittest.TestCase):
    def test_redact_sensitive_masks_google_key_shape(self):
        text = "failure for AIza1234567890abcdefghijklmnopqrstuvwxyz"

        redacted = redact_sensitive(text)

        self.assertNotIn("AIza1234567890", redacted)
        self.assertIn("<redacted-google-api-key>", redacted)

    def test_terminal_contract_accepts_compact_answer(self):
        errors = validate_terminal_response_contract(
            "Verifie d'abord les enregistrements NS et MX. Ensuite compare les reponses DNS publiques."
        )

        self.assertEqual(errors, [])

    def test_terminal_contract_flags_decorative_markdown(self):
        errors = validate_terminal_response_contract(
            "### Analyse\n\n---\n\n| Action | Detail |\n| --- | --- |"
        )

        self.assertIn("decorative markdown heading emitted", errors)
        self.assertIn("decorative horizontal rule emitted", errors)
        self.assertIn("unnecessary markdown table emitted", errors)

    def test_terminal_contract_flags_prompt_scaffold_echo(self):
        errors = validate_terminal_response_contract(
            "* Topic: DNS checks\n* Constraint 1: two sentences\n\nVerifier NS puis MX."
        )

        self.assertIn("prompt/planning scaffold echoed", errors)

    def test_qa_registry_keeps_dangerous_tool_gated(self):
        registry = build_qa_registry(include_dangerous=True)

        self.assertFalse(registry.get_tool("safe_lookup").dangerous)
        self.assertTrue(registry.get_tool("dangerous_lookup").dangerous)


if __name__ == "__main__":
    unittest.main()
