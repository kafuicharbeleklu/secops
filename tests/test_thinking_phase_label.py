"""ANIM-04 — semantic thinking-spinner label from the mission phase, from
docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

The thinking spinner shows what the agent is actually doing (its mission phase)
instead of a flat "Generating...", falling back to the generic label when no
mission is active.  The label is derived from the controlled phase enum only,
never raw model reasoning (ASI01).
"""
from __future__ import annotations

import unittest

from secops_agent.core.mission import PentestPhase
from secops_agent.ui.animations import ThinkingSpinner, thinking_label_for_phase


def _real_phases():
    return [p for p in PentestPhase if isinstance(p.value, str) and p.name != "_phase_order"]


class ThinkingPhaseLabelTests(unittest.TestCase):
    def test_every_phase_has_a_distinct_specific_label(self):
        labels = [thinking_label_for_phase(p.value) for p in _real_phases()]
        for phase, label in zip(_real_phases(), labels):
            self.assertNotEqual(
                label, "Generating", f"{phase.value} falls through to the generic label"
            )
        self.assertEqual(len(set(labels)), len(labels), "phase labels must be distinct")

    def test_no_active_mission_falls_back_to_generic(self):
        self.assertEqual(thinking_label_for_phase(""), "Generating")
        self.assertEqual(thinking_label_for_phase(None), "Generating")
        self.assertEqual(thinking_label_for_phase("nonsense"), "Generating")

    def test_case_insensitive(self):
        self.assertEqual(thinking_label_for_phase("RECON"), thinking_label_for_phase("recon"))
        self.assertEqual(thinking_label_for_phase("recon"), "Running reconnaissance")

    def test_spinner_carries_the_phase_label(self):
        spinner = ThinkingSpinner(thinking_label_for_phase("reporting"))
        self.assertEqual(spinner.message, "Compiling the report")


if __name__ == "__main__":
    unittest.main()
