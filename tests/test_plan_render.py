"""render_plan renders the mission plan as a distinct, reviewable block.

Audit item #7 / T2.1, Part A step 3. The plan is a trust artifact — it must be a
titled block of its own (target/scope, numbered steps with risk labels, which
need approval), never folded into reasoning text.
"""
from __future__ import annotations

import io
import unittest

from rich.console import Console

from secops_agent.core.mission import MissionPlan, PlanStep
from secops_agent.ui.renderer import Renderer


class RenderPlanTest(unittest.TestCase):
    def _render(self, plan) -> str:
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())
        renderer.render_plan(plan)
        return renderer.console.export_text()

    def test_render_lists_scope_steps_and_risk_labels(self):
        plan = MissionPlan(
            steps=[
                PlanStep(
                    title="nmap_scan 10.10.10.5", tool_name="nmap_scan",
                    risk_label="ACTIVE", active=True, needs_approval=True,
                ),
                PlanStep(
                    title="dir_brute http://10.10.10.5", tool_name="dir_brute",
                    risk_label="ACTIVE", active=True,
                ),
            ],
            scope_snapshot=["10.10.10.5"],
        )
        out = self._render(plan)
        self.assertIn("Mission Plan", out)
        self.assertIn("10.10.10.5", out)
        self.assertIn("nmap_scan", out)
        self.assertIn("dir_brute", out)
        self.assertIn("ACTIVE", out)
        self.assertIn("needs approval", out)

    def test_render_empty_plan_is_safe(self):
        out = self._render(MissionPlan())
        self.assertIn("Mission Plan", out)

    def test_render_surfaces_divergences(self):
        plan = MissionPlan(
            steps=[PlanStep(title="scan", tool_name="nmap_scan", active=True)],
            acknowledged=True,
            divergences=["dir_brute"],
        )
        out = self._render(plan)
        self.assertIn("dir_brute", out)


if __name__ == "__main__":
    unittest.main()
