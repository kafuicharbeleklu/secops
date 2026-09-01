"""First-class MissionPlan on the blackboard (audit item #7 / T2.1, Part A step 1).

The plan is a *persisted* review artifact — unlike the runtime-only scan cache it
must survive a to_dict/from_dict round-trip. `record_divergence` collects active
tools that ran outside the acknowledged plan (once per tool, so the caller emits a
single notice), and `narrow_scope` tightens the mission so ScopeGuard denies
everything else — a `/plan scope <t>` edit that really constrains the mission.
"""
from __future__ import annotations

import unittest

from secops_agent.core.mission import (
    MissionContext,
    MissionPlan,
    PlanStep,
)


class PlanStepSerialisationTest(unittest.TestCase):
    def test_round_trip_preserves_all_fields(self):
        step = PlanStep(
            title="Port scan 10.10.10.5",
            tool_name="nmap_scan",
            risk_label="ACTIVE",
            active=True,
            needs_approval=True,
            status="planned",
        )
        restored = PlanStep.from_dict(step.to_dict())
        self.assertEqual(restored, step)

    def test_from_dict_tolerates_missing_and_unknown_keys(self):
        """Persisted blackboard schema may drift; a load must not crash."""
        restored = PlanStep.from_dict({"title": "recon", "future_field": "ignored"})
        self.assertEqual(restored.title, "recon")
        self.assertEqual(restored.tool_name, "")
        self.assertEqual(restored.status, "planned")


class MissionPlanSerialisationTest(unittest.TestCase):
    def test_round_trip_preserves_steps_and_state(self):
        plan = MissionPlan(
            steps=[
                PlanStep(title="ping", tool_name="ping_host", active=False),
                PlanStep(title="scan", tool_name="nmap_scan", active=True, needs_approval=True),
            ],
            scope_snapshot=["10.10.10.5"],
            acknowledged=True,
            divergences=["subdomain_enum"],
        )
        restored = MissionPlan.from_dict(plan.to_dict())
        self.assertEqual(restored, plan)

    def test_default_plan_is_empty_and_unacknowledged(self):
        plan = MissionPlan()
        self.assertEqual(plan.steps, [])
        self.assertFalse(plan.acknowledged)
        self.assertEqual(plan.divergences, [])


class MissionContextPlanTest(unittest.TestCase):
    def test_context_has_default_plan(self):
        mission = MissionContext(name="m")
        self.assertIsInstance(mission.plan, MissionPlan)
        self.assertFalse(mission.plan.acknowledged)

    def test_plan_persists_through_context_round_trip(self):
        mission = MissionContext(name="persist")
        mission.plan.steps.append(PlanStep(title="scan", tool_name="nmap_scan", active=True))
        mission.plan.acknowledged = True
        mission.record_divergence("dir_brute")

        restored = MissionContext.from_dict(mission.to_dict())
        self.assertTrue(restored.plan.acknowledged)
        self.assertEqual([s.tool_name for s in restored.plan.steps], ["nmap_scan"])
        self.assertEqual(restored.plan.divergences, ["dir_brute"])

    def test_from_dict_without_plan_key_defaults(self):
        """Sessions saved before the plan existed still load."""
        legacy = MissionContext(name="legacy").to_dict()
        legacy.pop("plan", None)
        restored = MissionContext.from_dict(legacy)
        self.assertIsInstance(restored.plan, MissionPlan)
        self.assertFalse(restored.plan.acknowledged)


class RecordDivergenceTest(unittest.TestCase):
    def test_first_divergence_returns_true_then_false(self):
        mission = MissionContext(name="d")
        self.assertTrue(mission.record_divergence("nmap_scan"))
        self.assertFalse(mission.record_divergence("nmap_scan"))
        self.assertEqual(mission.plan.divergences, ["nmap_scan"])

    def test_distinct_tools_each_diverge_once(self):
        mission = MissionContext(name="d2")
        self.assertTrue(mission.record_divergence("nmap_scan"))
        self.assertTrue(mission.record_divergence("dir_brute"))
        self.assertEqual(mission.plan.divergences, ["nmap_scan", "dir_brute"])

    def test_blank_tool_name_is_ignored(self):
        mission = MissionContext(name="d3")
        self.assertFalse(mission.record_divergence(""))
        self.assertFalse(mission.record_divergence("   "))
        self.assertEqual(mission.plan.divergences, [])


class NarrowScopeTest(unittest.TestCase):
    def test_narrow_scope_resets_in_scope_and_registers_target(self):
        mission = MissionContext(name="scope")
        mission.add_target("10.10.10.0/24", target_type="cidr")

        mission.narrow_scope("10.10.10.5")

        # in_scope is now exactly the narrowed value (no leftover broad entry).
        self.assertEqual(mission.scope.in_scope, ["10.10.10.5"])
        # The narrowed value is registered as a target.
        self.assertIn("10.10.10.5", [t.value for t in mission.targets])

    def test_narrow_scope_tightens_enforcement(self):
        mission = MissionContext(name="enforce")
        # Before: no explicit in-scope -> permissive.
        self.assertTrue(mission.scope.is_in_scope("10.10.10.6"))

        mission.narrow_scope("10.10.10.5")

        self.assertTrue(mission.scope.is_in_scope("10.10.10.5"))
        self.assertFalse(mission.scope.is_in_scope("10.10.10.6"))

    def test_narrow_scope_is_idempotent(self):
        mission = MissionContext(name="idem")
        mission.narrow_scope("example.com")
        mission.narrow_scope("example.com")
        self.assertEqual(mission.scope.in_scope, ["example.com"])
        self.assertEqual(
            [t.value for t in mission.targets].count("example.com"), 1
        )

    def test_narrow_scope_infers_target_type(self):
        mission = MissionContext(name="types")
        mission.narrow_scope("example.com")
        target = next(t for t in mission.targets if t.value == "example.com")
        self.assertEqual(target.type, "domain")

    def test_blank_narrow_scope_is_a_noop(self):
        mission = MissionContext(name="blank")
        mission.narrow_scope("   ")
        self.assertEqual(mission.scope.in_scope, [])
        self.assertEqual(mission.targets, [])


if __name__ == "__main__":
    unittest.main()
