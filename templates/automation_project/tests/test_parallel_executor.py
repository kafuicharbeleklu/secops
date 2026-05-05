"""Tests for parallel_executor — concurrent tool execution."""

import unittest
from unittest.mock import MagicMock, patch

from app.parallel_executor import (
    BatchResult,
    ParallelResult,
    ParallelToolExecutor,
    format_batch_result,
)


class TestParallelResult(unittest.TestCase):
    """Test ParallelResult dataclass."""

    def test_success_result(self):
        r = ParallelResult(
            step_index=0,
            tool_name="scan_target",
            result={"stdout": "output"},
            success=True,
            duration_seconds=1.5,
        )
        self.assertTrue(r.success)
        self.assertEqual(r.tool_name, "scan_target")

    def test_failure_result(self):
        r = ParallelResult(
            step_index=1,
            tool_name="enumerate_web",
            success=False,
            error="Timeout",
        )
        self.assertFalse(r.success)
        self.assertEqual(r.error, "Timeout")


class TestBatchResult(unittest.TestCase):
    """Test BatchResult aggregation."""

    def test_empty_batch(self):
        batch = BatchResult()
        self.assertEqual(batch.success_count, 0)
        self.assertEqual(batch.failure_count, 0)

    def test_mixed_results(self):
        batch = BatchResult(
            results=[
                ParallelResult(0, "tool_a", success=True),
                ParallelResult(1, "tool_b", success=False, error="err"),
                ParallelResult(2, "tool_c", success=True),
            ],
            total_duration_seconds=3.5,
        )
        self.assertEqual(batch.success_count, 2)
        self.assertEqual(batch.failure_count, 1)

    def test_summary_format(self):
        batch = BatchResult(
            results=[
                ParallelResult(0, "tool_a", success=True),
                ParallelResult(1, "tool_b", success=True),
            ],
            total_duration_seconds=2.0,
        )
        summary = batch.summary
        self.assertIn("2/2", summary)
        self.assertIn("reussi", summary)


class TestParallelToolExecutor(unittest.TestCase):
    """Test the parallel executor logic."""

    def _make_mock_executor(self, side_effect=None):
        executor = MagicMock()
        if side_effect:
            executor.dispatch.side_effect = side_effect
        else:
            executor.dispatch.return_value = {"stdout": "ok", "returncode": 0}
        return executor

    def _make_step(self, index, tool="scan_target", args=None, deps=None):
        from app.attack_planner import AttackStep, AttackPriority
        return AttackStep(
            index=index,
            name=f"Step {index}",
            tool=tool,
            arguments=args or {},
            priority=AttackPriority.MEDIUM,
            depends_on=deps or [],
        )

    def test_execute_batch_all_success(self):
        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec, max_workers=2)

        steps = [self._make_step(0), self._make_step(1)]
        result = parallel.execute_batch(steps)

        self.assertEqual(result.success_count, 2)
        self.assertEqual(result.failure_count, 0)
        self.assertEqual(mock_exec.dispatch.call_count, 2)

    def test_execute_batch_with_failures(self):
        def side_effect(tool_name, arguments):
            if tool_name == "scan_target":
                return {"stdout": "ok"}
            raise RuntimeError("Tool failed")

        mock_exec = self._make_mock_executor(side_effect=side_effect)
        parallel = ParallelToolExecutor(mock_exec, max_workers=2)

        steps = [
            self._make_step(0, tool="scan_target"),
            self._make_step(1, tool="enumerate_web"),
        ]
        result = parallel.execute_batch(steps)

        self.assertEqual(result.success_count, 1)
        self.assertEqual(result.failure_count, 1)

    def test_execute_batch_empty(self):
        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec, max_workers=2)

        result = parallel.execute_batch([])
        self.assertEqual(len(result.results), 0)

    def test_results_sorted_by_index(self):
        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec, max_workers=3)

        steps = [self._make_step(2), self._make_step(0), self._make_step(1)]
        result = parallel.execute_batch(steps)

        indices = [r.step_index for r in result.results]
        self.assertEqual(indices, [0, 1, 2])

    def test_find_independent_steps(self):
        from app.attack_planner import AttackPlan, AttackStep, AttackPriority, StepStatus

        plan = AttackPlan(target="test")
        plan.steps = [
            AttackStep(0, "Step A", "tool_a", priority=AttackPriority.HIGH),
            AttackStep(1, "Step B", "tool_b", depends_on=[0], priority=AttackPriority.MEDIUM),
            AttackStep(2, "Step C", "tool_c", priority=AttackPriority.MEDIUM),
        ]

        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec)

        independent = parallel.find_independent_steps(plan)
        # Steps 0 and 2 have no dependencies
        indices = [s.index for s in independent]
        self.assertIn(0, indices)
        self.assertIn(2, indices)
        # Step 1 depends on step 0
        self.assertNotIn(1, indices)

    def test_find_independent_after_completion(self):
        from app.attack_planner import AttackPlan, AttackStep, AttackPriority, StepStatus

        plan = AttackPlan(target="test")
        plan.steps = [
            AttackStep(0, "Step A", "tool_a", priority=AttackPriority.HIGH, status=StepStatus.DONE),
            AttackStep(1, "Step B", "tool_b", depends_on=[0], priority=AttackPriority.MEDIUM),
        ]

        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec)

        independent = parallel.find_independent_steps(plan)
        # Step 1's dependency (step 0) is done, so step 1 is now independent
        indices = [s.index for s in independent]
        self.assertIn(1, indices)

    def test_max_workers_capped(self):
        mock_exec = self._make_mock_executor()
        parallel = ParallelToolExecutor(mock_exec, max_workers=2)

        steps = [self._make_step(i) for i in range(5)]
        result = parallel.execute_batch(steps)

        self.assertEqual(result.success_count, 5)


class TestFormatBatchResult(unittest.TestCase):
    """Test batch result formatting."""

    def test_format_success(self):
        batch = BatchResult(
            results=[
                ParallelResult(0, "scan_target", success=True, duration_seconds=2.1),
            ],
            total_duration_seconds=2.1,
        )
        output = format_batch_result(batch)
        self.assertIn("OK", output)
        self.assertIn("scan_target", output)

    def test_format_failure(self):
        batch = BatchResult(
            results=[
                ParallelResult(0, "tool_x", success=False, error="timeout", duration_seconds=30.0),
            ],
            total_duration_seconds=30.0,
        )
        output = format_batch_result(batch)
        self.assertIn("ECHEC", output)
        self.assertIn("timeout", output)


if __name__ == "__main__":
    unittest.main()
