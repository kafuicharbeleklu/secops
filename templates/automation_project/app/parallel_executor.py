"""Parallel tool executor — runs independent attack steps concurrently.

Uses ThreadPoolExecutor to execute multiple tool calls in parallel
when they have no interdependencies (as determined by AttackPlan).
"""

import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ParallelResult:
    """Result of a single parallel tool execution."""

    step_index: int
    tool_name: str
    arguments: dict = field(default_factory=dict)
    result: dict = field(default_factory=dict)
    success: bool = True
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class BatchResult:
    """Aggregated result of a parallel batch execution."""

    results: list[ParallelResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failure_count(self) -> int:
        return sum(1 for r in self.results if not r.success)

    @property
    def summary(self) -> str:
        total = len(self.results)
        ok = self.success_count
        failed = self.failure_count
        return (
            f"{ok}/{total} reussi(s), {failed} echec(s) "
            f"en {self.total_duration_seconds:.1f}s"
        )


class ParallelToolExecutor:
    """Execute independent tool steps concurrently.

    Parameters
    ----------
    tool_executor : ToolExecutor
        The underlying tool executor for dispatching individual tools.
    max_workers : int
        Maximum number of concurrent threads (default: 3).
    timeout_seconds : int
        Global timeout for the entire batch (default: 600).
    """

    def __init__(self, tool_executor, *, max_workers=3, timeout_seconds=600):
        self.tool_executor = tool_executor
        self.max_workers = max_workers
        self.timeout_seconds = timeout_seconds

    def find_independent_steps(self, plan) -> list:
        """Identify steps in the plan that have no unsatisfied dependencies.

        Parameters
        ----------
        plan : AttackPlan
            The attack plan to analyze.

        Returns
        -------
        list[AttackStep]
            Steps that can be executed in parallel.
        """
        from app.attack_planner import StepStatus

        done_indices = {
            s.index for s in plan.steps
            if s.status in (StepStatus.DONE, StepStatus.SKIPPED)
        }

        independent = []
        for step in plan.steps:
            if step.status != StepStatus.PENDING:
                continue
            if all(dep in done_indices for dep in step.depends_on):
                independent.append(step)

        return independent

    def execute_batch(self, steps: list) -> BatchResult:
        """Execute independent steps in parallel.

        Parameters
        ----------
        steps : list[AttackStep]
            Steps to execute concurrently. Caller is responsible for
            ensuring these steps have no interdependencies.

        Returns
        -------
        BatchResult
            Aggregated results of all parallel executions.
        """
        if not steps:
            return BatchResult()

        batch_start = datetime.now()
        results = []

        # Limit workers to the number of steps
        workers = min(self.max_workers, len(steps))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for step in steps:
                future = pool.submit(
                    self._execute_single_step,
                    step,
                )
                futures[future] = step

            for future in concurrent.futures.as_completed(
                futures, timeout=self.timeout_seconds
            ):
                step = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    results.append(ParallelResult(
                        step_index=step.index,
                        tool_name=step.tool,
                        arguments=step.arguments,
                        success=False,
                        error=f"Timeout apres {self.timeout_seconds}s",
                    ))
                except Exception as exc:
                    results.append(ParallelResult(
                        step_index=step.index,
                        tool_name=step.tool,
                        arguments=step.arguments,
                        success=False,
                        error=str(exc),
                    ))

        batch_duration = (datetime.now() - batch_start).total_seconds()

        # Sort results by step index for deterministic ordering
        results.sort(key=lambda r: r.step_index)

        return BatchResult(
            results=results,
            total_duration_seconds=batch_duration,
        )

    def _execute_single_step(self, step) -> ParallelResult:
        """Execute a single attack step via the tool executor.

        Parameters
        ----------
        step : AttackStep
            The step to execute.

        Returns
        -------
        ParallelResult
            The execution result.
        """
        step_start = datetime.now()
        try:
            result = self.tool_executor.dispatch(step.tool, step.arguments)
            duration = (datetime.now() - step_start).total_seconds()
            return ParallelResult(
                step_index=step.index,
                tool_name=step.tool,
                arguments=step.arguments,
                result=result if isinstance(result, dict) else {"output": str(result)},
                success=True,
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = (datetime.now() - step_start).total_seconds()
            return ParallelResult(
                step_index=step.index,
                tool_name=step.tool,
                arguments=step.arguments,
                success=False,
                error=str(exc),
                duration_seconds=duration,
            )


def format_batch_result(batch: BatchResult) -> str:
    """Format batch results for display in the terminal.

    Parameters
    ----------
    batch : BatchResult
        The batch execution results.

    Returns
    -------
    str
        Human-readable summary.
    """
    lines = [f"Execution parallele: {batch.summary}"]
    for r in batch.results:
        status = "OK" if r.success else "ECHEC"
        lines.append(
            f"  [{status}] #{r.step_index} {r.tool_name} ({r.duration_seconds:.1f}s)"
        )
        if r.error:
            lines.append(f"       erreur: {r.error[:100]}")
    return "\n".join(lines)
