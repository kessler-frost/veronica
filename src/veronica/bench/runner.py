"""Runner — times an agent against suite tasks and scores each via its oracle.

Agent-agnostic by design: pass a callable that attempts a task in a working dir
and an oracle that checks the artifacts. The same runner serves the Veronica
executor, a fake agent in tests, or a cua wrapper on a real host — identical
metrics for all, which is what makes the head-to-head credible.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from time import perf_counter

from veronica.bench.model import (
    AgentRun,
    BenchTask,
    OracleResult,
    SuiteResult,
    TaskResult,
)

# An agent attempts `task` in `workdir` and reports its trajectory + counters.
Agent = Callable[[BenchTask, Path], AgentRun]
# An oracle inspects `workdir` after the attempt and returns pass/fail.
Oracle = Callable[[Path], OracleResult]


def _missing_oracle(_workdir: Path) -> OracleResult:
    return OracleResult(False, "no oracle registered for this task")


def run_task(
    task: BenchTask, agent: Agent, oracle: Oracle, workdir: Path
) -> TaskResult:
    """Run one task: time only the agent, then score via the oracle.

    An agent that raises is a failed task, not a crashed harness — we record it
    as unsuccessful with the error in `detail`.
    """
    start = perf_counter()
    try:
        run = agent(task, workdir)
    except Exception as exc:  # noqa: BLE001 — agent failure is a task failure
        return TaskResult(
            task_id=task.id,
            bucket=task.bucket,
            success=False,
            wall_clock_s=perf_counter() - start,
            llm_calls=0,
            screenshots=0,
            steps=0,
            detail=f"agent error: {exc}",
        )
    elapsed = perf_counter() - start

    verdict = oracle(workdir)
    return TaskResult(
        task_id=task.id,
        bucket=task.bucket,
        success=verdict.passed,
        wall_clock_s=elapsed,
        llm_calls=run.llm_calls,
        screenshots=run.screenshots,
        steps=len(run.steps),
        detail=verdict.detail,
        trajectory=run.steps,
    )


def run_suite(
    tasks: tuple[BenchTask, ...],
    agent: Agent,
    oracles: Mapping[str, Oracle],
    workroot: Path,
    agent_name: str,
    suite: str = "v1",
) -> SuiteResult:
    """Run every task under its own working dir and collect scored results."""
    results = []
    for task in tasks:
        workdir = Path(workroot) / task.id
        workdir.mkdir(parents=True, exist_ok=True)
        oracle = oracles.get(task.id, _missing_oracle)
        results.append(run_task(task, agent, oracle, workdir))
    return SuiteResult(suite=suite, agent=agent_name, results=tuple(results))
