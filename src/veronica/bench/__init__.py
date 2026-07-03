"""cua-parity benchmark harness.

Phase-0 foundation for measuring Veronica against cua-style computer-use agents
on the frozen suite in benchmarks/cua-parity/. Agent-agnostic: the same runner,
oracles, and metrics score the Veronica executor, a fake agent in tests, or a
cua wrapper on a real host.

See docs/goal-driven-roadmap.md (Phase 0) and benchmarks/cua-parity/SCOREBOARD.md.
"""

from __future__ import annotations

from veronica.bench.model import (
    AgentRun,
    BenchTask,
    OracleResult,
    StepRecord,
    SuiteResult,
    TaskResult,
)
from veronica.bench.runner import Agent, Oracle, run_suite, run_task
from veronica.bench.suite import SUITE_V1, SUITE_V1_BY_ID

__all__ = [
    "AgentRun",
    "BenchTask",
    "OracleResult",
    "StepRecord",
    "SuiteResult",
    "TaskResult",
    "Agent",
    "Oracle",
    "run_task",
    "run_suite",
    "SUITE_V1",
    "SUITE_V1_BY_ID",
]
