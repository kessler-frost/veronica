"""Data model for the cua-parity benchmark harness.

Pure records: how a run is described, instrumented, and scored. No I/O, no
external deps. The metrics mirror benchmarks/cua-parity/SCOREBOARD.md —
success / wall_clock_s / llm_calls / screenshots / steps — so a Veronica run and
a cua run are directly comparable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Bucket = Literal["native", "headless", "blind"]


@dataclass(frozen=True)
class BenchTask:
    """One frozen suite task. Mirrors an entry in suite-v1.yaml."""

    id: str
    domain: str
    instruction: str
    bucket: Bucket = "headless"


@dataclass(frozen=True)
class OracleResult:
    """Deterministic pass/fail for a task, checked from its output artifacts."""

    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class StepRecord:
    """One action the agent took, plus what was observed as its result.

    `observed` is the verified-trajectory signal: for Veronica it is what
    eBPF/the oracle confirmed actually happened, not what the agent claimed.
    This is the data moat — kernel-verified, unlike a screenshot-judged step.
    """

    index: int
    action: str  # e.g. "exec", "http.post", "click"
    target: str = ""  # command / url / selector
    ok: bool = True
    observed: str = ""  # kernel/oracle-confirmed outcome


@dataclass(frozen=True)
class AgentRun:
    """What an agent reports after attempting a task.

    `steps` is the trajectory; `llm_calls`/`screenshots` are the efficiency
    counters compared against cua (Veronica target on 🟢/🟡: screenshots == 0).
    """

    steps: tuple[StepRecord, ...] = ()
    llm_calls: int = 0
    screenshots: int = 0


@dataclass(frozen=True)
class TaskResult:
    """The scored outcome of one task attempt."""

    task_id: str
    bucket: Bucket
    success: bool
    wall_clock_s: float
    llm_calls: int
    screenshots: int
    steps: int
    detail: str = ""
    trajectory: tuple[StepRecord, ...] = ()

    def beats(self, baseline: TaskResult) -> bool:
        """True if this result wins the cua-parity condition against `baseline`.

        Win = both succeed, AND we used fewer screenshots, AND we were faster.
        That is the literal SCOREBOARD win condition ("same oracle passes at 0
        screenshots and lower wall-clock"). `baseline` is the frozen cua run.
        """
        if not (self.success and baseline.success):
            return False
        return (
            self.screenshots < baseline.screenshots
            and self.wall_clock_s < baseline.wall_clock_s
        )


@dataclass(frozen=True)
class SuiteResult:
    """All task results for one agent's run of a suite."""

    suite: str
    agent: str
    results: tuple[TaskResult, ...] = ()

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def total_screenshots(self) -> int:
        return sum(r.screenshots for r in self.results)

    def by_id(self) -> dict[str, TaskResult]:
        return {r.task_id: r for r in self.results}

    def beats(self, baseline: SuiteResult) -> int:
        """Count of tasks where this run beats the baseline run (by id)."""
        base = baseline.by_id()
        return sum(
            1 for r in self.results if r.task_id in base and r.beats(base[r.task_id])
        )
