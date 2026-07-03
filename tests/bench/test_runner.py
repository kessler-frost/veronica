"""Runner tests — fake agents + fake oracles, no LLM/VM/daemon.

Proves the harness times, scores, and aggregates correctly and that an agent
crash is recorded as a failed task rather than blowing up the run.
"""

from __future__ import annotations

from pathlib import Path

from veronica.bench.model import AgentRun, BenchTask, StepRecord
from veronica.bench.oracles import csv_matches, pending
from veronica.bench.runner import run_suite, run_task

TASK = BenchTask("v1.demo", "test", "do the thing")


def _writing_agent(rows: str):
    """An agent that 'succeeds' by writing products.csv, reporting 0 screenshots."""

    def agent(task: BenchTask, workdir: Path) -> AgentRun:
        (workdir / "products.csv").write_text(rows)
        return AgentRun(
            steps=(StepRecord(0, "exec", "curl+parse", True, "wrote products.csv"),),
            llm_calls=1,
            screenshots=0,
        )

    return agent


def _crashing_agent(task: BenchTask, workdir: Path) -> AgentRun:
    raise RuntimeError("boom")


def test_run_task_success_records_metrics(tmp_path):
    (tmp_path / "expected.csv").write_text("a,1\nb,2\n")
    result = run_task(
        TASK, _writing_agent("b,2\na,1\n"), csv_matches("products.csv"), tmp_path
    )
    assert result.success is True
    assert result.screenshots == 0  # the whole thesis
    assert result.llm_calls == 1
    assert result.steps == 1
    assert result.wall_clock_s >= 0.0
    assert result.trajectory[0].observed == "wrote products.csv"


def test_run_task_failure_when_oracle_rejects(tmp_path):
    (tmp_path / "expected.csv").write_text("a,1\n")
    result = run_task(
        TASK, _writing_agent("x,9\n"), csv_matches("products.csv"), tmp_path
    )
    assert result.success is False
    assert "!=" in result.detail


def test_run_task_agent_crash_is_a_failed_task(tmp_path):
    result = run_task(TASK, _crashing_agent, csv_matches("products.csv"), tmp_path)
    assert result.success is False
    assert "agent error: boom" in result.detail


def test_pending_oracle_fails_with_reason(tmp_path):
    result = run_task(TASK, _writing_agent("a,1\n"), pending("needs adapter:x"), tmp_path)
    assert result.success is False
    assert "oracle pending: needs adapter:x" in result.detail


def test_run_suite_aggregates(tmp_path):
    tasks = (
        BenchTask("t.pass", "test", "ok"),
        BenchTask("t.fail", "test", "no"),
    )
    # Only t.pass has a matching oracle+fixture; t.fail has no oracle → fails.
    def agent(task, workdir):
        (workdir / "products.csv").write_text("a,1\n")
        (workdir / "expected.csv").write_text("a,1\n")
        return AgentRun(llm_calls=1, screenshots=0)

    oracles = {"t.pass": csv_matches("products.csv")}
    suite = run_suite(tasks, agent, oracles, tmp_path, agent_name="veronica@test")

    assert suite.total == 2
    assert suite.passed == 1
    assert suite.agent == "veronica@test"
    by_id = suite.by_id()
    assert by_id["t.pass"].success is True
    assert by_id["t.fail"].success is False  # no oracle registered
    assert "no oracle registered" in by_id["t.fail"].detail
