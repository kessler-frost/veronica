"""Results I/O + scoreboard rendering + the beats() win condition."""

from __future__ import annotations

from veronica.bench.model import SuiteResult, TaskResult
from veronica.bench.results import read_result, render_scoreboard, write_result


def _tr(task_id, success, shots, secs) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        bucket="headless",
        success=success,
        wall_clock_s=secs,
        llm_calls=1,
        screenshots=shots,
        steps=1,
    )


def test_write_read_roundtrip(tmp_path):
    suite = SuiteResult(
        suite="v1",
        agent="veronica@abc",
        results=(_tr("v1.a", True, 0, 0.4), _tr("v1.b", False, 0, 0.1)),
    )
    path = write_result(suite, tmp_path / "results" / "veronica-v1.json")
    assert path.exists()
    back = read_result(path)
    assert back.agent == "veronica@abc"
    assert back.passed == 1
    assert back.total == 2
    assert back.by_id()["v1.a"].wall_clock_s == 0.4


def test_beats_requires_success_fewer_shots_and_faster():
    veronica = _tr("v1.a", True, 0, 0.5)
    cua = _tr("v1.a", True, 8, 30.0)
    assert veronica.beats(cua) is True
    # Fails if Veronica didn't succeed.
    assert _tr("v1.a", False, 0, 0.5).beats(cua) is False
    # Fails if Veronica used no fewer screenshots.
    assert _tr("v1.a", True, 8, 0.5).beats(cua) is False
    # Fails if Veronica was slower despite fewer shots.
    assert _tr("v1.a", True, 0, 31.0).beats(cua) is False


def test_suite_beats_counts_per_task():
    veronica = SuiteResult(
        "v1", "veronica", (_tr("v1.a", True, 0, 0.5), _tr("v1.b", True, 0, 0.5))
    )
    cua = SuiteResult(
        "v1", "cua", (_tr("v1.a", True, 8, 30.0), _tr("v1.b", False, 5, 30.0))
    )
    # Beats a (cua passed), not b (cua failed → not a valid parity win).
    assert veronica.beats(cua) == 1


def test_render_scoreboard_with_baseline():
    veronica = SuiteResult("v1", "veronica", (_tr("v1.a", True, 0, 0.5),))
    cua = SuiteResult("v1", "cua", (_tr("v1.a", True, 8, 30.0),))
    md = render_scoreboard(veronica, cua)
    assert "v1.a" in md
    assert "Beat?" in md
    assert "beats cua on 1/1" in md


def test_render_scoreboard_without_baseline():
    veronica = SuiteResult("v1", "veronica", (_tr("v1.a", True, 0, 0.5),))
    md = render_scoreboard(veronica)
    assert "v1.a" in md
    assert "Beat?" not in md
