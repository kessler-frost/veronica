"""Results I/O + scoreboard rendering for the cua-parity benchmark.

Writes a diffable JSON per run into benchmarks/cua-parity/results/ (so the
delta over time lives in git) and renders the Veronica-vs-cua comparison rows.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from veronica.bench.model import SuiteResult, TaskResult


def write_result(result: SuiteResult, path: Path | str) -> Path:
    """Write a SuiteResult as pretty, sorted JSON (stable for git diffs)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "suite": result.suite,
        "agent": result.agent,
        "passed": result.passed,
        "total": result.total,
        "total_screenshots": result.total_screenshots,
        "results": [asdict(r) for r in result.results],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def read_result(path: Path | str) -> SuiteResult:
    """Load a SuiteResult back from disk (inverse of write_result)."""
    payload = json.loads(Path(path).read_text())
    results = tuple(
        TaskResult(
            task_id=r["task_id"],
            bucket=r["bucket"],
            success=r["success"],
            wall_clock_s=r["wall_clock_s"],
            llm_calls=r["llm_calls"],
            screenshots=r["screenshots"],
            steps=r["steps"],
            detail=r.get("detail", ""),
        )
        for r in payload["results"]
    )
    return SuiteResult(
        suite=payload["suite"], agent=payload["agent"], results=results
    )


def render_scoreboard(
    veronica: SuiteResult, baseline: SuiteResult | None = None
) -> str:
    """Render a markdown table of Veronica results, optionally vs a cua baseline.

    When `baseline` (the frozen cua run) is given, adds its columns and a Beat?
    check per row using the SCOREBOARD win condition.
    """
    base = baseline.by_id() if baseline else {}
    header = "| Task | V success | V shots | V time |"
    sep = "|------|:--:|:--:|:--:|"
    if baseline:
        header += " cua success | cua shots | cua time | Beat? |"
        sep += ":--:|:--:|:--:|:--:|"

    lines = [header, sep]
    for r in veronica.results:
        cells = [
            r.task_id,
            "✅" if r.success else "❌",
            str(r.screenshots),
            f"{r.wall_clock_s:.2f}s",
        ]
        if baseline:
            b = base.get(r.task_id)
            if b is None:
                cells += ["—", "—", "—", "—"]
            else:
                cells += [
                    "✅" if b.success else "❌",
                    str(b.screenshots),
                    f"{b.wall_clock_s:.2f}s",
                    "✅" if r.beats(b) else "—",
                ]
        lines.append("| " + " | ".join(cells) + " |")

    won = veronica.beats(baseline) if baseline else 0
    lines.append("")
    lines.append(
        f"Veronica passes {veronica.passed}/{veronica.total}; "
        f"{veronica.total_screenshots} screenshots total"
        + (f"; beats cua on {won}/{veronica.total}." if baseline else ".")
    )
    return "\n".join(lines)
