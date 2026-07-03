"""Success oracles for suite v1.

Each oracle inspects a task's working dir after the agent runs and returns a
deterministic pass/fail — the SAME check for Veronica and (later) cua, so the
number is comparable. Oracles that only become meaningful once a Phase-2 adapter
exists are marked `pending`; they are filled in alongside the adapter that makes
the task doable (see docs/goal-driven-roadmap.md and SCOREBOARD.md).
"""

from __future__ import annotations

import csv
from pathlib import Path

from veronica.bench.model import OracleResult
from veronica.bench.runner import Oracle


def _read_csv_rows(path: Path) -> list[tuple[str, ...]]:
    with path.open(newline="") as f:
        return [tuple(cell.strip() for cell in row) for row in csv.reader(f)]


def csv_matches(
    actual_name: str, expected_name: str = "expected.csv", *, sort: bool = True
) -> Oracle:
    """Oracle: workdir/`actual_name` equals workdir/`expected_name`.

    Order-insensitive by default (rows sorted before compare), whitespace
    trimmed per cell. The expected fixture is placed in the workdir by whoever
    sets up the task; both agents write the same `actual_name` output.
    """

    def check(workdir: Path) -> OracleResult:
        actual_p = Path(workdir) / actual_name
        expected_p = Path(workdir) / expected_name
        if not actual_p.exists():
            return OracleResult(False, f"missing output {actual_name}")
        if not expected_p.exists():
            return OracleResult(False, f"missing fixture {expected_name}")
        actual = _read_csv_rows(actual_p)
        expected = _read_csv_rows(expected_p)
        if sort:
            actual, expected = sorted(actual), sorted(expected)
        if actual != expected:
            return OracleResult(
                False,
                f"{actual_name} != {expected_name} "
                f"({len(actual)} vs {len(expected)} rows)",
            )
        return OracleResult(True, f"{actual_name} matches ({len(actual)} rows)")

    return check


def pending(reason: str) -> Oracle:
    """A not-yet-implemented oracle: always fails with a clear reason.

    Used for tasks whose oracle needs a Phase-2 adapter. Failing (not passing)
    is correct — Veronica can't do these yet, so a run should not score them
    green by omission.
    """

    def check(_workdir: Path) -> OracleResult:
        return OracleResult(False, f"oracle pending: {reason}")

    return check


# Registry: task id -> oracle. CSV-based tasks are fully implemented now (no
# extra deps); the rest are pending their adapter.
ORACLES: dict[str, Oracle] = {
    "v1.web.scrape_table": csv_matches("products.csv"),
    "v1.db.query_export": csv_matches("top_customers.csv"),
    "v1.web.form_submit": pending("needs Phase-1 executor + local test server"),
    "v1.calc.find_replace": pending("needs adapter:libreoffice-headless"),
    "v1.calc.formula_column": pending("needs adapter:xlsx-ods"),
    "v1.writer.docx_to_pdf": pending("needs adapter:libreoffice-headless"),
    "v1.image.crop_convert": pending("needs adapter:imagemagick"),
    "v1.image.batch_watermark": pending("needs adapter:imagemagick"),
    "v1.media.transcode": pending("needs adapter:ffmpeg"),
    "v1.pdf.merge_extract": pending("needs adapter:pdf"),
}
