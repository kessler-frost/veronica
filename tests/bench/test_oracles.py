"""Oracle tests — deterministic pass/fail from output artifacts."""

from __future__ import annotations

from veronica.bench.oracles import ORACLES, csv_matches
from veronica.bench.suite import SUITE_V1_BY_ID


def test_csv_matches_order_insensitive(tmp_path):
    (tmp_path / "products.csv").write_text("widget, 3.50 , 12\ngadget, 9.00, 4\n")
    (tmp_path / "expected.csv").write_text("gadget,9.00,4\nwidget,3.50,12\n")
    assert csv_matches("products.csv")(tmp_path).passed is True


def test_csv_matches_detects_wrong_rows(tmp_path):
    (tmp_path / "products.csv").write_text("widget,3.50,12\n")
    (tmp_path / "expected.csv").write_text("widget,3.50,13\n")
    res = csv_matches("products.csv")(tmp_path)
    assert res.passed is False
    assert "!=" in res.detail


def test_csv_matches_missing_output(tmp_path):
    (tmp_path / "expected.csv").write_text("a,1\n")
    res = csv_matches("products.csv")(tmp_path)
    assert res.passed is False
    assert "missing output" in res.detail


def test_registry_covers_every_suite_task():
    """Every frozen suite task must have an oracle (real or pending)."""
    assert set(ORACLES) == set(SUITE_V1_BY_ID)


def test_pending_tasks_fail_closed(tmp_path):
    # A pending oracle must fail (never green by omission).
    assert ORACLES["v1.media.transcode"](tmp_path).passed is False
