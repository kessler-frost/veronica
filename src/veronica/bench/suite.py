"""Suite v1 — the frozen 10-task chase set, as executable BenchTasks.

Mirrors benchmarks/cua-parity/suite-v1.yaml (the frozen spec), exactly the way
control/catalog.py mirrors the Go catalog. Keep the ids and instructions in
lockstep with the yaml; the yaml is the human-facing spec, this is what the
runner executes. All rows are bucket=headless — the fair chase set.
"""

from __future__ import annotations

from veronica.bench.model import BenchTask

SUITE_V1: tuple[BenchTask, ...] = (
    BenchTask(
        "v1.web.form_submit",
        "web / Chrome",
        "Open the local test page, fill name/email/message, submit the form.",
    ),
    BenchTask(
        "v1.web.scrape_table",
        "web / Chrome",
        "From the given page, extract the products table to CSV (name,price,stock).",
    ),
    BenchTask(
        "v1.calc.find_replace",
        "office / LibreOffice Calc",
        "In sheet.ods, replace every 'Pending' in column C with 'Closed', save.",
    ),
    BenchTask(
        "v1.calc.formula_column",
        "office / LibreOffice Calc",
        "In orders.ods add column D = B*C, then put the sum of D in E1.",
    ),
    BenchTask(
        "v1.writer.docx_to_pdf",
        "office / LibreOffice Writer",
        "Set report.docx title to 'Q3 Summary', export the doc to report.pdf.",
    ),
    BenchTask(
        "v1.image.crop_convert",
        "image / GIMP",
        "Crop input.png to the center 512x512 and save as output.jpg quality 85.",
    ),
    BenchTask(
        "v1.image.batch_watermark",
        "image / GIMP",
        "Resize every *.png in ./photos to max width 1024 and watermark bottom-right.",
    ),
    BenchTask(
        "v1.media.transcode",
        "media / video player",
        "Convert clip.mp4 to clip.webm (VP9) and extract clip.mp3 (audio only).",
    ),
    BenchTask(
        "v1.db.query_export",
        "data / DB GUI",
        "In store.db, export customers with >5 orders to top_customers.csv.",
    ),
    BenchTask(
        "v1.pdf.merge_extract",
        "docs / PDF viewer",
        "Merge a.pdf and b.pdf into merged.pdf, then write pages 2-3 to excerpt.pdf.",
    ),
)

SUITE_V1_BY_ID: dict[str, BenchTask] = {t.id: t for t in SUITE_V1}
