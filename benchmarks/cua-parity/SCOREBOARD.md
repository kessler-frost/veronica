# cua-parity Scoreboard (Suite v1)

Living tracker for the 10-task chase set in [`suite-v1.yaml`](./suite-v1.yaml).
cua is measured **once** (the baseline target); Veronica is re-measured every time
we ship a feature, until it beats every row. **Win = same oracle passes at 0
screenshots and lower wall-clock than cua.**

## How the baseline works (read this before trusting a number)

- **cua cannot be run from the dev CI container** (needs macOS/Linux + VM sandbox +
  vision LLM). The cua column is filled by **one turnkey run on a real host**, then
  frozen. See "Running the baseline" below.
- Until that run exists, cua cells are marked `~exp` (expected, provisional) and
  anchored to published data — **not** measured. Don't cite `~exp` as fact.
- Published anchor (real, cited): OSWorld-Verified SOTA **~85%** (Anthropic Claude
  agents), human baseline **72.36%**; efficiency — **1.4–2.7× excess steps**,
  **75–94% of latency in vision/LLM calls**, **≥1 screenshot/step**
  ([OSWorld-Human](https://arxiv.org/abs/2506.16042)).

## Scoreboard

Legend: ✅ pass · ❌ fail · ⬜ not built · `~exp` provisional (unmeasured)

| # | Task | cua success | cua shots | cua time | Veronica success | Veronica shots | Veronica time | Beat? |
|---|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| 1 | web.form_submit    | `~exp` ✅ | `~exp` 6–10 | `~exp` | ⬜ | 0 | — | — |
| 2 | web.scrape_table   | `~exp` ✅ | `~exp` 4–8  | `~exp` | ⬜ | 0 | — | — |
| 3 | calc.find_replace  | `~exp` ✅ | `~exp` 5–9  | `~exp` | ⬜ | 0 | — | — |
| 4 | calc.formula_column| `~exp` ✅ | `~exp` 6–12 | `~exp` | ⬜ | 0 | — | — |
| 5 | writer.docx_to_pdf | `~exp` ✅ | `~exp` 5–9  | `~exp` | ⬜ | 0 | — | — |
| 6 | image.crop_convert | `~exp` ✅ | `~exp` 8–14 | `~exp` | ⬜ | 0 | — | — |
| 7 | image.batch_watermark | `~exp` ⚠️ | `~exp` many | `~exp` | ⬜ | 0 | — | — |
| 8 | media.transcode    | `~exp` ✅ | `~exp` 4–8  | `~exp` | ⬜ | 0 | — | — |
| 9 | db.query_export    | `~exp` ✅ | `~exp` 5–9  | `~exp` | ⬜ | 0 | — | — |
| 10| pdf.merge_extract  | `~exp` ✅ | `~exp` 6–10 | `~exp` | ⬜ | 0 | — | — |

`⚠️` row 7 (batch) is where GUI agents degrade — per-image manual steps don't
scale; this is a likely early Veronica win.

**Target after the one-time cua run:** replace every `~exp` with a measured value,
freeze the cua columns, then only the Veronica columns move.

## Running the baseline (one-time, real host)

1. cua side — install cua + a vision LLM, wrap each `suite-v1.yaml` task with its
   oracle, run once, capture `success / screenshots / wall_clock_s / steps` →
   `results/cua-v1-<date>.json`. Freeze it and paste into the cua columns above.
2. Veronica side — after each feature ships, run the same tasks through the
   goal-driven executor → `results/veronica-v1-<date>.json`, update the Veronica
   columns, tick **Beat?** when success matches at fewer shots + less time.

## Progress log

| Date | Event | Rows Veronica beats |
|------|-------|:--:|
| (pending) | suite v1 frozen; cua baseline not yet measured | 0 / 10 |
</content>
