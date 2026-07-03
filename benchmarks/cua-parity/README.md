# cua-parity benchmark

Measure Veronica against [cua](https://github.com/trycua/cua)-style computer-use
agents on the tasks where a fair comparison exists — and prove the thesis:
**same outcome, a fraction of the latency, zero screenshots.**

Read [`docs/cua-comparison.md`](../../docs/cua-comparison.md) first for the
strategy. This directory is the runnable side of it.

## Files

- `tasks.yaml` — the task catalog (source of truth). Each task is bucketed
  `native` / `headless` / `blind` and carries a `veronica_status`.
- `results/` — measured runs (JSON), one file per run. Git-tracked so we can see
  the delta over time. *(created on first run)*

## The comparison, honestly scoped

cua drives *pixels*; Veronica reads the *kernel*. A head-to-head across all 369
OSWorld tasks is not a fair fight in either direction:

- On `blind` (🔴) tasks — visual judgment, canvas, OCR — Veronica has no
  perception channel and should not be scored as if it could compete.
- On `native` (🟢) and `headless` (🟡) tasks — file/process/network ops and
  GUI actions with a headless equivalent — Veronica should *win on efficiency*
  while matching the outcome.

So the headline number is: **success rate on the 🟢+🟡 subset, at X% of cua's
wall-clock and 0 screenshots.** Not "beats cua at everything."

## Metrics (per task)

| Metric | Definition |
|---|---|
| `success` | Task oracle (same checker for both agents) returns pass/fail |
| `wall_clock_s` | End-to-end: task accepted → oracle passes |
| `llm_calls` | Number of model round-trips |
| `screenshots` | Vision captures taken (Veronica target: 0 on 🟢/🟡) |
| `steps` | Actions/skills invoked |
| `bucket` | native / headless / blind (from `tasks.yaml`) |

### Reference baselines (cua / SOTA CUAs)

- **OSWorld**: 369 tasks. Human success **72.36%**. SOTA CUAs now exceed humans
  (mid-80s% on some 2026 trackers) — capability is solved; **efficiency is the
  game.**
- **OSWorld-Human** (the efficiency numbers we target):
  - agents take **1.4×–2.7× more steps** than necessary
  - **75%–94% of latency** is in LLM planning/reflection calls over screenshots
  - one screenshot per step, many redundant

Veronica's target on 🟢/🟡: **1 LLM call, 0 screenshots, no excess steps.**

## v0 baseline (what to measure first)

Veronica is not goal-driven yet (see gaps in the comparison doc), so v0 is the
**reactive baseline**: re-score the 11 shipped scenarios in `docs/examples.md`
with the metrics above. That establishes "here is Veronica today" before we build
goal-driven mode and start closing the 🟡 bucket.

Suggested `results/` record shape:

```json
{
  "run": "v0-reactive-baseline",
  "date": "YYYY-MM-DD",
  "agent": "veronica@<git-sha>",
  "tasks": [
    {
      "id": "native.config.edit_validate_reload",
      "success": true,
      "wall_clock_s": 0.0,
      "llm_calls": 1,
      "screenshots": 0,
      "steps": 1,
      "bucket": "native"
    }
  ]
}
```

## Roadmap to a real head-to-head

1. **Goal-driven executor mode** in Veronica (accept task → plan → call skills →
   verify via eBPF feedback → loop). Unlocks the 🟡 bucket.
2. **Tool adapters** for 🟡: headless LibreOffice, ImageMagick, ffmpeg, Playwright,
   sqlite.
3. **Shared success oracles** — reuse OSWorld's per-task checkers so `success`
   means the same thing for cua and Veronica.
4. **Head-to-head harness** — run the same task through both, log all metrics,
   commit to `results/`.

Note: running cua itself needs a macOS/Linux host with a VM sandbox + a
vision-capable LLM, and Veronica needs its Lima VM + LM Studio. Neither runs in
this repo's CI container — these benchmarks are executed on a dev host, and only
the `results/*.json` are committed.
</content>
