# Goal-Driven Executor — Roadmap / Backlog

> The work items to make Veronica do what a computer-use agent (cua) does, but
> faster — by acting at the highest-signal, lowest-cost layer instead of pixels.
> Companion to [`cua-comparison.md`](./cua-comparison.md) and
> [`../benchmarks/cua-parity/`](../benchmarks/cua-parity/).

Status: **planning.** Nothing here is built yet. This is the ordered list, not a
spec — each phase gets its own design doc when we start it.

## The two modes (parallel, not sequential)

Veronica runs **two agents over one daemon skill surface**:

- **Reactive** (exists today): kernel event → "should I act?" → remediate.
  This is the App-Aware Kernel Control Plane already on `main` (observe + enforce,
  audit-first).
- **Goal-driven** (this roadmap): task string → plan → act → verify via kernel
  feedback → loop until done.

They share one thing worth building well: an **action-resolution layer** — "I want
to accomplish X; what's the cheapest layer that actually makes it happen?" Both
modes call into it.

## Design principle: the ladder of abstraction

Always act at the **highest-signal, lowest-cost rung available**; descend only when
forced. This is *why* Veronica is faster than cua — cua starts every action at the
bottom rung (pixels) for everything.

| Rung | Channel | App cooperation | Cost |
|---|---|---|---|
| 1 (top) | Kernel / syscalls / eBPF-LSM | none — universal | lowest |
| 2 | Structured app channels: CLI/exec, D-Bus, UNO, CDP, LSP, local APIs | per-app, already exists | low |
| 3 | Accessibility tree (AT-SPI) — generic structured GUI | app exposes a11y | medium |
| 4 (bottom) | Pixels (screenshot / OCR) | none — but blind & slow | highest |

**Decision (locked):** we do **not** invent a new universal abstraction layer
(would need ecosystem adoption we can't force). We build a uniform broker *over the
rungs that already exist*, and only add rung 4 as a last-resort fallback if ever.

---

## Phase 0 — Foundations (do first, cheap, no downside)

- [ ] **Verified-trajectory logging.** Every executor run logs `task → skills
      called → what eBPF actually observed as the outcome`. This is the data moat:
      raw material for both distillation (speed) and RL-on-verified-outcomes
      (quality). cua exports trajectories; ours are *kernel-verified*. Cost ≈ zero.
- [ ] **Success-oracle harness.** Reuse OSWorld's per-task checkers so `success`
      means the same thing for Veronica and cua. Without a shared oracle no
      head-to-head number is credible.
- [ ] **Metrics plumbing.** Emit `success / wall_clock_s / llm_calls / screenshots
      / steps / bucket` per run into `benchmarks/cua-parity/results/`.

## Phase 1 — Goal-driven executor MVP (the centerpiece)

- [ ] **Executor loop.** Accept a task string → plan → call daemon skills → read
      eBPF feedback → verify sub-goal → loop or stop. Runs as a second Agentfield
      agent alongside the reactive one.
- [ ] **Action-resolution registry v0 — rungs 1–2 only.** Map a planned action to
      the best available channel; MVP covers kernel (observe/verify) + `exec` CLI.
      Structured (D-Bus/UNO/CDP) and a11y rungs come later.
- [ ] **Kernel-feedback verification.** "Did it work?" answered by the event
      stream: did the process `execve`? did the file get written? exit code?
      This is the differentiator vs cua's vision-judged success.
- [ ] **Safety reuse.** Route destructive/ambiguous actions through the existing
      warden audit-first + `panic` kill-switch + self-protection guard list. The
      executor must not become a bypass around enforcement.
- [ ] **Planner prompt + structured output.** Schema-validated plan steps, same
      discipline as the control-plane catalog (no free-form kernel/shell escapes
      beyond the vetted skill surface).

## Phase 2 — Close the 🟡 "headless" bucket (rung 2 adapters)

Each adapter turns a class of "GUI tasks" into deterministic, screenshot-free
calls. Priority by task frequency in OSWorld:

- [ ] **Web** — Playwright / CDP headless (form-fill, scrape, navigate).
- [ ] **Office** — LibreOffice headless / UNO (`--convert-to`, macros for
      Calc/Writer/Impress).
- [ ] **Images** — ImageMagick (crop/resize/convert/batch).
- [ ] **Media** — ffmpeg (transcode).
- [ ] **Data** — sqlite / psql (query + export).
- [ ] Each adapter registers as a rung-2 resolver for its task class + gets
      parity tasks flipped from `not-started` in `tasks.yaml`.

## Phase 3 — Head-to-head benchmark

- [ ] **Runner** — same OSWorld-subset task through both cua and Veronica, same
      oracle, all metrics logged to `results/`.
- [ ] **Report** — success on 🟢+🟡 subset + the wall-clock / step / screenshot
      delta. The headline: "≈parity success at N× less latency, 0 screenshots."
- [ ] **v0 reactive baseline** — re-score the 11 shipped scenarios first, as the
      "Veronica today" reference point.

## Phase 4 — Optimize (only when a specific pain shows up)

- [ ] **Distill the planner** to a small local model (already on distilled MLX
      qwen) — *when latency, not correctness, is the bottleneck.*
- [ ] **RL on verified outcomes** — use kernel-truthed rewards; a moat cua can't
      easily copy. *Only once we have logged trajectories and a reliability gap.*
- [ ] **Decide the 🔴 boundary** — either declare genuinely-visual tasks
      out-of-scope (own the system-ops lane cleanly) or add rung-3 a11y (rung-4
      pixels) fallback for the few tasks that truly need it.

---

## Dependencies / ordering

```
Phase 0 (logging + oracle + metrics)
   └─► Phase 1 (executor MVP, rungs 1–2)
          ├─► Phase 2 (adapters, rung 2 breadth)
          └─► Phase 3 (head-to-head)  ── needs 0's oracle + 1's executor
                 └─► Phase 4 (train/optimize) ── needs 0's trajectories + 3's data
```

## Open questions (resolve during Phase 1 design)

- Do reactive and goal-driven share one Agentfield agent process or two?
- Where does the plan live — Python warden (reasoning) with the daemon staying
  deterministic, mirroring the control-plane split? (Leaning yes.)
- Rollback semantics: if a multi-step task half-completes, do we auto-revert via
  the same lifecycle machinery, or leave state and report?
- Trajectory schema — reuse the observation buffer format or a new one?
</content>
