# Veronica vs. cua (Computer-Use Agents)

> Baseline study + benchmark design. Goal: understand what [cua](https://github.com/trycua/cua)
> does, where Veronica can match it *faster* (no screenshots), and where the
> two are fundamentally different animals.

Status: **v0 — baseline & task catalog.** Numbers to be filled by live runs
(see `benchmarks/cua-parity/`). This document is the "know your competitor"
groundwork before we start iterating.

---

## TL;DR

1. **Yes, cua still uses screenshots.** Its core loop is *sense → think → act*:
   capture a screenshot (+ optionally an accessibility tree), send the pixels to
   a vision-language model, get back a `click(x,y)` / `type(text)` action, repeat.
   Perception can be screenshots, accessibility trees, or Set-of-Marks overlays,
   but the default and dominant path is **visual**.

2. **cua's "efficiency" is not about being fast per action — it's the opposite.**
   cua is efficient as *infrastructure*: sandboxed VMs, one API across
   macOS/Linux/Windows/Android, thousands of trajectories in parallel for
   training/eval. But *per task*, the screenshot→VLM→action loop is slow and
   wasteful (numbers below). This is exactly the gap Veronica is aiming at.

3. **Veronica and cua are different paradigms**, and this shapes everything:
   - **cua is goal-driven and perceptual.** You hand it a task ("book a flight",
     "fix the formatting in this doc") and it drives *application GUIs* by looking
     at pixels.
   - **Veronica is reactive and structural.** The kernel (via eBPF) tells it what
     is *actually happening* — `execve`, `openat`, `connect` — and it reacts by
     running commands / setting policy. No pixels, ever.

4. **Parity is real but bounded.** A large fraction of "computer use" tasks are
   really *system operations wearing a GUI costume* (rename files, install a
   package, edit a config, convert an image, run a query). For those, Veronica's
   syscall-level view is strictly better: no screenshot latency, no click
   mis-grounding, deterministic. But a genuinely *graphical* task — judging a
   visual layout, dragging on a canvas, reading text baked into an image, driving
   a closed GUI with no API — **eBPF cannot see pixels** and Veronica cannot do it
   without adding a perception channel. We should be honest about that boundary,
   not paper over it.

---

## How cua works

cua ("Computer-Use Agent" infra by trycua) is best described as **"Docker for
computer-use agents"**: sandboxed OS environments (VM or container) plus an SDK
and benchmark harness for agents that control a *whole desktop*.

### The agent loop (sense → think → act)

```
┌─────────────────────────────────────────────────────┐
│  1. SENSE   capture screenshot of the sandbox VM      │
│             (+ optional a11y tree / Set-of-Marks)     │
│  2. THINK   send image + task + history to a VLM       │
│             (Claude, GPT-4o-class, Gemini, ...)        │
│  3. ACT     model returns an action:                  │
│             click(x,y) / type(text) / key / scroll /   │
│             shell.run(cmd) / multi-touch gesture       │
│  4. LOOP    apply action, screenshot again, repeat     │
└─────────────────────────────────────────────────────┘
```

### Action / tool space

Direct UI interaction primitives (the "computer" the model drives):

| Category | Actions |
|---|---|
| Mouse | `click(x,y)`, double-click, right-click, move, drag |
| Keyboard | `type(text)`, key presses, hotkeys |
| Perception | `screenshot()` (plus a11y tree, Set-of-Marks) |
| Scroll/gesture | scroll, multi-touch gestures (Android) |
| Shell | `shell.run(cmd)` — escape hatch to the command line |

### Perception modalities

- **Screenshots** — raw pixels. The default. Works on *anything* rendered, which
  is the whole point: no API needed, no integration, it just looks at the screen.
- **Accessibility (a11y) tree** — structured UI elements (role, name, value,
  hierarchy). Cheaper and more precise *when the app exposes it*; many apps expose
  it poorly or not at all (this is a documented "accessibility gap").
- **Set-of-Marks** — overlay numbered labels on interactive elements in a
  screenshot so the model can say "click element 7" instead of raw coordinates.
  Improves click grounding.

### What it controls

Full desktops: **macOS, Linux, Windows, Android**. Any GUI app — browsers,
office suites, image editors, IDEs, native apps — because it works at the pixel
level. Ships with benchmark integrations: **OSWorld, ScreenSpot, WindowsAgentArena**,
plus custom tasks, and can export trajectories for RL training.

### The efficiency reality (this is the opening for Veronica)

From **OSWorld-Human: Benchmarking the Efficiency of Computer-Use Agents**
([arXiv 2506.16042](https://arxiv.org/abs/2506.16042)):

- Even the best agents take **1.4×–2.7× more steps than necessary** to finish a task.
- **75%–94% of total latency** is the LLM planning/reflection calls (the "think"
  in sense-think-act), *not* the actual actions.
- Latency compounds: **each successive step can take ~3× longer** than early steps
  as context grows.
- Many steps don't even need a fresh screenshot (clicking a text box, typing,
  pressing enter — no UI change) yet the loop takes one anyway.

So the per-task cost of the screenshot→VLM loop is dominated by repeated
vision-model round-trips. **That is the tax Veronica avoids by reading the kernel
instead of the screen.**

---

## How Veronica works (for contrast)

```
┌─────────────────────────────────────────────────────┐
│  eBPF probes in the kernel  (execve, openat, connect) │
│        │  writes event struct to ring buffer          │
│        ▼                                               │
│  Go daemon  →  classifier  →  Agentfield control plane │
│        │                                               │
│        ▼                                               │
│  Python behavior agent  →  LLM (LM Studio)  →  decides │
│        │                                               │
│        ▼                                               │
│  Calls daemon skills: exec / enforce / transform /     │
│  schedule / measure / map+program ops                  │
└─────────────────────────────────────────────────────┘
```

- **Perception = structured kernel events**, not pixels. A process start arrives
  as `{comm, cmdline, pid, uid, filename, ppid}` — already parsed, already exact.
  No OCR, no click grounding, no ambiguity.
- **Action = shell commands and eBPF policy**, not mouse/keyboard. `exec` runs a
  command; `enforce` blocks a file/IP; `transform` rewrites packets; `schedule`
  renices; `measure` reads perf counters.
- **Trigger model = reactive.** Today Veronica does not take a goal and drive it
  to completion. It *reacts* to things the user/system does. (See gap #1 below.)

### Why "faster" is a legitimate claim

For any task expressible as system operations, Veronica has **zero screenshots,
zero vision inference, and one LLM decision** (event → action) instead of an
N-step visual loop. Where cua spends 75–94% of latency on repeated VLM calls over
screenshots, Veronica spends one text-only LLM call over a small structured event.
That's the thesis, and the benchmark exists to prove or bound it.

---

## The two big gaps to close before parity is even measurable

These are architectural, not tuning. Iteration should start here.

1. **Reactive → goal-driven.** cua accepts a *task* and runs a loop until done.
   Veronica reacts to events. To "do what cua can do", Veronica needs a
   **goal-driven executor mode**: accept an instruction, plan, call skills in a
   loop, verify completion. The eBPF event stream becomes *feedback* ("did my
   command actually open the file / start the process?") rather than the sole
   trigger.

2. **No perception channel for genuinely graphical tasks.** eBPF sees syscalls,
   not pixels. Tasks that are inherently visual (read a chart, judge a layout,
   operate a canvas/closed GUI) are **out of reach** for the pure-kernel approach.
   Options later: (a) accept these as out-of-scope and own the system-ops
   category, or (b) add an optional perception fallback (a11y tree / screenshot)
   *only* for the tasks that truly need it — a hybrid where kernel-first is the
   fast path and pixels are the exception, not the rule.

---

## Capability mapping: cua task → Veronica feasibility

Every "computer use" task falls into one of three buckets. This classification is
the strategic core — it says where we win, where we have work to do, and where we
shouldn't pretend.

| Bucket | Meaning | Veronica story |
|---|---|---|
| 🟢 **native** | Pure system/FS/process/network op. Kernel already sees it. | **We win.** No pixels, faster, deterministic. Often already implemented. |
| 🟡 **headless** | GUI task that has a CLI/headless/API equivalent (LibreOffice headless, ImageMagick, git, sqlite, curl). | **Achievable** once goal-driven mode + tool adapters exist. Still no screenshots. |
| 🔴 **blind** | Genuinely perceptual/graphical. No structural signal, no API. | **eBPF can't do it.** Needs a perception fallback or is out-of-scope. Be honest. |

Examples across OSWorld-style app categories:

| cua does (example) | App | Bucket | Veronica approach |
|---|---|---|---|
| Rename/move/organize files | File manager | 🟢 native | `exec` mv/rename; `file_open` events confirm |
| Install / configure a package | Terminal/GUI | 🟢 native | `exec` apt/uv; `process_exec` confirms |
| Edit a config file + reload service | Text editor | 🟢 native | already an example (nginx.conf validate+reload) |
| Change a system/network setting | Settings | 🟢 native | `exec` / `enforce` / `transform` |
| Kill/limit a runaway process | System monitor | 🟢 native | `schedule` / `measure` / cgroup |
| Find & replace across a spreadsheet | LibreOffice Calc | 🟡 headless | `soffice --headless` macro, or parse xlsx |
| Convert / edit / crop an image | GIMP | 🟡 headless | ImageMagick via `exec` |
| Reformat / export a document | LibreOffice Writer | 🟡 headless | `soffice --headless --convert-to` |
| Git operations, run tests, build | VS Code | 🟡 headless | `exec` git/make; `process_exit` for pass/fail |
| Fill a web form / scrape data | Chrome | 🟡 headless | HTTP/API or headless browser (Playwright) |
| Judge which layout "looks better" | Impress/GIMP | 🔴 blind | no structural signal — perception needed |
| Read text rendered inside an image | any | 🔴 blind | OCR/vision only |
| Drag nodes on a canvas / whiteboard | Figma-like | 🔴 blind | no API, pixel-only |
| Operate a closed proprietary GUI | vendor app | 🔴 blind | screenshot fallback or out-of-scope |

The full, machine-readable catalog lives in
[`benchmarks/cua-parity/tasks.yaml`](../benchmarks/cua-parity/tasks.yaml).

---

## Benchmark design

See [`benchmarks/cua-parity/README.md`](../benchmarks/cua-parity/README.md) for
the runnable spec. Summary:

### Reference baselines (cua / SOTA CUAs)

- **OSWorld** — 369 real desktop tasks across real apps on Ubuntu/Windows/macOS.
  - Human baseline: **72.36%** success.
  - SOTA has now *passed* humans (mid-80s% on some trackers as of 2026) — so
    capability is no longer the story; **efficiency is.**
- **OSWorld-Human efficiency baseline** — the numbers we actually target:
  1.4–2.7× excess steps; 75–94% of latency in vision/LLM calls.
- **ScreenSpot** — click-grounding accuracy (not relevant to Veronica; we have no
  clicks to ground). Kept only to remind us *why* cua needs it and we don't.

### Metrics we track (per task)

| Metric | cua | Veronica | Why it matters |
|---|---|---|---|
| `success` | 0/1 (task oracle) | 0/1 (same oracle) | parity must be measured on *outcome*, same checker |
| `wall_clock_s` | full loop | event→done | the headline "faster" claim |
| `llm_calls` | plan+reflect per step | ideally 1 | where cua's latency lives |
| `screenshots` | N | **0** (native/headless) | the whole thesis |
| `steps` | actions taken | skills called | excess-step comparison |
| `bucket` | — | native/headless/blind | scopes the fair-comparison set |

The honest headline number is **success-rate on the 🟢+🟡 subset at a fraction of
the wall-clock / zero screenshots**, *not* "beats cua on all 369 OSWorld tasks"
(the 🔴 tasks are not a fair fight in either direction).

### v0 baseline: what we measure first

Because Veronica isn't goal-driven yet, v0 baseline = **the 11 existing Veronica
scenarios** (`docs/examples.md`) re-scored with these metrics, established as the
"reactive baseline". Then we add a small goal-driven task set (bucket 🟢/🟡) and
grow it. The task catalog seeds ~30 tasks spanning the three buckets.

---

## Iteration roadmap (later)

1. **Goal-driven executor mode** — accept a task string, plan → call skills →
   verify via eBPF feedback → loop. Unlocks the whole 🟡 bucket. (Gap #1)
2. **Tool adapters for the 🟡 bucket** — headless LibreOffice, ImageMagick,
   Playwright, sqlite — so "GUI tasks" become deterministic `exec` calls.
3. **Head-to-head harness** — run the same OSWorld-subset task through cua and
   Veronica, same success oracle, log all metrics. Prove the latency/step delta.
4. **Decide the 🔴 boundary** — either declare visual tasks out-of-scope (own the
   system-ops category cleanly) or add an optional perception fallback for the
   rare tasks that need it.

---

## Sources

- [trycua/cua (GitHub)](https://github.com/trycua/cua)
- [cua README](https://github.com/trycua/cua/blob/main/README.md)
- [cua benchmarks docs](https://www.trycua.com/docs/agent-sdk/benchmarks)
- [OSWorld-Human: Benchmarking the Efficiency of Computer-Use Agents (arXiv 2506.16042)](https://arxiv.org/abs/2506.16042)
- [OSWorld benchmark & leaderboards](https://leaderboard.steel.dev/leaderboards/osworld/)
- [Inside Windows Computer Use (cua blog)](https://github.com/trycua/cua/blob/main/blog/inside-windows-computer-use.md)
</content>
</invoke>
