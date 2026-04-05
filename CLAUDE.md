# Veronica — eBPF Intelligence Layer

> Proactive agents at the kernel level, powered by eBPF

## Top 3 Priorities
1. **Lima** — Cross-platform VM runtime (macOS: Virtualization.framework, Linux: QEMU). Ubuntu guest with full eBPF support.
2. **Hybrid Model/Harness** — Claude Opus 4.6 (via Claude Code) for development. mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled (via LM Studio, localhost:1234, parallel inference) for runtime intelligence.
3. **eBPF** — All six powers: observe, enforce, transform, schedule, measure, iterate.

## Architecture
- **Daemon** (`cmd/veronicad/`): Go binary, runs as root in Lima VM. Embedded NATS server + JetStream, eBPF manager, classifier, event publisher. Tool responders on NATS request/reply. All state in NATS KV.
- **Host Agent** (`src/veronica/agents/agent.py`): Single Python agent, runs on macOS host. Connects to daemon via NATS, accumulates behaviors from `veronica add`, subscribes to relevant event types dynamically.
- **CLI** (`src/veronica/cli/`): Python (Typer), manages VM lifecycle, daemon, and behaviors.
- **NATS**: embedded server + JetStream. Events stream (5min TTL), KV buckets for agents/tasks/policies/logs.
- **Why not SSH**: daemon holds live eBPF map/program file descriptors. The daemon IS the eBPF runtime.
- **Noise filtering**: TEMPORARY — hardcoded silent command lists in Go classifier + Python agent. Will be replaced with smarter approach.
- **Design specs**: `docs/superpowers/specs/2026-04-03-veronica-design.md`, `docs/superpowers/specs/2026-04-04-two-step-model-design.md`

## CLI (`uv run veronica`)
- `uv run veronica vm start` — Create/start Lima VM
- `uv run veronica vm stop` — Stop Lima VM
- `uv run veronica vm ssh` — Interactive shell in VM
- `uv run veronica setup` — Full setup: sync source, compile eBPF, build daemon, install systemd service
- `uv run veronica build` — Sync source, build daemon, restart service
- `uv run veronica add "<description>"` — Add a behavior
- `uv run veronica list` — List all behaviors and subscriptions
- `uv run veronica rm "<description>"` — Remove a behavior (partial match)
- `uv run veronica start` — Start VM + daemon + agent (blocks, Ctrl+C to stop)
- `uv run veronica stop` — Stop agent + daemon
- `uv run veronica status` — Show VM and daemon status
- `uv run veronica logs` — Stream daemon logs (journalctl)
- `uv run veronica run <cmd>` — Run arbitrary command in VM

## Lima VM
- Config: `lima/veronica.yaml` (base: Ubuntu `template:default`)
- Files copied into VM via `limactl cp` (no host mounts)
- Project path in VM: `/home/fimbulwinter.linux/veronica`
- LLM from VM: `http://host.lima.internal:1234`
- Port forwarding: 4222 (NATS)
- Go in VM needs `GOTOOLCHAIN=auto`

## eBPF
- C programs in `internal/ebpf/programs/`: process_exec, process_exit, file_open, net_connect (compiled), lsm_enforce, sched_enforce, xdp_filter (not yet compiled)
- Go bindings in `internal/ebpf/bpf/` (generated via `go generate`)
- `vmlinux.h` generated in VM: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- Compile: `clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c program.c -o program.o`
- Prefix custom structs with `vr_` to avoid kernel type name conflicts
- cilium/ebpf API: `link.Tracepoint(group, name, prog, opts)`, `link.Kprobe(symbol, prog, opts)` — NOT `AttachTracepoint`/`AttachKprobe`
- macOS clang diagnostics on .c files are expected and harmless

## NATS
- Embedded in daemon, port 4222
- From host: `nats://localhost:4222` (Lima port forwarding)
- Tool subjects: `tools.exec`, `tools.enforce`, `tools.transform`, `tools.schedule`, `tools.measure`, `tools.map.read`, `tools.map.write`, `tools.map.delete`, `tools.program.list`, `tools.program.load`, `tools.program.detach`

## Build & Test
- Daemon binary: `veronicad`, package `./cmd/veronicad/`, installs to `/usr/local/bin/veronicad`
- Build via CLI: `uv run veronica build` (syncs source + builds in VM)
- Full setup: `uv run veronica setup` (first time — includes eBPF compile + Go generate)
- Go tests (macOS): `go test ./internal/classifier/ ./internal/nats/ -v`
- Python tests: `uv run pytest`
- eBPF tests: must run in VM

## LM Studio (Runtime LLM)
- Model: `mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled`
- Load: `lms load mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled -c 262144 --parallel 4 --gpu max`
- API: `http://localhost:1234/v1/chat/completions` (OpenAI-compatible)
- From VM: `http://host.lima.internal:1234`
- Check status: `lms ps --json`

## Build Tools
- Go modules + cilium/ebpf for daemon
- clang for eBPF C programs (CO-RE/BTF)
- `uv` for Python (NEVER pip)
- `bun` for JS/TS (NEVER npm/npx)
- Colima for Docker (not Docker Desktop)
- No Windows support
