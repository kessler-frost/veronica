# Veronica — eBPF Intelligence Layer

> Proactive agents at the kernel level, powered by eBPF

## Why Agentfield

I migrated from NATS + MCP + OpenCode to [Agentfield](https://github.com/Agent-Field/agentfield) for two fundamental reasons:

1. **Native Python AND Go SDK support.** I couldn't find another framework that had first-class SDKs for both languages. My Go daemon (eBPF runtime) and Python behavior agents were stitched together with NATS message passing, FastMCP bridging, and OpenCode REST calls — three separate protocols just to connect two languages. Agentfield gives me one unified control plane with native SDKs on both sides.

2. **Bidirectional communication without MCP.** MCP is inherently unidirectional — the model calls tools, but tools can't push events back to the model. I need true bidirectional communication: the Go daemon pushes eBPF events TO agents, and agents call functions BACK on the daemon. MCP forced me to build a Rube Goldberg machine (NATS → EventWatcher → OpenCode → MCP → FastMCP → NATS) just to achieve what Agentfield does natively through its control plane.

**Zero MCP. Zero NATS. Zero OpenCode.** Just Agentfield + eBPF + LM Studio.

## Top 3 Priorities
1. **Lima** — Cross-platform VM runtime (macOS: Virtualization.framework, Linux: QEMU). Ubuntu guest with full eBPF support.
2. **Agentfield** — Control plane on macOS host. Go daemon registers functions, Python behavior agents react to events. Direct LM Studio API for LLM reasoning.
3. **eBPF** — All six powers: observe, enforce, transform, schedule, measure, iterate.

## Architecture
- **Daemon** (`cmd/veronicad/`): Go binary, runs as root in Lima VM. eBPF manager, classifier. Registers functions (exec, enforce, transform, schedule, measure, map/program ops) with Agentfield control plane. Pushes classified eBPF events to control plane.
- **Behavior Agents** (`src/veronica/`): Python, runs on macOS host. Each user-defined behavior becomes an Agentfield agent that subscribes to relevant eBPF events and calls daemon functions through the control plane. LLM reasoning via direct LM Studio API calls.
- **Control Plane**: Agentfield server (`af server`) runs on macOS host. Routes events from daemon to agents, routes function calls from agents to daemon. Built-in async execution, memory, observability.
- **Why not SSH**: daemon holds live eBPF map/program file descriptors. The daemon IS the eBPF runtime.
- **Why not MCP**: unidirectional, requires bridging layers (FastMCP, OpenCode, EventWatcher). Agentfield is bidirectional natively.

## CLI (`uv run veronica`)
- `uv run veronica vm start` — Create/start Lima VM
- `uv run veronica vm stop` — Stop Lima VM
- `uv run veronica vm ssh` — Interactive shell in VM
- `uv run veronica setup` — Full setup: sync source, compile eBPF, build daemon, install systemd service
- `uv run veronica build` — Sync source, build daemon, restart service
- `uv run veronica add "<description>"` — Add a behavior
- `uv run veronica list` — List all behaviors
- `uv run veronica rm "<description>"` — Remove a behavior (partial match)
- `uv run veronica start` — Start VM + daemon + Agentfield control plane + behavior agents (blocks, Ctrl+C to stop)
- `uv run veronica stop` — Stop everything
- `uv run veronica status` — Show VM, daemon, and agent status
- `uv run veronica logs` — Stream daemon logs (journalctl)
- `uv run veronica run <cmd>` — Run arbitrary command in VM

## Lima VM
- Config: `lima/veronica.yaml` (base: Ubuntu `template:default`)
- Files copied into VM via `limactl cp` (no host mounts)
- Project path in VM: `/home/fimbulwinter.linux/veronica`
- LLM from VM: `http://host.lima.internal:1234`
- Port forwarding: 8090 (Agentfield control plane, daemon connects back to host)
- Go in VM needs `GOTOOLCHAIN=auto`

## eBPF
- C programs in `internal/ebpf/programs/`: process_exec, process_exit, file_open, net_connect (compiled), lsm_enforce, sched_enforce, xdp_filter (not yet compiled)
- Go bindings in `internal/ebpf/bpf/` (generated via `go generate`)
- `vmlinux.h` generated in VM: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- Compile: `clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c program.c -o program.o`
- Prefix custom structs with `vr_` to avoid kernel type name conflicts
- cilium/ebpf API: `link.Tracepoint(group, name, prog, opts)`, `link.Kprobe(symbol, prog, opts)` — NOT `AttachTracepoint`/`AttachKprobe`
- macOS clang diagnostics on .c files are expected and harmless

## Agentfield
- Control plane runs on macOS host: `af server` (port 8090)
- Go daemon connects from VM: `http://host.lima.internal:8090`
- Python behavior agents connect from host: `http://localhost:8090`
- Functions exposed by daemon: exec, enforce, transform, schedule, measure, map.read, map.write, map.delete, program.list, program.load, program.detach
- Events pushed by daemon: process_exec, process_exit, file_open, net_connect

## Build & Test
- Daemon binary: `veronicad`, package `./cmd/veronicad/`, installs to `/usr/local/bin/veronicad`
- Build via CLI: `uv run veronica build` (syncs source + builds in VM)
- Full setup: `uv run veronica setup` (first time — includes eBPF compile + Go generate)
- Go tests (macOS): `go test ./internal/classifier/ ./internal/agent/ -v`
- Python tests: `uv run pytest`
- eBPF tests: must run in VM

## LM Studio (Runtime LLM)
- Model: `mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled`
- Load: `lms load mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled -c 262144 --parallel 4 --gpu max`
- API: `http://localhost:1234/v1/chat/completions` (OpenAI-compatible)
- From VM: `http://host.lima.internal:1234`
- Check status: `lms ps --json`

## Build Tools
- Go modules + cilium/ebpf + Agentfield Go SDK for daemon
- clang for eBPF C programs (CO-RE/BTF)
- `uv` for Python (NEVER pip)
- `bun` for JS/TS (NEVER npm/npx)
- Colima for Docker (not Docker Desktop)
- No Windows support
