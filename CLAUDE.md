# Veronica — eBPF Intelligence Layer

## Top 3 Priorities
1. **Lima** — Cross-platform VM runtime (macOS: Virtualization.framework, Linux: QEMU). Fedora 43 guest with kernel 6.17 for full eBPF support including sched_ext.
2. **Hybrid Model/Harness** — Claude Opus 4.6 (via Claude Code) for development. mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled (via LM Studio, localhost:1234, parallel inference) for runtime intelligence.
3. **eBPF** — All six powers: observe, enforce, transform, schedule, measure, iterate. Dozens of probes across kprobes, tracepoints, XDP, TC, LSM, sched_ext, uprobes, perf_event.

## Architecture
- **Daemon** (Go, runs as root in Lima VM): eBPF manager, classifier, embedded NATS server + JetStream. Publishes events to NATS subjects. Tool responders on NATS request/reply. All state in NATS KV.
- **Host Agents** (Python, run on macOS host): connect to daemon via NATS, subscribe to event types, run LLM loops (any harness). Created from natural language via `veronica agent add`.
- **NATS** replaces WebSocket + buntdb. Events stream (5min TTL), KV buckets for agents/tasks/policies/logs.
- **Why not SSH**: daemon holds live eBPF map/program file descriptors. The daemon IS the eBPF runtime.
- **Noise filtering**: TEMPORARY — hardcoded silent command lists in Go classifier + Python agent. Will be replaced with smarter approach (LLM-based, frequency-based, or eBPF map-driven).
- **Design specs**: `docs/superpowers/specs/2026-04-03-veronica-design.md`, `docs/superpowers/specs/2026-04-04-two-step-model-design.md`

## CLI (use this, not raw limactl)
- Build CLI: `go build -o /tmp/veronica ./cmd/cli/`
- First time: `limactl create --name=veronica lima/veronica.yaml && /tmp/veronica vm start`
- Start daemon: `/tmp/veronica start`
- Stop daemon: `/tmp/veronica stop`
- View status: `/tmp/veronica status`
- Stream logs: `/tmp/veronica logs`
- Build + deploy: `/tmp/veronica build`
- SSH into VM: `/tmp/veronica vm ssh`
- Stop VM: `/tmp/veronica vm stop`

## Lima VM (internals)
- Config: `lima/veronica.yaml`
- Mount path inside VM: `/Users/fimbulwinter/dev/veronica` (virtiofs, writable)
- LLM from VM: `http://host.lima.internal:1234`
- Go in VM needs `GOTOOLCHAIN=auto` since Fedora ships Go 1.25 but go.mod requires 1.26

## eBPF Development
- C programs live in `internal/ebpf/programs/` — compile only on Linux (not macOS)
- `vmlinux.h` generated in VM via: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- Compile: `clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c program.c -o program.o`
- Go bindings generated via `go generate ./internal/ebpf/bpf/` (must run in VM)
- Prefix all custom structs with `vr_` to avoid kernel type name conflicts (vmlinux.h has `event_header`)
- cilium/ebpf API: `link.Tracepoint(group, name, prog, opts)`, `link.Kprobe(symbol, prog, opts)` — NOT `AttachTracepoint`/`AttachKprobe`
- macOS clang diagnostics on .c files are expected and harmless — BPF headers only exist in the VM

## Build
- Daemon: build in VM with `GOTOOLCHAIN=auto go build -o /tmp/veronica ./cmd/veronica/`
- Run: `sudo /tmp/veronica` (needs root for eBPF)
- Tests (non-eBPF): `go test ./internal/event/ ./internal/classifier/ ./internal/nats/ -v` — works on macOS
- Tests (eBPF): must run in VM

## NATS
- Embedded in daemon, port 4222
- From host: `nats://localhost:4222` (forwarded via Lima port forwarding)
- From VM: in-process connection

## LM Studio (Runtime LLM)
- Model: `mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled` (Jackrong/MLX-Qwen3.5-35B-A3B-Claude-4.6-Opus-Reasoning-Distilled-4bit)
- Start server: `lms server start`
- Load model: `lms load mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled -c 262144 --parallel 4 --gpu max`
- Context: 262144 (256k) — always use max
- Parallel inference: 4 concurrent requests
- API: `http://localhost:1234/v1/chat/completions` (OpenAI-compatible)
- From VM: `http://host.lima.internal:1234`
- Model supports tool use natively (`trainedForToolUse: true`)
- Check status: `lms ps --json`

## Build Tools
- Go modules for the main project
- Cilium's `ebpf` Go package for eBPF program loading/interaction
- clang for compiling eBPF C programs (CO-RE/BTF, ahead of time)
- `uv` for any Python tooling
- `bun` for any JS/TS tooling
- No Windows support — ever
