# Veronica — eBPF Intelligence Layer

## Top 3 Priorities
1. **Lima** — Cross-platform VM runtime (macOS: Virtualization.framework, Linux: QEMU). Fedora 43 guest with kernel 6.17 for full eBPF support including sched_ext.
2. **Hybrid Model/Harness** — Claude Opus 4.6 (via Claude Code) for development. mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled (via LM Studio, localhost:1234, parallel inference) for runtime intelligence.
3. **eBPF** — All six powers: observe, enforce, transform, schedule, measure, iterate. Dozens of probes across kprobes, tracepoints, XDP, TC, LSM, sched_ext, uprobes, perf_event.

## Architecture
- **Single Go binary** running as root in a Lima Fedora 43 VM
- **eBPF Manager**: loads C programs via cilium/ebpf, reads ring buffers, writes maps
- **Coordinator**: single goroutine, owns action queue, serializes all writes, resolves conflicts via Qwen
- **Conversation goroutines**: spawned per event, call Qwen directly (parallel), read-only locally, write via coordinator
- **Shared state**: buntdb file mode, single AOF persistence, LLM reads via structured db queries
- **Agent SDK**: custom ~300 LOC, tool-calling loop with Go generics, no external deps
- **Observer**: basic CLI log output for now, TUI/dashboard later
- **Design spec**: `docs/superpowers/specs/2026-04-03-veronica-design.md`

## Lima VM
- Config: `lima/veronica.yaml`
- Create: `limactl create --name=veronica lima/veronica.yaml`
- Start: `limactl start veronica`
- Shell: `limactl shell veronica`
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
- Tests (non-eBPF): `go test ./internal/agent/ ./internal/llm/ ./internal/tool/ ./internal/state/ ./internal/coordinator/` — works on macOS
- Tests (eBPF): must run in VM

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
