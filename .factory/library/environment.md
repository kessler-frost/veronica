# Environment

Environment variables, external dependencies, and setup notes.

**What belongs here:** Required env vars, external API keys/services, dependency quirks, platform-specific notes.
**What does NOT belong here:** Service ports/commands (use `.factory/services.yaml`).

---

## Go
- Module: `github.com/fimbulwinter/veronica`
- Key deps: `github.com/Agent-Field/agentfield/sdk/go/agent`, `github.com/cilium/ebpf`, `github.com/goccy/go-json`
- In VM: `GOTOOLCHAIN=auto` needed for Go version management
- macOS has no /proc filesystem — tests must mock file I/O

## Python
- Managed with `uv` (NEVER pip)
- Key deps: `agentfield>=0.1.63`, `httpx>=0.28`, `msgspec>=0.19`, `pydantic-settings>=2.0`, `typer>=0.15`
- CLI entry: `uv run veronica`

## Lima VM
- Instance name: `veronica`
- SSH: `limactl shell veronica` or port 59556
- Host from VM: `host.lima.internal`
- Project path in VM: `/home/fimbulwinter.linux/veronica`
- 4 CPUs, 8GB RAM (Ubuntu guest)

## LM Studio
- Model: `mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled`
- API: `http://localhost:1234/v1/chat/completions` (OpenAI-compatible)
- From VM: `http://host.lima.internal:1234`
