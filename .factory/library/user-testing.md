# User Testing

Testing surface, tools, and resource cost classification.

## Validation Surface

**Primary surface:** Terminal/CLI in the Lima VM.

The notify feature writes to `/proc/<pid>/fd/1` inside the Lima VM. Validation requires:
1. Starting the Agentfield control plane on the host (port 8090)
2. Building and deploying the daemon to the VM (`uv run veronica build`)
3. Starting the daemon (`limactl shell veronica -- sudo systemctl start veronicad`)
4. Calling `veronicad.notify` via the Agentfield API or a test agent
5. Verifying output in a VM shell session

**Testing tools:**
- `limactl shell veronica -- <command>` for direct VM access
- `curl` for Agentfield API calls
- Go tests on macOS (unit tests with mocked /proc)
- Python tests on macOS (`uv run pytest`)

**Constraints:**
- macOS has no /proc — all /proc interactions happen in the VM
- Full E2E requires LM Studio running (for agent reasoning)
- The VM has 4 CPUs and 8GB RAM

## Validation Concurrency

**Terminal/VM surface:** Max 1 concurrent validator. The VM is a single shared resource with 4 CPUs and 8GB RAM. Multiple validators starting/stopping the daemon concurrently would cause conflicts.

**Go/Python test surface:** Max 2 concurrent validators. These run on the macOS host (48GB/12 CPUs) and are lightweight, but both may need `go mod tidy` / `uv sync` which can conflict.
