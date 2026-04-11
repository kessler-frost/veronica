# User Testing

Testing surface, tools, and resource cost classification.

## Validation Surface

**Primary surface:** Terminal/CLI in the Lima VM.

The notify feature writes to `/proc/<pid>/fd/1` inside the Lima VM. Validation requires:
1. Starting the Agentfield control plane on the host (port 8090)
2. Building and deploying the daemon to the VM (`uv run veronica build`)
3. Starting the daemon (`limactl shell veronica -- sudo systemctl start veronica`)
4. Calling `veronicad.notify` via the Agentfield API or a test agent
5. Verifying output in a VM shell session

**Testing tools:**
- `limactl shell veronica -- <command>` for direct VM access
- `curl` for Agentfield API calls
- Go tests on macOS (unit tests with mocked /proc)
- Python tests on macOS (`uv run pytest`)

**Constraints:**
- macOS has no /proc — all /proc interactions happen in the VM
- Full E2E requires a working LLM endpoint (LM Studio at localhost:1234 OR OpenRouter)
- For OpenRouter: set env vars `VERONICA_LM_STUDIO_URL=https://openrouter.ai/api/v1`, `VERONICA_LM_STUDIO_MODEL=gpt-5.4-mini`, `VERONICA_LM_API_KEY=$OPENROUTER_API_KEY`
- The VM has 4 CPUs and 8GB RAM

## Validation Concurrency

**Terminal/VM surface:** Max 1 concurrent validator. The VM is a single shared resource with 4 CPUs and 8GB RAM. Multiple validators starting/stopping the daemon concurrently would cause conflicts.

**Go/Python test surface:** Max 2 concurrent validators. These run on the macOS host (48GB/12 CPUs) and are lightweight, but both may need `go mod tidy` / `uv sync` which can conflict.

## Setup Notes (notify-core)

- Agentfield health endpoint for this version is `http://localhost:8090/api/v1/nodes` (not `/api/nodes`).
- The VM service unit is `veronica` (not `veronicad`).
- Reliable startup sequence:
  1. `af server --port 8090 --open=false`
  2. `uv run veronica build`
  3. `limactl shell veronica -- sudo systemctl start veronica`
- `uv run veronica start` can fail in this repository state with `TypeError: write() argument must be str, not bytes`; for validation flows, use a temporary Agentfield node directly instead of CLI orchestration when this occurs.
- Some Agentfield deployments here do not expose `/api/call`; use node metadata from `/api/v1/nodes` and call reasoner endpoints directly (for example `http://localhost:8001/reasoners/<name>`).

## Flow Validator Guidance: host-unit-tests

- Surface: macOS host shell only.
- Allowed resources: repository working tree and local test runners.
- Off-limits: start/stop VM services, kill shared background services.
- Run only host-side tests/code inspection (Go unit tests, Python unit tests, static source checks).
- Use absolute paths and avoid mutating mission files directly.

## Flow Validator Guidance: terminal-vm-e2e

- Surface: Lima VM + local Agentfield API on port 8090.
- Allowed resources: `limactl shell veronica -- ...`, `curl http://localhost:8090/...`, daemon journal logs.
- Must not change ports or edit VM config.
- Keep to one validator on this surface (shared VM + shared control plane).
- Do not kill global host processes except those started by this validation flow.
