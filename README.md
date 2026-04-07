# Veronica

> Convert any operating system into an agentic operating system.

This is an experiment to stress test what AI agents can actually do when given kernel-level access via eBPF. I don't know if this is useful - it's about answering the "what if?" question, especially if done right.

## Why Agentfield

We switched to Agentfield because:

1. **Native Python AND Go SDK support.** We couldn't find another framework with first-class SDKs for both languages. Our Go daemon and Python behavior agents were previously stitched together with NATS, FastMCP, and OpenCode - three protocols to connect two languages. Agentfield replaces all of that with one control plane.

2. **Bidirectional communication, no MCP.** MCP is unidirectional - models call tools, but tools can't push events back. We need the Go daemon to push eBPF events TO agents AND agents to call functions BACK on the daemon. Agentfield does this natively. No MCP, no NATS, no OpenCode. Just agents and functions talking through a control plane.

---

| User did | Veronica did |
|---|---|
| `mkdir my-fastapi-app` | Scaffolded full project - `main.py`, `requirements.txt`, tests |
| `mkdir my-go-server` | `go mod init`, created `main.go`, `Makefile` |
| `git clone flask.git` | Detected `pyproject.toml`, installed uv, ran `uv sync` |
| `chmod 777 /etc/shadow` | Reverted to `640` immediately |
| `ssh-keygen -t rsa` | Replaced with `ed25519`, fixed permissions |
| `pip install reqeusts` | Caught typosquat, killed install |
| nginx crashed | Diagnosed via logs, restarted service |
| Edited `nginx.conf` | Validated with `nginx -t`, reloaded service |
| Wrote `todo_project.md` | Read spec, scaffolded todo CLI with add/list/done commands |

## Quick Start

```bash
# Install
git clone https://github.com/kessler-frost/veronica.git
cd veronica
uv sync

# Create and setup VM (one-time)
uv run veronica vm start
uv run veronica setup

# Add behaviors
uv run veronica add "scaffold projects automatically based on directory creation"
uv run veronica add "revert dangerous permission changes on sensitive files"

# Start (blocks - Ctrl+C to stop)
uv run veronica start
```

Requires: macOS (Apple Silicon) or Linux, [uv](https://docs.astral.sh/uv/), [Lima](https://lima-vm.io/), [Agentfield](https://github.com/Agent-Field/agentfield), and [LM Studio](https://lmstudio.ai/) with a model loaded.

## Architecture

```
                    Agentfield Control Plane
                    (af server, macOS host)
                           |
              +------------+------------+
              |                         |
     Go Daemon                   Behavior Agents
     (Lima VM, root)             (macOS host, Python)
     - eBPF manager              - One per user-defined behavior
     - Exposes functions:        - Subscribes to eBPF events
       exec, enforce,            - Calls daemon functions
       transform, schedule,        via control plane
       measure, map/program ops  - LLM reasoning via
     - Pushes eBPF events          direct LM Studio API
              |
         eBPF Programs
         (kernel space)
```
