# Veronica + OpenCode Subagent Architecture

**Date:** 2026-04-05
**Status:** Approved
**Supersedes:** Single-agent architecture (`2026-04-05-single-agent-design.md`)

## Problem

Both multi-agent and single-agent architectures failed in testing:

- **Multi-agent (N independent agents):** Agent collision — multiple agents act on the same event. LLM-generated filters are unreliable across all tested models.
- **Single-agent (one agent, all behaviors):** 2/8 tests passed. Agent gets distracted by noise, can't handle multiple behaviors simultaneously, comm filter gaps from LLM generation.

The root cause: we're asking a single LLM loop to handle parallel concerns. The framework (Agno) doesn't support subagent spawning or parallel execution.

## Solution

Replace Agno with OpenCode as the LLM harness. One OpenCode session with a main agent that spawns subagents per behavior. Each subagent runs independently with its own tools, subscriptions, and comm filters — decided by the main agent, not by our code.

## Architecture

```
Lima VM:
  Go daemon (veronicad)
    - eBPF probes → event channel → classifier → NATS publish
    - NATS server + JetStream
    - Tool responders (exec, enforce, transform, schedule, measure, map ops)

macOS Host:
  Python host service (veronica start)
    - FastMCP server wrapping NATS tools → OpenCode connects to this
    - NATS event watcher → routes events to appropriate subagent sessions
    - Thin OpenCode REST client
    - CLI (Typer)

  OpenCode (headless server)
    - Main agent session — spawns/kills subagents, writes agent configs
    - Subagent per behavior — each with own tools, subscriptions, system prompt
    - Calls tools via MCP → FastMCP → NATS → Go daemon
```

## Event Flow

1. eBPF probe fires in VM kernel
2. Go daemon publishes to NATS (`events.process_exec`, etc.)
3. Python host service receives event via NATS subscription
4. Host service checks which subagent(s) match (event type + comm filter)
5. Sends event as a message to that subagent's OpenCode session
6. Subagent's LLM decides what to do, calls MCP tools
7. FastMCP server translates tool call → NATS request → Go daemon executes
8. Result flows back: Go daemon → NATS reply → FastMCP → OpenCode → subagent acts on result

## Behavior Lifecycle

### `veronica add "scaffold projects based on directory creation"`

1. Save behavior text to `~/.veronica/behaviors.json`
2. Send message to main OpenCode session: "Create and spawn a new subagent for this behavior: scaffold projects based on directory creation"
3. Main agent:
   - Decides subscriptions, comm filter, tool permissions, system prompt
   - Writes `~/.veronica/.opencode/agents/<name>.md` with YAML frontmatter
   - Spawns the subagent via `@<name>`
   - Returns the subagent config (subscriptions, comm_filter) to the host service
4. Host service stores the routing config for event forwarding

### `veronica rm "scaffold"`

1. Remove from `~/.veronica/behaviors.json`
2. Send message to main session: "Kill the subagent handling: scaffold projects"
3. Main agent kills the subagent
4. Host service removes routing config
5. Delete the `.md` file from `~/.veronica/.opencode/agents/`

### `veronica list`

Read `~/.veronica/behaviors.json` and display behaviors + their subagent configs.

### `veronica start`

1. Start Lima VM if not running
2. Start Go daemon (`systemctl start veronica`)
3. Start FastMCP server (background thread, wraps NATS tools)
4. Start OpenCode server headless (with `OPENCODE_CONFIG_DIR=~/.veronica/.opencode` or equivalent)
5. Create main OpenCode session, send system prompt
6. For each stored behavior, send "add" message to replay subagent creation
7. Start NATS event watcher loop (subscribe to `events.*`, route to subagents)

### `veronica stop`

1. Stop NATS event watcher
2. Stop OpenCode server
3. Stop FastMCP server
4. Stop Go daemon (`systemctl stop veronica`)

## OpenCode Configuration

All OpenCode config lives in `~/.veronica/.opencode/`, isolated from any other OpenCode usage.

**`~/.veronica/.opencode/opencode.json`:**
```json
{
  "mcp": {
    "veronica": {
      "type": "local",
      "url": "http://localhost:<mcp-port>"
    }
  }
}
```

**`~/.veronica/.opencode/agents/main.md`** — the main orchestrator agent:
```markdown
---
description: Veronica main orchestrator
mode: primary
---

You are the Veronica orchestrator. You manage subagents that handle eBPF kernel events.

When asked to add a behavior:
1. Determine which event types the subagent needs (process_exec, process_exit, file_open, net_connect)
2. Determine which command names (comms) are relevant
3. Write an agent markdown file to .opencode/agents/<name>.md with appropriate system prompt, tools, and permissions
4. Spawn the subagent

When asked to remove a behavior, kill the corresponding subagent.
```

**Subagent files** (created by main agent, e.g. `~/.veronica/.opencode/agents/scaffolder.md`):
```markdown
---
description: Scaffold new projects based on directory creation
mode: subagent
permission:
  veronica_exec_command: allow
  veronica_enforce: deny
  "*": deny
---

You observe mkdir and git events. When a new project directory is created, scaffold it with the appropriate tooling based on the directory name.
```

## FastMCP Server

Python process exposing NATS tools as MCP tools. Each tool is a thin wrapper:

```python
@mcp.tool
async def exec_command(command: str, reason: str = "") -> str:
    """Run a shell command in the VM."""
    resp = await nc.request("tools.exec", encode({"command": command, "reason": reason}))
    return decode(resp.data).get("data", "")

@mcp.tool
async def enforce(hook: str, target: str, action: str, reason: str = "") -> str:
    """Block or allow access. hook: file_open/xdp_drop/socket_connect."""
    resp = await nc.request("tools.enforce", encode({...}))
    return decode(resp.data).get("data", "")

# ... same pattern for transform, schedule, measure
```

## Event Routing

The host service maintains a routing table (in memory, rebuilt from stored configs on restart):

```python
routing = {
    "scaffolder": {"subscriptions": ["process_exec"], "comm_filter": {"mkdir", "git", "uv", "go"}},
    "perm-guard": {"subscriptions": ["process_exec"], "comm_filter": {"chmod", "chown"}},
}
```

When an event arrives:
1. Check event type against each subagent's subscriptions
2. Check event comm against each subagent's comm_filter
3. Send to ALL matching subagents (fan-out, not exclusive)

## Storage

`~/.veronica/behaviors.json`:
```json
{
  "behaviors": [
    "scaffold projects based on directory creation",
    "revert dangerous permission changes"
  ],
  "subagents": {
    "scaffolder": {
      "session_id": "opencode-session-abc",
      "subscriptions": ["process_exec"],
      "comm_filter": ["mkdir", "git", "uv", "go"]
    },
    "perm-guard": {
      "session_id": "opencode-session-def",
      "subscriptions": ["process_exec"],
      "comm_filter": ["chmod", "chown"]
    }
  }
}
```

`~/.veronica/.opencode/` — OpenCode config dir (agents, opencode.json, etc.)

## What Gets Deleted

- `src/veronica/agents/agent.py` (VeronicaAgent)
- `agno` dependency
- `openai` dependency
- All Agno-related imports and code
- NATS KV `agents` bucket usage for config
- `comm_filter` logic in Python (moves to OpenCode main agent's decisions)
- `SUBSCRIPTION_PROMPT` and `_resolve_subscriptions` in CLI

## What Stays

- Go daemon — completely unchanged
- NATS event pub/sub and tool request/reply
- CLI framework (Typer)
- `veronica vm/*`, `setup`, `build`, `run`, `logs`, `status` commands
- Lima VM management

## What's New

- `fastmcp` dependency (Python MCP server)
- `nats-py` stays (NATS client for event watching + MCP tool wrappers)
- Custom OpenCode REST client (~100 lines Python)
- `~/.veronica/` directory structure
- OpenCode as a runtime dependency (installed globally via `bun install -g opencode`)

## Framework Abstraction

The interface between Veronica and the LLM framework is:
1. Create a session
2. Send a message to a session
3. Get a response from a session

Today this is OpenCode's REST API. Tomorrow it could be any framework that supports sessions + subagents. The Python host service isolates this behind a client class.
