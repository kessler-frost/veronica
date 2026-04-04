# Veronica Two-Step Model: Daemon + Host Agents

**Date:** 2026-04-04
**Status:** Approved
**Supersedes:** Monolithic daemon architecture from `2026-04-03-veronica-design.md` (agent loop + LLM sections only)

## Overview

Split Veronica into two processes:

1. **Go Daemon** — runs as root in the Lima VM. eBPF event capture, classification, tool execution, action serialization. No LLM calls.
2. **Python Host Agents** — run on macOS host. Connect to daemon via WebSocket, subscribe to event types, run LLM loops using any harness (Claude Agent SDK, LM Studio, OpenCode, etc.).

The daemon becomes the **eBPF runtime and tool server**. It holds live map/program file descriptors via cilium/ebpf and exposes structured operations as tools. Host agents get typed access to kernel state — they never SSH into the VM.

## Architecture Diagram

```
┌─────────────────────────────┐     ┌──────────────────────────────┐
│  Lima VM (Fedora 43, root)  │     │  macOS Host                  │
│                             │     │                              │
│  Go Daemon                  │     │  Python (uv + typer)         │
│  ├─ eBPF Manager            │     │  ├─ veronica CLI             │
│  ├─ Classifier              │◄═══►│  ├─ Agent: network           │
│  ├─ Coordinator             │ WS  │  ├─ Agent: filesystem        │
│  ├─ WebSocket Server        │JSON │  ├─ Agent: process           │
│  ├─ Tool Server             │     │  └─ (any LLM harness)        │
│  ├─ buntdb state            │     │                              │
│  └─ Action Queue            │     └──────────────────────────────┘
└─────────────────────────────┘
```

## Why Not SSH

The daemon holds live eBPF map and program file descriptors via cilium/ebpf Go API. These are in-memory objects that cannot be reached over SSH — only bpftool (string-based, no loaded-program context). The daemon IS the eBPF runtime. Going through the daemon also means all writes are serialized through the action queue, preventing conflicts between agents.

## Communication

**Transport:** WebSocket (single connection per agent, full-duplex, multiplexed sessions)

**Wire format:** JSON everywhere
- Go: `github.com/goccy/go-json`
- Python: `msgspec.json` (same Struct definitions can flip to msgpack later if needed)

**Session model:** Each eBPF event spawns a daemon-side goroutine that creates a session. The session is routed to all agents subscribed to that event type (fan-out). Each session is an independent bidirectional tool-calling channel.

## Protocol

Five message types:

### Agent → Daemon

```json
// Register + subscribe (sent on connect)
{"type": "subscribe", "agent_id": "network-01", "events": ["net_connect", "process_exec"]}

// Tool call within a session
{"type": "tool_call", "session": "abc123", "call_id": "1", "name": "map_read", "args": {"map": "connections"}}

// Agent done with a session
{"type": "session_done", "session": "abc123"}
```

### Daemon → Agent

```json
// New event (creates a session)
{"type": "event", "session": "abc123", "event": {"type": "net_connect", "resource": "ip:10.0.0.5", "data": {...}, "timestamp": "..."}}

// Tool result
{"type": "tool_result", "session": "abc123", "call_id": "1", "result": {"ok": true, "data": {...}}}
```

### Session Lifecycle

1. Daemon classifies event as `CategoryAgent`
2. Daemon finds agents subscribed to this event type
3. For each: spawn goroutine, assign session ID, send `event` message
4. Agent sends N `tool_call` messages, daemon responds with `tool_result` for each
5. Agent sends `session_done` → goroutine cleans up
6. Timeout: if no messages for 60s, daemon closes the session

## Daemon Tools

### Existing (carried forward)
- `read_file(path)` — read any file in the VM (not host filesystem)
- `shell_read(cmd)` — run allowlisted read-only commands (ps, ss, ip, stat, df, etc.)
- `request_action(type, resource, args)` — send write action to coordinator's serial queue

### New: eBPF Map Operations
- `map_read(map, key?)` — read entry or dump entire map
- `map_write(map, key, value)` — write entry (goes through action queue)
- `map_delete(map, key)` — delete entry (goes through action queue)

### New: eBPF Program Operations
- `program_list()` — list loaded programs and their attach points
- `program_load(name)` — load and attach a program (goes through action queue)
- `program_detach(name)` — detach and unload a program (goes through action queue)

### New: State Operations
- `state_query(key_pattern)` — query buntdb by key pattern
- `state_write(key, value, ttl?)` — write to buntdb (goes through action queue)

All write operations go through the coordinator's action queue for serialization and conflict resolution.

## Repo Structure

```
veronica/
├── pyproject.toml              # uv project: CLI + agents + shared types
├── src/veronica/
│   ├── __init__.py
│   ├── config.py               # pydantic-settings, no env var overrides
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py             # typer CLI: start/stop/build/status/logs/vm
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py             # WebSocket client, session handling
│   │   ├── network.py          # subscribes to net_connect
│   │   ├── filesystem.py       # subscribes to file_open
│   │   └── process.py          # subscribes to process_exec, process_exit
│   └── protocol/
│       ├── __init__.py
│       └── messages.py         # msgspec Struct definitions for all 5 message types
├── internal/                   # Go daemon
│   ├── ebpf/                   # unchanged
│   ├── coordinator/            # modified: session proxy instead of agent loop
│   ├── tool/                   # unchanged: registry + schema, extended with new tools
│   ├── state/                  # unchanged
│   └── ws/                     # NEW: WebSocket server
├── cmd/veronicad/              # Go daemon entry point
├── go.mod
├── go.sum
└── lima/veronica.yaml
```

## Go Changes

### Deleted
- `internal/agent/` — agent loop replaced by Python agents
- `internal/llm/` — LLM calls happen on host
- `cmd/cli/` — Go CLI replaced by Python typer CLI
- `agentPrompt` / `digestPrompt` in coordinator — system prompts live in Python agents
- `VERONICA_LLM_URL`, `VERONICA_LLM_MODEL` env vars — no longer relevant to daemon

### New
- `internal/ws/` — WebSocket server using `coder/websocket` (actively maintained, gorilla is archived)
  - Listens on port 9090 (default)
  - Accepts agent connections
  - Manages subscriptions (agent → event types)
  - Routes sessions to agents
  - Multiplexes tool calls/results per session over single connection

### Modified
- `internal/coordinator/coordinator.go`:
  - `eventLoop`: instead of spawning agent goroutines with LLM loops, spawns session goroutines that proxy to host agents
  - `digestLoop`: sends batched events to subscribed agents instead of running internal LLM
  - Removes direct LLM client dependency
- `internal/coordinator/toolkit.go`:
  - Same tool registry, extended with eBPF map/program tools and state tools
  - Tools called by session goroutines on behalf of remote agents

### Unchanged
- `internal/ebpf/` — all eBPF loading, ring buffer reading, event parsing
- `internal/state/` — buntdb persistence
- `internal/tool/` — registry and schema generation
- `internal/coordinator/classifier.go` — event classification
- `internal/coordinator/types.go` — domain types
- Coordinator action queue + conflict resolution

## Python Side

### Config (`src/veronica/config.py`)
pydantic-settings with defaults, no env var overrides:

```python
from pydantic_settings import BaseSettings

class VeronicaConfig(BaseSettings):
    daemon_ws_url: str = "ws://localhost:9090"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_build_path: str = "/tmp/veronica"
    session_timeout: int = 60
```

### CLI (`src/veronica/cli/main.py`)
Typer app replacing the Go CLI:
- `veronica start` — SSH into VM, start daemon
- `veronica stop` — SSH into VM, stop daemon
- `veronica build` — SSH into VM, go build
- `veronica status` — query daemon health
- `veronica logs` — stream daemon logs
- `veronica vm ssh` — limactl shell veronica
- `veronica vm stop` — limactl stop veronica

### Base Agent (`src/veronica/agents/base.py`)
Shared WebSocket client:
- Connects to daemon, sends `subscribe` with event types
- Receives `event` messages, dispatches to `handle_event(session, event)`
- Provides `call_tool(session, name, args) → result` — sends `tool_call`, awaits matching `tool_result`
- Sends `session_done` when handler returns
- Handles concurrent sessions via asyncio tasks

### Individual Agents
Each agent:
- Declares subscribed event types
- Has its own system prompt
- Implements `handle_event` with its LLM loop
- Uses whatever LLM harness it wants (base class doesn't care)

### Protocol Types (`src/veronica/protocol/messages.py`)

```python
import msgspec

class EventData(msgspec.Struct):
    type: str
    resource: str
    data: dict
    timestamp: str

class Subscribe(msgspec.Struct):
    type: str = "subscribe"
    agent_id: str
    events: list[str]

class Event(msgspec.Struct):
    type: str = "event"
    session: str
    event: EventData

class ToolCall(msgspec.Struct):
    type: str = "tool_call"
    session: str
    call_id: str
    name: str
    args: dict

class ToolResult(msgspec.Struct):
    type: str = "tool_result"
    session: str
    call_id: str
    result: dict

class SessionDone(msgspec.Struct):
    type: str = "session_done"
    session: str
```

## Dependencies

### Go (added)
- `github.com/goccy/go-json` — fast JSON, drop-in replacement for encoding/json
- `github.com/coder/websocket` — WebSocket server (actively maintained)

### Python (new)
- `msgspec` — fast JSON encode/decode with typed structs
- `pydantic-settings` — config management
- `typer` — CLI framework
- `websockets` — WebSocket client
