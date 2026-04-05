# SUPERSEDED — See `2026-04-05-single-agent-design.md`

# Veronica NATS Agent Architecture

**Date:** 2026-04-04
**Status:** Superseded by single-agent architecture
**Supersedes:** `2026-04-04-two-step-model-design.md` (WebSocket + buntdb approach)

## Overview

Veronica is an eBPF intelligence layer. A Go daemon in a Lima VM captures kernel events via eBPF and exposes all six eBPF powers (observe, enforce, transform, schedule, measure, iterate) as tools. Python agents on the macOS host connect via NATS, subscribe to event types, and use LLM reasoning to decide when and how to act.

Agents are created from natural language via the CLI (`veronica add "scaffold projects on directory creation"`). An LLM translates the intent into event subscriptions and a context append for the system prompt. Agents are persistent — they run until explicitly stopped.

All state lives in NATS JetStream KV. No buntdb. No WebSocket. No custom protocol.

## Architecture

```
Go Daemon (Lima VM, root):
├─ Embedded NATS server + JetStream
│   ├─ Stream: events (subjects: events.*, 5min TTL)
│   ├─ KV: agents (persistent, agent configs)
│   ├─ KV: tasks (1hr TTL, in-flight task tracking)
│   ├─ KV: policies (persistent, enforcement rules)
│   └─ KV: logs (1hr TTL, agent activity)
├─ eBPF Manager (all program types, holds map/program FDs)
│   ├─ Tracepoints/kprobes (observe)
│   ├─ LSM programs (enforce)
│   ├─ XDP/TC programs (transform + enforce)
│   ├─ sched_ext programs (schedule)
│   └─ Perf event programs (measure)
├─ Classifier (moved to internal/classifier/, filters noise)
├─ Dangerous command filter (carried forward from current isDangerous())
└─ Tool responders (NATS request/reply on tools.>)
    ├─ tools.exec — run shell command in VM (with dangerous command filtering)
    ├─ tools.enforce — LSM/XDP deny/allow
    ├─ tools.transform — TC/XDP packet rewrite/redirect
    ├─ tools.schedule — sched_ext priority
    ├─ tools.measure — perf counters
    ├─ tools.map.read / write / delete — raw eBPF map CRUD
    └─ tools.program.list / load / detach — manage eBPF programs

Python Host (macOS, user):
├─ veronica CLI (typer)
│   ├─ start / stop / status
│   ├─ add / list / stop <name> / remove <name>
│   ├─ build / setup / logs
│   └─ vm start / stop / ssh
├─ Agent runner (watches "agents" KV, spawns/stops asyncio tasks)
├─ Agent creator (LLM call: natural language → subscriptions + context)
└─ BaseAgent (NATS client, LLM loop, tool calling)
```

## Why NATS (Not WebSocket + buntdb)

- **Pub/sub built in** — no custom subscription routing code
- **Request/reply built in** — no custom tool call/result correlation
- **JetStream persistence** — replaces buntdb for event storage and KV state
- **Embeddable** — single Go binary, ~22MB overhead, no external process
- **Python client** — nats-py is fully async, supports JetStream and KV
- **Standard protocol** — no custom JSON protocol to maintain

## Why Not SSH for Agent Execution

The daemon holds live eBPF map and program file descriptors via cilium/ebpf Go API. SSH cannot reach these in-memory objects. The daemon IS the eBPF runtime — it translates high-level tool calls into kernel operations. Additionally, the architecture assumes daemon and agents may run on the same machine in the future, making SSH unnecessary.

## Event Flow

```
Kernel event (sched_process_exec, tcp_v4_connect, etc.)
    ↓
eBPF program captures → ring buffer
    ↓
eBPF Manager reads, parses into structured event
    ↓
Classifier: silent → drop, otherwise publish
    ↓
Publish to NATS: events.process_exec (etc.)
JetStream persists (5min TTL)
    ↓
Subscribed agent gets notification
    ↓
Agent pulls recent events from JetStream stream
Agent reads "tasks" KV for in-flight work
Agent runs LLM loop:
    ├─ LLM reasons about events + in-flight context
    ├─ Calls tools via NATS request/reply
    ├─ Reads results, continues reasoning
    └─ Done or no-op
    ↓
Agent writes to "tasks" KV (claim/complete)
```

## Agent Lifecycle

### Creating an agent

```
$ veronica agent add "scaffold projects automatically based on directory creation"

CLI → LLM: "What event types match this intent? What context to append?"
LLM → {name: "project-scaffolder", events: ["process_exec"], context: "Focus on mkdir, git clone..."}
CLI → writes to NATS KV: agents.project-scaffolder = {events, context, status: "active"}
Agent runner → sees new config → spawns asyncio task
Agent → subscribes to events.process_exec via NATS
```

### Stopping/removing an agent

```
$ veronica agent stop project-scaffolder
CLI → updates NATS KV: agents.project-scaffolder.status = "stopped"
Agent runner → sees change → cancels asyncio task

$ veronica agent rm project-scaffolder
CLI → deletes agents.project-scaffolder from KV
Agent runner → sees deletion → cancels asyncio task
```

### Agent runner

A single long-lived Python process on the host. Watches the "agents" KV bucket. Keeps agents in sync: spawns new ones, stops removed/stopped ones. This is what `veronica start` launches. All agents run as asyncio tasks in one event loop.

## System Prompt

Shared base prompt for all agents (hardcoded):

```
You are Veronica, an eBPF intelligence layer embedded in a Linux OS.
You observe kernel events and can enforce policies, transform traffic,
schedule processes, and measure performance — all at kernel speed via eBPF.

You receive notifications when events matching your subscriptions occur.
Pull recent events to understand what's happening. Check in-flight tasks
to avoid duplicate work. Act decisively when action is needed.

Available tools:
- exec: run a shell command in the VM
- enforce: block/allow via LSM or XDP (file access, network, syscalls)
- transform: rewrite packets, redirect traffic via TC/XDP
- schedule: set CPU scheduling priority via sched_ext
- measure: read perf counters (cache misses, cycles, bandwidth)
- map.read/write/delete: raw eBPF map operations
- program.list/load/detach: manage eBPF programs
- kv.get/put/keys: read/write shared state (client-side, no daemon round-trip)

If nothing needs action, say "no action needed" and exit quickly.
```

Per-agent context appended:

```
Your specific focus: scaffold projects automatically when the user creates
a new directory. Look for mkdir, git clone, npm init, uv init patterns.
When you see one, check the directory, determine the project type, and
set it up (uv init for Python, npm init for JS, go mod init for Go, etc.)
```

## NATS Subject Schema

```
events.process_exec       — process started
events.process_exit       — process exited
events.net_connect        — TCP connection initiated
events.file_open          — file opened

tools.exec                — run shell command in VM
tools.enforce             — LSM/XDP deny/allow
tools.transform           — TC/XDP packet rewrite/redirect
tools.schedule            — sched_ext priority
tools.measure             — perf counters
tools.map.read            — raw eBPF map read
tools.map.write           — raw eBPF map write
tools.map.delete          — raw eBPF map delete
tools.program.list        — list loaded eBPF programs
tools.program.load        — load + attach program
tools.program.detach      — detach + unload program
```

KV tools (kv.get, kv.put, kv.keys) are **client-side** — the agent calls nats-py KV API directly, no daemon round-trip. They are still registered as LLM tools so the LLM can use them, but the agent code handles them locally.

## Lima Port Forwarding

NATS port 4222 must be exposed to the host. Add to `lima/veronica.yaml`:

```yaml
portForwards:
  - guestPort: 4222
    hostPort: 4222
```

From host: `nats://localhost:4222`. From inside VM: in-process connection (no network).

## NATS KV Schema

### agents bucket (no TTL)

```json
agents.project-scaffolder = {
    "events": ["process_exec"],
    "context": "Focus on mkdir, git clone, npm init...",
    "status": "active",
    "created": "2026-04-04T12:00:00Z"
}
```

### tasks bucket (1hr TTL)

```json
tasks.scaffold-myapp = {
    "agent": "project-scaffolder",
    "description": "scaffolding /home/user/my-fastapi-app",
    "status": "in_progress",
    "started": "2026-04-04T12:00:00Z"
}
```

### policies bucket (no TTL)

```json
policies.lsm.file._etc_shadow = {
    "action": "deny",
    "reason": "sensitive file",
    "set_by": "network-guardian"
}
policies.xdp.ip.10_0_0_5 = {
    "action": "drop",
    "reason": "port scanner",
    "set_by": "network-guardian",
    "original_target": "10.0.0.5"
}
```

### logs bucket (1hr TTL)

```json
logs.project-scaffolder.1712250000 = {
    "action": "exec: uv init",
    "result": "ok",
    "task": "scaffold-myapp"
}
```

## CLI Commands

```
veronica start              — start VM + build daemon + start daemon + start agent runner (idempotent)
veronica stop               — stop agent runner + stop daemon
veronica status             — show VM, daemon, agents, active tasks

veronica agent add "..."    — create agent from natural language
veronica agent list         — list all agents with status and description
veronica agent stop <name>  — stop a specific agent
veronica agent rm <name>    — stop + delete agent config

veronica build              — build daemon in VM, restart service
veronica setup              — full eBPF compile + daemon build + service install
veronica logs               — stream daemon logs

veronica vm start           — start Lima VM
veronica vm stop            — stop Lima VM
veronica vm ssh             — interactive shell
```

`veronica start` is idempotent — safe to run if things are already running.

## Concurrency Model

- Agent runner: single asyncio event loop, one task per agent
- LLM concurrency: limited by LM Studio parallel slots (default 4)
- Coordination: "tasks" KV — agents read before acting, write when claiming work
- Multiple agents can subscribe to the same event type
- Each agent reasons independently, tasks KV prevents duplicate work

## Dependencies

### Go (daemon)
- `github.com/cilium/ebpf` — eBPF program loading
- `github.com/nats-io/nats-server/v2` — embedded NATS server (port 4222, exposed to host via Lima port forwarding)
- `github.com/nats-io/nats.go` — NATS client (in-process connection)
- `github.com/goccy/go-json` — fast JSON

### Python (host)
- `nats-py` — async NATS client with JetStream + KV
- `msgspec` — fast JSON serialization for tool payloads
- `pydantic-settings` — config
- `typer` — CLI

## What Gets Removed From Previous Implementation

- `internal/ws/` — replaced by NATS
- `internal/state/` (buntdb) — replaced by NATS KV
- `internal/coordinator/coordinator.go`, `toolkit.go`, `types.go` — no coordinator; daemon publishes events + serves tools
- `src/veronica/agents/network.py`, `filesystem.py`, `process.py` — agents created dynamically
- `src/veronica/protocol/` — NATS handles the protocol
- `websockets` Python dependency — no longer needed

## What Gets Kept / Moved

- `internal/ebpf/` — unchanged, core of the daemon
- `internal/classifier/` — moved from `internal/coordinator/classifier.go` to its own package
- `internal/tool/` — registry + schema generation, used by tool responders
- `src/veronica/cli/` — expanded with add/list/stop/remove commands
- `src/veronica/agents/base.py` — rewritten for NATS
- `src/veronica/config.py` — updated with NATS URL
