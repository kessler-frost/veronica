# Veronica Architecture

Proactive agents at the kernel level, powered by eBPF.

## Components

### Lima VM (Ubuntu Guest)

A Virtualization.framework VM on macOS (`lima/veronica.yaml`). All kernel-level work happens here. Files are synced from the host via `limactl cp`; there are no shared mounts. The guest reaches the host network through `host.lima.internal`.

### Go Daemon (`cmd/veronicad/`)

Runs as root inside the Lima VM. Owns the eBPF lifecycle:

- **eBPF Manager** (`internal/ebpf/`): Loads compiled BPF object files via cilium/ebpf, attaches tracepoints and kprobes, and reads ring buffers on concurrent goroutines. Each ring buffer record is parsed into a typed `event.Event`.
- **Classifier** (`internal/classifier/`): First gate after the kernel. Drops self-generated noise (daemon PIDs, system daemons, read-only file opens, uninteresting paths) and passes everything else. Two categories only: Silent or Pass.
- **Publisher** (`internal/af/publisher.go`): Maintains an in-memory subscriber table. For each Pass event, finds matching subscribers by event type and optional comm filter, then pushes the event via `agent.Call("<subscriber>.receive_event", ...)`.
- **Skills** (`internal/af/skills.go`): Registers 13 callable functions with Agentfield — subscribe/unsubscribe, exec, enforce, transform, schedule, measure, map CRUD, and program lifecycle. These are the daemon's API surface.

The daemon connects outbound to the Agentfield control plane at `host.lima.internal:8090`.

### Agentfield Control Plane

`af server` on the macOS host, port 8090. A routing fabric — no domain logic. It routes `Call()` invocations between any two registered agents by node ID, and supports bidirectional communication (daemon → agents and agents → daemon) without protocol bridging.

### Behavior Agents (`src/veronica/agent.py`)

Python processes on the macOS host. Each user-defined behavior becomes a separate Agentfield agent (`veronica-<id>`). An agent:

1. **Self-configures** on first boot: asks the LLM which event types and comm filters match its behavior description, persists the result.
2. **Subscribes** with the daemon via `app.call("veronicad.subscribe", ...)`.
3. **Receives events** through a `receive_event` reasoner invoked by the daemon's publisher.
4. **Reasons** using LM Studio (OpenAI-compatible API at `localhost:1234`), deciding whether to act and which daemon skill to call.
5. **Acts** via `app.call("veronicad.<skill>", ...)` — the control plane routes the call back to the daemon.

### LM Studio

Local LLM server on the macOS host (`localhost:1234`). Provides OpenAI-compatible `/v1/chat/completions`. Used for both agent self-configuration and runtime event reasoning. Accessed from the VM at `host.lima.internal:1234`.

## eBPF Programs

C sources in `internal/ebpf/programs/`, compiled with clang targeting BPF (CO-RE/BTF). Generated Go bindings in `internal/ebpf/bpf/`.

| Program | Hook | Ring Buffer |
|---------|------|-------------|
| process_exec | `sched/sched_process_exec` tracepoint | ✓ |
| process_exit | `sched/sched_process_exit` tracepoint | ✓ |
| file_open | `do_sys_openat2` kprobe | ✓ |
| net_connect | `tcp_v4_connect` kprobe | ✓ |

Planned but not yet compiled: `lsm_enforce`, `sched_enforce`, `xdp_filter`.

## Data Flow

```
kernel hook
    │
    ▼
ring buffer ──► Go daemon (parse + enrich from /proc)
                    │
                    ▼
                classifier ──► Silent → drop
                    │
                    Pass
                    │
                    ▼
                publisher ──► match subscribers by (event type, comm filter)
                    │
                    ▼
           Agentfield Call("<agent>.receive_event")
                    │
                    ▼
             Python behavior agent
                    │
                    ▼
                LLM reasoning (LM Studio)
                    │
                    ▼
              decision: {"action": "<skill>", "params": {...}}
                    │
                    ▼
           Agentfield Call("veronicad.<skill>")
                    │
                    ▼
                Go daemon skill handler
```

## Invariants

- **The daemon IS the eBPF runtime.** It holds live map and program file descriptors. There is no SSH-based remote control — skills execute in-process.
- **Classifier is daemon-side only.** It exists to prevent feedback loops (daemon's own child processes) and drop known system noise. All domain-specific filtering is agent-side.
- **Subscription-based routing.** The daemon does not broadcast. An agent must explicitly subscribe (event types + optional comm filter) before it receives anything.
- **Bidirectional over Agentfield.** The daemon pushes events to agents; agents call skills on the daemon. One protocol, no bridging layers.
- **Self-configuring agents.** A behavior agent with no prior config will ask the LLM to determine its subscriptions before participating in the event loop.

## Planned: Notify Skill

A new `notify` daemon skill that writes messages to a target process's stdout by opening `/proc/<pid>/fd/1`. This gives behavior agents a way to surface information directly in the user's terminal — closing the loop from kernel observation through LLM reasoning to user-visible output, without requiring a separate notification channel. The notify skill fits alongside the existing skill set (exec, enforce, transform, etc.) as another action a behavior agent can invoke after reasoning about an event.
