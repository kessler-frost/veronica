# Veronica: eBPF-Powered Embedded Intelligence Layer

## What It Is

A single Go binary that runs as root inside a Linux VM (Fedora 43, kernel 6.17). It uses eBPF to observe, enforce, transform, schedule, measure, and iterate on everything happening in the OS. LLM-powered goroutines decide what to do. All actions are serialized through a single action queue to prevent conflicts.

## System Layout

```
HOST (macOS or Linux)
  LM Studio :1234  — Qwen 3.5-35B, parallel inference (--parallel N)
  Bubble Tea v2 TUI — observes all agent activity via WebSocket
  Lima              — VM lifecycle (macOS: Virtualization.framework, Linux: QEMU)

LIMA VM (Fedora 43, Kernel 6.17)
  Veronica daemon   — single Go binary, root, does everything
```

## Daemon Architecture

The daemon is four things in one binary:

### 1. eBPF Manager

Loads pre-compiled C programs into the kernel via cilium/ebpf (CO-RE/BTF, no runtime compiler needed). Attaches to all hook types. Reads events from ring buffers. Writes policy to eBPF maps.

eBPF capabilities used:

| Capability | Hook types | What it does |
|---|---|---|
| Observe | kprobes, tracepoints, fentry/fexit, uprobes, perf_event | See any syscall, kernel function, or userspace function call |
| Enforce | LSM, seccomp, XDP | Block/allow security operations, syscalls, network packets |
| Transform | XDP, TC, sockops, sk_msg | Rewrite packets, redirect connections, DNS rewriting, transparent proxy |
| Schedule | sched_ext | Custom CPU scheduling policies per process |
| Measure | perf_event, maps | In-kernel histograms, counters, per-process metrics at wire speed |
| Iterate | iter programs | Walk all TCP connections, processes, kernel data structures |

Dozens of probes active simultaneously across all six domains. High-frequency events (hundreds/sec possible).

### 2. Coordinator

A single goroutine that owns the action queue.

Responsibilities:
- Receives classified events from the eBPF manager
- Triages and deduplicates events
- Spawns conversation goroutines per event
- Processes the action queue sequentially (all write/execute operations serialized)
- Resolves conflicts when two goroutines want contradictory things on the same resource
- Reports all activity to TUI via WebSocket

Conflict resolution: when two actions in the queue touch the same resource (pid, file, IP, cgroup), the coordinator detects the conflict, queries buntdb for context on what both goroutines have been doing, sends the full context to Qwen, and executes whatever Qwen decides.

### 3. Conversation Goroutines

Spawned per event/task. Each goroutine gets:

```go
type AgentToolkit struct {
    ReadFile      func(path string) (string, error)
    ReadProc      func(pid int) (ProcessInfo, error)
    ListProcesses func() ([]Process, error)
    InspectConns  func() ([]Connection, error)
    ReadMap       func(name string, key []byte) ([]byte, error)
    ReadSysctl    func(key string) (string, error)
    ShellRead     func(cmd string, args ...string) (string, error) // allowlisted: cat, ls, ps, stat, df, ip, ss, etc.
    RequestAction func(action Action) (Result, error)  // → coordinator queue
    CallLLM       func(messages []Message) (Response, error)  // → Qwen direct
}
```

Read-only tools execute locally inside the goroutine. `RequestAction` is the only write path — it sends an `Action` struct to the coordinator's channel and blocks until approved/rejected.

Each goroutine runs the tool-calling loop:
1. Build context from the event + any prior state from buntdb
2. Send messages + tool schemas to Qwen (direct HTTP to host LM Studio)
3. LLM returns tool_calls → dispatch to toolkit functions → append results
4. Loop until LLM returns final text (done) or max turns exceeded (default: 10)
5. Log outcome to buntdb, exit

Goroutines call Qwen in parallel (LM Studio parallel inference). Thinking is concurrent, acting is serial.

### 4. Shared State (buntdb)

buntdb in file mode. Single AOF persistence path.

```go
db, _ := buntdb.Open("/var/veronica/state.db")
```

Key schema:
```
agent:{domain}-{8char-uuid}:meta     → JSON: task, status, started_at
agent:{domain}-{8char-uuid}:log:{ts} → JSON: entry (action, result, message)
policy:{resource-type}:{resource-id}  → JSON: current policy
event:{timestamp}:{type}              → JSON: raw eBPF event (recent, TTL'd)
```

Used for:
- Agent activity log (each goroutine appends to its own key prefix)
- Coordinator reads context for conflict resolution
- LLM gets context via structured db queries, not file reads
- Survives daemon restarts (AOF replayed on startup)
- TUI streams updates via chan fanout from db writes

Writes go through a channel to serialize appends. Reads are concurrent (buntdb RWMutex).

## Agent SDK

Custom, built into the daemon. Not a separate library.

### Tool System (~80 LOC)

Tool registration with Go generics:

```go
type Tool[TArgs any] struct {
    Name        string
    Description string
    Execute     func(ctx context.Context, args TArgs) (any, error)
}
```

JSON schema generated from Go struct tags via reflect at registration time. No external schema library — struct tags + reflect is sufficient for OpenAI-compatible function calling format.

### Tool-Calling Loop (~100 LOC)

```
send (system prompt + history + tool schemas) → Qwen
  → LLM returns tool_calls
    → dispatch by name, unmarshal args, call function
    → append result to history
  → loop until final text or max turns
```

### LLM Client (~70 LOC)

Thin wrapper over `net/http`. Speaks OpenAI-compatible chat completions API to LM Studio at `http://{host-ip}:1234/v1/chat/completions`. Sends tool definitions, receives tool_calls. No external OpenAI client library.

Total agent SDK: ~250-300 LOC, zero external dependencies beyond net/http.

## eBPF Programs

Written in C. Compiled ahead of time with clang (CO-RE, BTF-enabled). Loaded at daemon startup.

Categories:

| Program | Hook | Purpose |
|---|---|---|
| syscall_monitor | tracepoints (sys_enter/sys_exit) | Observe all syscall activity |
| process_exec | tracepoint (sched_process_exec) | Detect new process starts |
| process_exit | tracepoint (sched_process_exit) | Detect process exits |
| file_open | kprobe (do_sys_openat2) | Watch file access patterns |
| file_write | kprobe (vfs_write) | Watch file modifications |
| net_connect | kprobe (tcp_v4_connect, tcp_v6_connect) | Track outbound connections |
| net_accept | kprobe (inet_csk_accept) | Track inbound connections |
| xdp_filter | XDP | Packet inspection/drop/rewrite at NIC |
| tc_shape | TC | Outbound traffic shaping and rewriting |
| lsm_file | LSM (file_open, file_permission) | File access enforcement |
| lsm_exec | LSM (bprm_check_security) | Execution enforcement |
| lsm_net | LSM (socket_connect, socket_bind) | Network enforcement |
| sched_policy | sched_ext | Custom CPU scheduling |
| uprobe_ssl | uprobe (SSL_write, SSL_read) | TLS traffic inspection |
| perf_profile | perf_event | CPU profiling, cache metrics |

Each program writes events to a ring buffer and/or checks eBPF maps for existing policy. Maps are shared between programs — a policy set by the LSM enforcer is readable by the syscall monitor.

## Event Flow

```
kernel event fires
     │
     ▼
eBPF probe captures → checks map for existing policy
     │                       │
     │ (no policy)           │ (policy exists)
     ▼                       ▼
ring buffer → daemon     enforce immediately
     │
     ▼
coordinator triages, spawns goroutine
     │
     ▼
goroutine calls Qwen (parallel) → tool calls → read-only local
     │
     ▼
goroutine sends action request → coordinator queue (serial)
     │
     ▼
coordinator checks conflicts → execute → update eBPF map
     │
     ▼
next time: kernel enforces directly from map (no daemon round-trip)
```

## TUI Observer

Bubble Tea v2 application running on the Mac host. Connects to the daemon via WebSocket.

Shows:
- Active goroutines (agent ID, task, status, duration)
- Recent actions (approved, rejected, conflicts)
- eBPF event rate per category
- Resource overview (from periodic eBPF measurements)

The daemon pushes updates via WebSocket. The TUI is read-only — it observes, never controls.

## External Dependencies

Go modules:
- `github.com/cilium/ebpf` — eBPF program loading, map access, ring buffer reading
- `github.com/tidwall/buntdb` — shared state persistence
- `github.com/charmbracelet/bubbletea/v2` — TUI (separate binary on host)
- `github.com/charmbracelet/lipgloss` — TUI styling
- `github.com/gorilla/websocket` — daemon → TUI communication (or stdlib nhooyr.io/websocket)

No OpenAI client library. No agent framework. No JSON schema library. net/http + reflect + struct tags.

## Build

- Daemon: `go build` → single static binary, deployed into Lima VM
- eBPF programs: `clang -target bpf -O2` → .o files, embedded in Go binary via `go:embed`
- TUI: `go build` → separate binary, runs on Mac host
- VM image: Fedora 43 cloud image via Lima (`limactl create`), daemon binary deployed via `limactl shell` or SSH

## What Is NOT In Scope

- CLI tool (daemon is autonomous, TUI is the observer)
- Web dashboard (TUI only)
- Multi-VM coordination (single VM for now)
- Rules cache / offline mode (LLM is always available)
- Python anything (pure Go)
- Custom kernel (stock Fedora 43 kernel 6.17)
