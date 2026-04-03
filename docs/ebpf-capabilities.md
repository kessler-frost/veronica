# eBPF: Full Capabilities Reference

eBPF gives you four powers over the Linux kernel.

## Power 1: See Everything (Observation)

Attach probes to almost any function in the kernel. When that function runs, your code fires.

| Hook point | What you see | Example |
|---|---|---|
| **kprobes** | Any kernel function call | `do_sys_openat2` — see every file open with full path, pid, uid |
| **tracepoints** | Stable kernel events | `sched:sched_process_exec` — every new process started |
| **uprobe** | Any userspace function | Hook `SSL_write` in nginx — see plaintext before encryption |
| **perf events** | CPU, cache, branch events | Profile what's hot in the CPU, per-process |
| **cgroup hooks** | Per-cgroup resource events | Memory pressure, OOM events, device access |

Zero overhead on the observed programs. No modification needed. The probe fires, reads data, writes to a ring buffer, and the observed program never knows.

## Power 2: Block/Allow Things (Enforcement)

eBPF can intercept and deny operations before they happen.

| Hook | What you can block | Example |
|---|---|---|
| **LSM BPF** | Any security-relevant operation | Block pid 1234 from reading `/etc/shadow` |
| **XDP** | Network packets at NIC level | Drop packets from malicious IP before they hit the network stack |
| **TC (traffic control)** | Outbound/inbound traffic | Rate-limit a process's bandwidth |
| **seccomp BPF** | Specific syscalls per process | Deny `ptrace` for all non-debugger processes |
| **sched_ext** | CPU scheduling decisions | Deprioritize batch jobs when interactive load is high |

Policies can be updated live by writing to eBPF maps from userspace. No restart, no reload, instant effect.

## Power 3: Modify Behavior (Transformation)

eBPF can rewrite data as it passes through the kernel.

| Capability | Example |
|---|---|
| Packet rewriting (XDP/TC) | Rewrite destination IP to load-balance traffic |
| Socket redirection | Redirect a connection from port 80 to port 8080 transparently |
| DNS interception | Rewrite DNS responses to point to local services |
| Transparent proxy | Redirect all outbound HTTP through a local proxy — process doesn't know |

## Power 4: Measure and Account (Metrics)

eBPF can aggregate data in-kernel without sending every event to userspace.

| Capability | Example |
|---|---|
| Histograms | Latency distribution of disk I/O per process |
| Counters | Syscalls per second per process |
| Top-N | Which processes are doing the most network I/O right now |
| Stack traces | Why is this function being called? Who's the caller chain? |

These run in-kernel at wire speed. No sampling, no overhead, no userspace round-trip.

## eBPF Programs: Constraints

eBPF programs are small C functions loaded into the kernel. They have strict limits:

- **No unbounded loops** — verifier rejects programs that could hang the kernel
- **No dynamic memory allocation** — must use maps (pre-allocated key-value stores)
- **No sleeping/blocking** — must complete quickly
- **No calling arbitrary kernel functions** — only approved BPF helper functions
- **Stack limit: 512 bytes** — use maps for larger data
- **Cannot call userspace** — communicate via ring buffers and maps only
- **Verified before loading** — the kernel's BPF verifier proves safety before running

This is why intelligence lives in userspace. eBPF is the sensor and actuator; the Go daemon is the brain.

## Communication: Kernel ↔ Userspace

### Kernel → Userspace (events)

**Ring buffers** — the primary mechanism. eBPF program writes a struct to the ring buffer, userspace reads it. High throughput, low latency.

```
eBPF probe fires
  → writes event struct to ring buffer
    → Go daemon reads via cilium/ebpf RingBuffer reader
      → event router dispatches to agent
```

### Userspace → Kernel (policy)

**eBPF maps** — shared key-value stores. Userspace writes, kernel reads.

```
Agent decides: "block pid 1234 from /etc/shadow"
  → Go daemon writes to eBPF map: key=1234, value={block, /etc/shadow}
    → next time pid 1234 calls openat()
      → LSM BPF probe checks map
        → finds block rule → returns -EPERM
```

### Map types

| Map type | Use case |
|---|---|
| `BPF_MAP_TYPE_HASH` | Key-value lookup (pid → policy) |
| `BPF_MAP_TYPE_ARRAY` | Indexed array (fast, fixed-size) |
| `BPF_MAP_TYPE_LRU_HASH` | Auto-evicting hash (bounded memory) |
| `BPF_MAP_TYPE_RINGBUF` | Kernel → userspace event stream |
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU counters (no lock contention) |
| `BPF_MAP_TYPE_LPM_TRIE` | Longest-prefix match (IP routing, CIDR rules) |

## Practical Examples for an Intelligent OS Agent

| Scenario | eBPF does | Agent does |
|---|---|---|
| Unknown process starts | tracepoint sees `execve`, sends event | Asks LLM: "is this expected?", sets cgroup limits or kills it |
| Process tries to read sensitive file | LSM hook intercepts, checks policy map | If map has no rule, blocks temporarily, agent asks LLM, updates map with permanent decision |
| Unusual outbound connection | XDP/TC hook sees new IP:port | Looks up IP, asks LLM, adds allow/block to map |
| CPU spike | perf events + sched tracepoints | Profiles what's hot, asks LLM for optimization strategy, adjusts sched_ext priorities |
| Config file changed | kprobe on `vfs_write` for watched paths | Reads new config, asks LLM to validate, reverts if bad |
| Memory pressure | cgroup OOM notification | Decides which process to sacrifice (smarter than kernel OOM killer) |
| Service deployment | watches `execve` + `bind` + `listen` | Auto-discovers new service, sets up monitoring, firewall rules, resource limits |
| SSL/TLS traffic | uprobe on `SSL_write`/`SSL_read` | Decrypts and inspects traffic for anomalies without MITM |
| Disk I/O bottleneck | kprobe on `blk_mq_submit_bio` + histograms | Identifies I/O-heavy processes, adjusts ionice or migrates workload |
| Privilege escalation | tracepoint on `setuid`/`setgid`/`capset` | Detects unexpected privilege changes, blocks or alerts |

## Go Integration: cilium/ebpf

The standard Go library for eBPF. Used by Cilium, Tetragon, Falco, and most serious eBPF projects.

```
Write eBPF programs in C
  → compile with clang to .o files (ahead of time, CO-RE/BTF)
    → load into kernel via cilium/ebpf Go API
      → attach to hooks (kprobes, tracepoints, XDP, LSM)
        → read events from ring buffers
        → read/write maps for policy
```

Single static Go binary. No runtime dependencies. No LLVM/Clang needed at runtime (unlike Python BCC).
