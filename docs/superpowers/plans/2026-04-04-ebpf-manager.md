# eBPF Manager + Programs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the eBPF manager that loads C programs into the kernel, reads events from ring buffers, writes policy to maps, and integrates with the coordinator. Start with 3 core probes (process_exec, file_open, net_connect) covering observe capability.

**Architecture:** eBPF C programs compiled with clang (CO-RE/BTF), Go bindings generated with bpf2go, manager goroutine reads ring buffers and feeds events to the coordinator. Lima VM with Fedora 43 (kernel 6.17) for testing.

**Tech Stack:** Go, C (eBPF), `github.com/cilium/ebpf`, clang, Lima, Fedora 43

---

## File Structure

```
internal/
  ebpf/
    manager.go           — loads programs, attaches hooks, reads ring buffers, writes maps
    manager_test.go      — tests (must run on Linux with root)
    event.go             — event types shared between C and Go
    bpf/                 — generated Go bindings (bpf2go output)
      gen.go             — //go:generate directive
    programs/
      process_exec.c     — tracepoint:sched_process_exec
      file_open.c        — kprobe:do_sys_openat2
      net_connect.c      — kprobe:tcp_v4_connect
      common.h           — shared structs, maps, ring buffer helpers

lima/
  veronica.yaml          — Lima VM config (Fedora 43, eBPF toolchain)
```

---

### Task 1: Lima VM Setup

**Files:**
- Create: `lima/veronica.yaml`

- [ ] **Step 1: Create Lima config**

```yaml
# Lima VM for Veronica eBPF development
# Usage: limactl create --name=veronica lima/veronica.yaml
#        limactl start veronica
#        limactl shell veronica

images:
  - location: "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/aarch64/images/Fedora-Cloud-Base-AArch64-43-1.1.qcow2"
    arch: "aarch64"

cpus: 4
memory: "8GiB"
disk: "30GiB"

vmType: "vz"
mountType: "virtiofs"

mounts:
  - location: "~/dev/veronica"
    writable: true

provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      dnf install -y \
        clang llvm \
        bpftool \
        libbpf-devel \
        kernel-devel \
        kernel-headers \
        golang \
        git \
        make
```

- [ ] **Step 2: Create and start the VM**

```bash
limactl create --name=veronica lima/veronica.yaml
limactl start veronica
```

- [ ] **Step 3: Verify eBPF support**

```bash
limactl shell veronica -- uname -r
limactl shell veronica -- bpftool version
limactl shell veronica -- clang --version
```

Expected: kernel 6.17.x, bpftool and clang available.

- [ ] **Step 4: Commit**

```bash
git add lima/veronica.yaml
git commit -m "infra: Lima VM config for Fedora 43 eBPF development"
```

---

### Task 2: eBPF Common Header + Process Exec Probe

**Files:**
- Create: `internal/ebpf/programs/common.h`
- Create: `internal/ebpf/programs/process_exec.c`

- [ ] **Step 1: Write common header**

```c
// common.h — shared between all eBPF programs
#ifndef __VERONICA_COMMON_H
#define __VERONICA_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_FILENAME_LEN 256

// Event types
#define EVENT_PROCESS_EXEC  1
#define EVENT_FILE_OPEN     2
#define EVENT_NET_CONNECT   3

// Base event header — all events start with this
struct event_header {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
};

// Process exec event
struct process_exec_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
};

// File open event
struct file_open_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
    int flags;
};

// Network connect event
struct net_connect_event {
    struct event_header hdr;
    __u32 daddr;
    __u16 dport;
    __u16 family;
};

#endif
```

- [ ] **Step 2: Write process_exec probe**

```c
// process_exec.c — tracepoint:sched_process_exec
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_PROCESS_EXEC;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 3: Generate vmlinux.h in the VM**

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica/internal/ebpf/programs && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
```

- [ ] **Step 4: Compile in the VM**

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica/internal/ebpf/programs && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c process_exec.c -o process_exec.o"
```

Expected: `process_exec.o` created without errors.

- [ ] **Step 5: Commit**

```bash
git add internal/ebpf/programs/common.h internal/ebpf/programs/process_exec.c
git commit -m "feat(ebpf): common header + process_exec tracepoint probe"
```

---

### Task 3: File Open + Net Connect Probes

**Files:**
- Create: `internal/ebpf/programs/file_open.c`
- Create: `internal/ebpf/programs/net_connect.c`

- [ ] **Step 1: Write file_open probe**

```c
// file_open.c — kprobe:do_sys_openat2
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int trace_file_open(struct pt_regs *ctx)
{
    struct file_open_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_FILE_OPEN;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    // Second arg (index 1) is the filename pointer
    const char *fname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    // Third arg (index 2) is the open_how struct, first field is flags
    struct open_how *how = (struct open_how *)PT_REGS_PARM3(ctx);
    bpf_probe_read_kernel(&e->flags, sizeof(e->flags), &how->flags);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 2: Write net_connect probe**

```c
// net_connect.c — kprobe:tcp_v4_connect
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int trace_connect(struct pt_regs *ctx)
{
    struct net_connect_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_NET_CONNECT;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
    e->dport = __builtin_bswap16(e->dport);
    BPF_CORE_READ_INTO(&e->family, sk, __sk_common.skc_family);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 3: Compile both in the VM**

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica/internal/ebpf/programs && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c file_open.c -o file_open.o && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c net_connect.c -o net_connect.o"
```

- [ ] **Step 4: Commit**

```bash
git add internal/ebpf/programs/file_open.c internal/ebpf/programs/net_connect.c
git commit -m "feat(ebpf): file_open kprobe + net_connect kprobe probes"
```

---

### Task 4: Go Event Types + bpf2go Generation

**Files:**
- Create: `internal/ebpf/event.go`
- Create: `internal/ebpf/bpf/gen.go`

- [ ] **Step 1: Write Go event types matching C structs**

```go
package ebpf

// EventType identifies the kind of eBPF event.
type EventType uint32

const (
	EventProcessExec EventType = 1
	EventFileOpen    EventType = 2
	EventNetConnect  EventType = 3
)

// EventHeader is the common header for all eBPF events.
type EventHeader struct {
	Type      EventType
	PID       uint32
	UID       uint32
	Timestamp uint64
	Comm      [64]byte
}

// ProcessExecEvent is emitted when a new process starts.
type ProcessExecEvent struct {
	Header   EventHeader
	Filename [256]byte
}

// FileOpenEvent is emitted when a file is opened.
type FileOpenEvent struct {
	Header   EventHeader
	Filename [256]byte
	Flags    int32
	_        [4]byte // padding
}

// NetConnectEvent is emitted when a TCP connection is initiated.
type NetConnectEvent struct {
	Header EventHeader
	DAddr  uint32
	DPort  uint16
	Family uint16
}

// CommString returns the command name as a trimmed string.
func (h *EventHeader) CommString() string {
	for i, b := range h.Comm {
		if b == 0 {
			return string(h.Comm[:i])
		}
	}
	return string(h.Comm[:])
}

// FilenameString returns the filename as a trimmed string.
func FilenameString(b [256]byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b[:])
}
```

- [ ] **Step 2: Write bpf2go generation script**

```go
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 ProcessExec ../programs/process_exec.c -- -I../programs -D__TARGET_ARCH_arm64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 FileOpen ../programs/file_open.c -- -I../programs -D__TARGET_ARCH_arm64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 NetConnect ../programs/net_connect.c -- -I../programs -D__TARGET_ARCH_arm64
```

- [ ] **Step 3: Add cilium/ebpf dependency**

```bash
go get github.com/cilium/ebpf
go mod tidy
```

- [ ] **Step 4: Run bpf2go in the VM** (requires Linux + clang)

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica && go generate ./internal/ebpf/bpf/"
```

- [ ] **Step 5: Verify generated files exist**

```bash
ls internal/ebpf/bpf/*_arm64.*
```

Expected: `processexec_arm64.go`, `processexec_arm64.o`, etc.

- [ ] **Step 6: Commit**

```bash
git add internal/ebpf/event.go internal/ebpf/bpf/ go.mod go.sum
git commit -m "feat(ebpf): Go event types + bpf2go generated bindings"
```

---

### Task 5: eBPF Manager

**Files:**
- Create: `internal/ebpf/manager.go`

- [ ] **Step 1: Write the manager**

```go
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/ebpf/bpf"
)

// Manager loads eBPF programs, attaches hooks, and reads events.
type Manager struct {
	links  []link.Link
	reader *ringbuf.Reader
	events chan<- coordinator.Event
}

// New creates an eBPF manager that sends events to the given channel.
func New(events chan<- coordinator.Event) *Manager {
	return &Manager{events: events}
}

// LoadAndAttach loads all eBPF programs and attaches them to hooks.
func (m *Manager) LoadAndAttach() error {
	// Process exec
	procObjs := bpf.ProcessExecObjects{}
	if err := bpf.LoadProcessExecObjects(&procObjs, nil); err != nil {
		return fmt.Errorf("load process_exec: %w", err)
	}

	procLink, err := link.AttachTracepoint(link.TracepointOptions{
		Group:   "sched",
		Name:    "sched_process_exec",
		Program: procObjs.TraceExec,
	})
	if err != nil {
		return fmt.Errorf("attach process_exec: %w", err)
	}
	m.links = append(m.links, procLink)

	// Create ring buffer reader from the process_exec events map
	reader, err := ringbuf.NewReader(procObjs.Events)
	if err != nil {
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	m.reader = reader

	// File open
	fileObjs := bpf.FileOpenObjects{}
	if err := bpf.LoadFileOpenObjects(&fileObjs, nil); err != nil {
		log.Printf("WARN: failed to load file_open (kprobe may not be available): %v", err)
	} else {
		fileLink, err := link.AttachKprobe(link.KprobeOptions{
			Symbol:  "do_sys_openat2",
			Program: fileObjs.TraceFileOpen,
		})
		if err != nil {
			log.Printf("WARN: failed to attach file_open: %v", err)
		} else {
			m.links = append(m.links, fileLink)
		}
	}

	// Net connect
	netObjs := bpf.NetConnectObjects{}
	if err := bpf.LoadNetConnectObjects(&netObjs, nil); err != nil {
		log.Printf("WARN: failed to load net_connect: %v", err)
	} else {
		netLink, err := link.AttachKprobe(link.KprobeOptions{
			Symbol:  "tcp_v4_connect",
			Program: netObjs.TraceConnect,
		})
		if err != nil {
			log.Printf("WARN: failed to attach net_connect: %v", err)
		} else {
			m.links = append(m.links, netLink)
		}
	}

	return nil
}

// ReadEvents reads events from the ring buffer and sends them to the coordinator.
// Blocks until context is cancelled.
func (m *Manager) ReadEvents(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}

		event := m.parseEvent(record.RawSample)
		if event != nil {
			m.events <- *event
		}
	}
}

func (m *Manager) parseEvent(data []byte) *coordinator.Event {
	if len(data) < 4 {
		return nil
	}

	eventType := EventType(binary.LittleEndian.Uint32(data[:4]))

	switch eventType {
	case EventProcessExec:
		if len(data) < int(binary.Size(ProcessExecEvent{})) {
			return nil
		}
		var e ProcessExecEvent
		readStruct(data, &e)
		return &coordinator.Event{
			Type:     "process_exec",
			Resource: fmt.Sprintf("pid:%d", e.Header.PID),
			Data:     fmt.Sprintf(`{"comm":%q,"filename":%q,"uid":%d}`, e.Header.CommString(), FilenameString(e.Filename), e.Header.UID),
		}

	case EventFileOpen:
		if len(data) < int(binary.Size(FileOpenEvent{})) {
			return nil
		}
		var e FileOpenEvent
		readStruct(data, &e)
		return &coordinator.Event{
			Type:     "file_open",
			Resource: fmt.Sprintf("file:%s", FilenameString(e.Filename)),
			Data:     fmt.Sprintf(`{"comm":%q,"pid":%d,"filename":%q,"flags":%d}`, e.Header.CommString(), e.Header.PID, FilenameString(e.Filename), e.Flags),
		}

	case EventNetConnect:
		if len(data) < int(binary.Size(NetConnectEvent{})) {
			return nil
		}
		var e NetConnectEvent
		readStruct(data, &e)
		ip := fmt.Sprintf("%d.%d.%d.%d", byte(e.DAddr), byte(e.DAddr>>8), byte(e.DAddr>>16), byte(e.DAddr>>24))
		return &coordinator.Event{
			Type:     "net_connect",
			Resource: fmt.Sprintf("ip:%s:%d", ip, e.DPort),
			Data:     fmt.Sprintf(`{"comm":%q,"pid":%d,"daddr":"%s","dport":%d}`, e.Header.CommString(), e.Header.PID, ip, e.DPort),
		}
	}

	return nil
}

func readStruct(data []byte, v any) {
	binary.Read(
		bytes.NewReader(data),
		binary.LittleEndian,
		v,
	)
}

// Close detaches all hooks and closes the ring buffer reader.
func (m *Manager) Close() error {
	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	return nil
}
```

Note: needs `"bytes"` import added.

- [ ] **Step 2: Verify it compiles in the VM**

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica && go build ./internal/ebpf/..."
```

- [ ] **Step 3: Commit**

```bash
git add internal/ebpf/manager.go
git commit -m "feat(ebpf): manager loads programs, reads ring buffer, parses events"
```

---

### Task 6: Daemon Main Entrypoint

**Files:**
- Create: `cmd/veronica/main.go`

- [ ] **Step 1: Write main.go**

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func main() {
	llmURL := envOr("VERONICA_LLM_URL", "http://host.lima.internal:1234")
	llmModel := envOr("VERONICA_LLM_MODEL", "qwen3.5-35b")
	stateDB := envOr("VERONICA_STATE_DB", "/var/veronica/state.db")

	log.Printf("veronica starting")
	log.Printf("  llm: %s (model: %s)", llmURL, llmModel)
	log.Printf("  state: %s", stateDB)

	// State store
	os.MkdirAll("/var/veronica", 0755)
	store, err := state.Open(stateDB)
	if err != nil {
		log.Fatalf("open state: %v", err)
	}
	defer store.Close()

	// LLM client
	client := llm.NewClient(llmURL, llmModel)

	// Coordinator
	coord := coordinator.New(client, store, coordinator.Config{
		SystemPrompt: systemPrompt,
		MaxTurns:     10,
		ActionExecutor: func(a coordinator.Action) (string, error) {
			log.Printf("EXECUTE: %s on %s args=%s", a.Type, a.Resource, a.Args)
			// TODO: real action executor in next plan
			return "executed (stub)", nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start coordinator
	coord.Start(ctx)

	// Log reports
	go func() {
		for r := range coord.Reports() {
			log.Printf("[%s] %s: %s", r.AgentID, r.EventType, r.Detail)
		}
	}()

	// eBPF manager
	events := make(chan coordinator.Event, 256)
	go func() {
		for e := range events {
			coord.HandleEvent(e)
		}
	}()

	ebpfMgr := vebpf.New(events)
	if err := ebpfMgr.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf load: %v", err)
	}
	defer ebpfMgr.Close()
	log.Printf("ebpf probes attached")

	// Read events (blocks)
	go func() {
		if err := ebpfMgr.ReadEvents(ctx); err != nil {
			log.Printf("ebpf read events stopped: %v", err)
		}
	}()

	log.Printf("veronica running. press ctrl+c to stop.")

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down...")
	cancel()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const systemPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux operating system.
You observe kernel events via eBPF and manage the system.
You have read-only tools (read_file, shell_read) and can request actions via request_action.
When you receive an event, analyze it and decide what action to take.
Be concise in your reasoning. Focus on system health, security, and performance.`
```

- [ ] **Step 2: Build in the VM**

```bash
limactl shell veronica -- bash -c "cd /Users/*/dev/veronica && go build -o veronica ./cmd/veronica/"
```

- [ ] **Step 3: Test run in the VM**

```bash
limactl shell veronica -- sudo /Users/*/dev/veronica/veronica
```

Expected: starts, attaches eBPF probes, logs events, ctrl+c to stop.

- [ ] **Step 4: Commit**

```bash
git add cmd/veronica/main.go
git commit -m "feat: daemon main entrypoint wiring eBPF + coordinator + state"
```

---

## Summary

After completing all 6 tasks:

| Component | What |
|---|---|
| Lima VM | Fedora 43, kernel 6.17, eBPF toolchain installed |
| 3 eBPF probes | process_exec, file_open, net_connect |
| Go event types | Matching C structs for ring buffer parsing |
| eBPF Manager | Loads programs, attaches hooks, reads ring buffer, parses events |
| Daemon main | Wires eBPF → coordinator → agents → LLM |

The daemon is runnable. Point LM Studio at the VM's host and watch Veronica observe the OS.
