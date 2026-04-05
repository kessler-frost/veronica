# SUPERSEDED — buntdb + coordinator deleted during NATS migration

# Shared State + Coordinator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the buntdb shared state layer and the coordinator that receives events, spawns conversation goroutines, serializes actions through a queue, and detects conflicts.

**Architecture:** Two new packages: `state` (buntdb wrapper with key schema) and `coordinator` (event intake, goroutine spawning, action queue, conflict detection). The coordinator uses the `agent.Run` loop from Plan 1 inside each goroutine. Read-only tools execute locally; write/execute tools go through `RequestAction` which blocks on the coordinator's action channel.

**Tech Stack:** Go 1.23+, `github.com/tidwall/buntdb`, existing `internal/agent`, `internal/llm`, `internal/tool`

---

## File Structure

```
internal/
  state/
    store.go             — buntdb wrapper: open, agent log, policy, events
    store_test.go        — tests

  coordinator/
    types.go             — Event, Action, ActionRequest, ActionResult
    toolkit.go           — AgentToolkit: read-only tools + RequestAction as agent tools
    toolkit_test.go      — tests for toolkit registration + read-only dispatch
    coordinator.go       — Coordinator struct, Start/Stop, event intake, action queue
    coordinator_test.go  — tests with mock LLM + simulated events
```

---

### Task 1: Add buntdb Dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add buntdb**

```bash
cd /Users/fimbulwinter/dev/veronica
go get github.com/tidwall/buntdb
```

- [ ] **Step 2: Tidy**

```bash
go mod tidy
```

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add buntdb

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: State Store

**Files:**
- Create: `internal/state/store.go`
- Create: `internal/state/store_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package state

import (
	"testing"
	"time"
)

func TestStore_OpenClose(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = store.Close()
	if err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestStore_AgentLog(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	agentID := "process-a1b2c3d4"

	err = store.SetAgentMeta(agentID, AgentMeta{
		Task:   "handle pid 4521 high CPU",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("set meta: %v", err)
	}

	meta, err := store.GetAgentMeta(agentID)
	if err != nil {
		t.Fatalf("get meta: %v", err)
	}
	if meta.Task != "handle pid 4521 high CPU" {
		t.Fatalf("expected task, got %q", meta.Task)
	}
	if meta.Status != "active" {
		t.Fatalf("expected active, got %q", meta.Status)
	}

	err = store.AppendAgentLog(agentID, LogEntry{
		Action:  "read_proc",
		Result:  "nginx worker, 10GB RSS",
		Message: "investigating high CPU process",
	})
	if err != nil {
		t.Fatalf("append log: %v", err)
	}

	entries, err := store.GetAgentLog(agentID)
	if err != nil {
		t.Fatalf("get log: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "read_proc" {
		t.Fatalf("expected read_proc, got %q", entries[0].Action)
	}
}

func TestStore_Policy(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	err = store.SetPolicy("pid", "4521", Policy{
		Rule:   "cgroup_limit",
		Value:  "mem=4G",
		Reason: "nginx memory spike",
	})
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	policy, err := store.GetPolicy("pid", "4521")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if policy.Rule != "cgroup_limit" {
		t.Fatalf("expected cgroup_limit, got %q", policy.Rule)
	}

	_, err = store.GetPolicy("pid", "9999")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_Events(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	err = store.RecordEvent(Event{
		Type:      "process_exec",
		Resource:  "pid:4521",
		Data:      `{"comm":"nginx","pid":4521}`,
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("record event: %v", err)
	}

	events, err := store.RecentEvents(10)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "process_exec" {
		t.Fatalf("expected process_exec, got %q", events[0].Type)
	}
}

func TestStore_AgentContext(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	id := "network-f9e8d7c6"
	store.SetAgentMeta(id, AgentMeta{Task: "investigate connection", Status: "active"})
	store.AppendAgentLog(id, LogEntry{Action: "inspect_conn", Result: "185.x.x.x:443"})
	store.AppendAgentLog(id, LogEntry{Action: "whois", Result: "Cloudflare CDN"})

	ctx, err := store.AgentContext(id)
	if err != nil {
		t.Fatalf("agent context: %v", err)
	}
	if ctx == "" {
		t.Fatal("expected non-empty context string")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/state/ -v
```

Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```go
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

var ErrNotFound = errors.New("not found")

// AgentMeta is metadata about an active agent goroutine.
type AgentMeta struct {
	Task      string    `json:"task"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
}

// LogEntry is a single entry in an agent's activity log.
type LogEntry struct {
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Policy is an active policy on a resource.
type Policy struct {
	Rule      string    `json:"rule"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	SetAt     time.Time `json:"set_at"`
	SetBy     string    `json:"set_by,omitempty"`
}

// Event is a recorded eBPF event.
type Event struct {
	Type      string    `json:"type"`
	Resource  string    `json:"resource"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// Store wraps buntdb for Veronica's shared state.
type Store struct {
	db *buntdb.DB
}

// Open creates or opens a state store. Use ":memory:" for in-memory mode.
func Open(path string) (*Store, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the state store.
func (s *Store) Close() error {
	return s.db.Close()
}

// SetAgentMeta sets metadata for an agent.
func (s *Store) SetAgentMeta(agentID string, meta AgentMeta) error {
	if meta.StartedAt.IsZero() {
		meta.StartedAt = time.Now()
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("agent:"+agentID+":meta", string(b), nil)
		return err
	})
}

// GetAgentMeta gets metadata for an agent.
func (s *Store) GetAgentMeta(agentID string) (*AgentMeta, error) {
	var meta AgentMeta
	err := s.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("agent:" + agentID + ":meta")
		if err == buntdb.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &meta)
	})
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// AppendAgentLog appends a log entry to an agent's log.
func (s *Store) AppendAgentLog(agentID string, entry LogEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("agent:%s:log:%020d", agentID, entry.Timestamp.UnixNano())
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), nil)
		return err
	})
}

// GetAgentLog returns all log entries for an agent, oldest first.
func (s *Store) GetAgentLog(agentID string) ([]LogEntry, error) {
	var entries []LogEntry
	prefix := "agent:" + agentID + ":log:"
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendRange("", prefix, prefix+"\xff", func(key, val string) bool {
			var entry LogEntry
			json.Unmarshal([]byte(val), &entry)
			entries = append(entries, entry)
			return true
		})
	})
	return entries, err
}

// SetPolicy sets a policy on a resource.
func (s *Store) SetPolicy(resourceType, resourceID string, policy Policy) error {
	if policy.SetAt.IsZero() {
		policy.SetAt = time.Now()
	}
	b, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	key := "policy:" + resourceType + ":" + resourceID
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), nil)
		return err
	})
}

// GetPolicy gets a policy for a resource.
func (s *Store) GetPolicy(resourceType, resourceID string) (*Policy, error) {
	var policy Policy
	err := s.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("policy:" + resourceType + ":" + resourceID)
		if err == buntdb.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &policy)
	})
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// RecordEvent records an eBPF event.
func (s *Store) RecordEvent(event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("event:%020d:%s", event.Timestamp.UnixNano(), event.Type)
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), &buntdb.SetOptions{
			Expires: true,
			TTL:     5 * time.Minute,
		})
		return err
	})
}

// RecentEvents returns the N most recent events.
func (s *Store) RecentEvents(limit int) ([]Event, error) {
	var events []Event
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.DescendRange("", "event:\xff", "event:", func(key, val string) bool {
			if len(events) >= limit {
				return false
			}
			var event Event
			json.Unmarshal([]byte(val), &event)
			events = append(events, event)
			return true
		})
	})
	return events, err
}

// AgentContext builds a human/LLM-readable context string for an agent's activity.
func (s *Store) AgentContext(agentID string) (string, error) {
	meta, err := s.GetAgentMeta(agentID)
	if err != nil {
		return "", err
	}
	entries, err := s.GetAgentLog(agentID)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Agent: %s\nTask: %s\nStatus: %s\n", agentID, meta.Task, meta.Status)
	for _, e := range entries {
		fmt.Fprintf(&b, "- %s: %s\n", e.Action, e.Result)
	}
	return b.String(), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/state/ -v
```

Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/state/store.go internal/state/store_test.go go.mod go.sum
git commit -m "feat(state): buntdb shared state store with agent log, policy, events

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Coordinator Types

**Files:**
- Create: `internal/coordinator/types.go`

- [ ] **Step 1: Write the types**

```go
package coordinator

import "time"

// Event is an eBPF event received by the coordinator.
type Event struct {
	Type      string // "process_exec", "file_write", "net_connect", etc.
	Resource  string // "pid:4521", "file:/etc/shadow", "ip:185.x.x.x"
	Data      string // raw JSON payload from eBPF
	Timestamp time.Time
}

// Action is something an agent wants to do to the system.
type Action struct {
	Type     string // "shell_exec", "write_file", "kill", "set_cgroup", "write_map", etc.
	Resource string // what resource this touches: "pid:4521", "file:/etc/config", "ip:1.2.3.4"
	Args     string // JSON-encoded type-specific arguments
}

// ActionRequest is sent from a conversation goroutine to the coordinator.
type ActionRequest struct {
	AgentID  string
	Action   Action
	Response chan ActionResult // coordinator sends result back on this channel
}

// ActionResult is the coordinator's response to an action request.
type ActionResult struct {
	Approved bool
	Output   string // result of execution if approved, reason if rejected
	Error    error
}

// Report is an activity update sent to observers (TUI).
type Report struct {
	AgentID   string
	EventType string // "spawned", "action_requested", "action_approved", "action_rejected", "conflict", "completed"
	Detail    string
	Timestamp time.Time
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/coordinator/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/coordinator/types.go
git commit -m "feat(coordinator): add event, action, and report types

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: AgentToolkit — Read-Only Tools as Agent Tools

**Files:**
- Create: `internal/coordinator/toolkit.go`
- Create: `internal/coordinator/toolkit_test.go`

This registers read-only OS tools + `request_action` into a `tool.Registry` that the `agent.Run` loop can use.

- [ ] **Step 1: Write the failing tests**

```go
package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fimbulwinter/veronica/internal/tool"
)

func TestToolkit_ReadFileRegistered(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	defs := reg.Definitions()
	found := false
	for _, d := range defs {
		if d.Function.Name == "read_file" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected read_file tool to be registered")
	}
}

func TestToolkit_ReadFileExecutes(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	os.WriteFile(testFile, []byte("hello world"), 0644)

	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	result, err := reg.Call(context.Background(), "read_file", `{"path":"`+testFile+`"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if s != "hello world" {
		t.Fatalf("expected 'hello world', got %q", s)
	}
}

func TestToolkit_RequestActionSendsToChannel(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	go func() {
		req := <-actionCh
		if req.AgentID != "test-agent" {
			t.Errorf("expected agent test-agent, got %s", req.AgentID)
		}
		if req.Action.Type != "shell_exec" {
			t.Errorf("expected shell_exec, got %s", req.Action.Type)
		}
		req.Response <- ActionResult{Approved: true, Output: "done"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"type":"shell_exec","resource":"pid:123","args":"{\"cmd\":\"systemctl restart nginx\"}"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if s != "approved: done" {
		t.Fatalf("expected 'approved: done', got %q", s)
	}
}

func TestToolkit_RequestActionRejected(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	go func() {
		req := <-actionCh
		req.Response <- ActionResult{Approved: false, Output: "conflicts with another agent"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"type":"kill","resource":"pid:1","args":"{}"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.(string)
	if s != "rejected: conflicts with another agent" {
		t.Fatalf("unexpected result: %q", s)
	}
}

func TestToolkit_ShellReadAllowlisted(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	result, err := reg.Call(context.Background(), "shell_read", `{"cmd":"echo","args":["hello"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.(string)
	if s != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", s)
	}
}

func TestToolkit_ShellReadBlocksDisallowed(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	_, err := reg.Call(context.Background(), "shell_read", `{"cmd":"rm","args":["-rf","/"]}`)
	if err == nil {
		t.Fatal("expected error for disallowed command")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/coordinator/ -v -run TestToolkit
```

Expected: FAIL — `NewToolkit` not defined.

- [ ] **Step 3: Write the implementation**

```go
package coordinator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fimbulwinter/veronica/internal/tool"
)

var allowedCommands = map[string]bool{
	"cat": true, "ls": true, "ps": true, "stat": true, "df": true,
	"ip": true, "ss": true, "whoami": true, "hostname": true, "uname": true,
	"uptime": true, "free": true, "id": true, "echo": true, "head": true,
	"tail": true, "wc": true, "du": true, "mount": true, "lsblk": true,
	"top": true, "netstat": true, "lsof": true, "file": true, "which": true,
}

type readFileArgs struct {
	Path string `json:"path" desc:"Absolute path to the file to read"`
}

type shellReadArgs struct {
	Cmd  string   `json:"cmd" desc:"Command to run (must be in allowlist)"`
	Args []string `json:"args,omitempty" desc:"Command arguments"`
}

type requestActionArgs struct {
	Type     string `json:"type" desc:"Action type: shell_exec, write_file, kill, set_cgroup, write_map, etc."`
	Resource string `json:"resource" desc:"Resource identifier: pid:N, file:/path, ip:addr, etc."`
	Args     string `json:"args" desc:"JSON-encoded action-specific arguments"`
}

// NewToolkit creates a tool.Registry with read-only tools and request_action.
// The agentID identifies this agent in action requests.
// The actionCh is used to send action requests to the coordinator.
func NewToolkit(actionCh chan<- ActionRequest, agentID string) *tool.Registry {
	reg := tool.NewRegistry()

	tool.Register(reg, "read_file", "Read a file's contents", func(ctx context.Context, args readFileArgs) (any, error) {
		b, err := os.ReadFile(args.Path)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	})

	tool.Register(reg, "shell_read", "Run a read-only shell command (allowlisted commands only)", func(ctx context.Context, args shellReadArgs) (any, error) {
		if !allowedCommands[args.Cmd] {
			return nil, fmt.Errorf("command %q not in allowlist", args.Cmd)
		}
		out, err := exec.CommandContext(ctx, args.Cmd, args.Args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %w\noutput: %s", args.Cmd, err, string(out))
		}
		return string(out), nil
	})

	tool.Register(reg, "request_action", "Request the coordinator to execute a write/execute action", func(ctx context.Context, args requestActionArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: agentID,
			Action: Action{
				Type:     args.Type,
				Resource: args.Resource,
				Args:     args.Args,
			},
			Response: respCh,
		}

		select {
		case result := <-respCh:
			if result.Error != nil {
				return nil, result.Error
			}
			if result.Approved {
				return "approved: " + result.Output, nil
			}
			return "rejected: " + result.Output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	return reg
}

// AllowedCommands returns the set of allowed shell_read commands. Exported for testing.
func AllowedCommands() map[string]bool {
	result := make(map[string]bool, len(allowedCommands))
	for k, v := range allowedCommands {
		result[k] = v
	}
	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/coordinator/ -v -run TestToolkit
```

Expected: all 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/coordinator/toolkit.go internal/coordinator/toolkit_test.go
git commit -m "feat(coordinator): agent toolkit with read-only tools and request_action

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Coordinator Core

**Files:**
- Create: `internal/coordinator/coordinator.go`
- Create: `internal/coordinator/coordinator_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func TestCoordinator_HandleEvent(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	var agentSpawned atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentSpawned.Store(true)
		resp := llm.Response{
			Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "handled"},
				FinishReason: "stop",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"nginx"}`,
	})

	// Wait for the goroutine to call the LLM
	deadline := time.After(3 * time.Second)
	for !agentSpawned.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for agent to be spawned")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCoordinator_ActionApproved(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response
		if callCount == 1 {
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c1", Type: "function",
						Function: llm.FunctionCall{
							Name:      "request_action",
							Arguments: `{"type":"shell_exec","resource":"pid:42","args":"{\"cmd\":\"echo ok\"}"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		} else {
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "action complete"},
				FinishReason: "stop",
			}}}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
		ActionExecutor: func(action Action) (string, error) {
			return "executed: " + action.Type, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	c.HandleEvent(Event{Type: "test", Resource: "pid:42", Data: `{}`})

	deadline := time.After(3 * time.Second)
	for callCount < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out, only got %d LLM calls", callCount)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCoordinator_Reports(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := llm.Response{Choices: []llm.Choice{{
			Message:      llm.Message{Role: "assistant", Content: "done"},
			FinishReason: "stop",
		}}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	c.HandleEvent(Event{Type: "test", Resource: "test", Data: `{}`})

	// Should receive at least a "spawned" report
	select {
	case r := <-reports:
		if r.EventType != "spawned" {
			t.Fatalf("expected spawned report, got %q", r.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for report")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/coordinator/ -v -run TestCoordinator
```

Expected: FAIL — `New`, `Start`, `HandleEvent` not defined.

- [ ] **Step 3: Write the implementation**

```go
package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/fimbulwinter/veronica/internal/agent"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	SystemPrompt   string
	MaxTurns       int
	ActionExecutor func(Action) (string, error) // executes approved actions; nil = auto-approve with "ok"
}

// Coordinator receives events, spawns agent goroutines, and serializes actions.
type Coordinator struct {
	client   *llm.Client
	store    *state.Store
	config   Config
	events   chan Event
	actions  chan ActionRequest
	reports  chan Report
	inFlight map[string]string // resource -> agentID currently acting on it
}

// New creates a coordinator.
func New(client *llm.Client, store *state.Store, cfg Config) *Coordinator {
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 10
	}
	return &Coordinator{
		client:   client,
		store:    store,
		config:   cfg,
		events:   make(chan Event, 64),
		actions:  make(chan ActionRequest, 64),
		reports:  make(chan Report, 256),
		inFlight: make(map[string]string),
	}
}

// Start begins the coordinator's event processing and action queue loops.
func (c *Coordinator) Start(ctx context.Context) {
	go c.eventLoop(ctx)
	go c.actionLoop(ctx)
}

// HandleEvent sends an event to the coordinator for processing.
func (c *Coordinator) HandleEvent(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	c.events <- event
}

// Reports returns the channel for observing coordinator activity.
func (c *Coordinator) Reports() <-chan Report {
	return c.reports
}

func (c *Coordinator) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-c.events:
			c.store.RecordEvent(state.Event{
				Type:      event.Type,
				Resource:  event.Resource,
				Data:      event.Data,
				Timestamp: event.Timestamp,
			})
			go c.spawnAgent(ctx, event)
		}
	}
}

func (c *Coordinator) spawnAgent(ctx context.Context, event Event) {
	agentID := agentIDFor(event)

	c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "active",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("%s on %s", event.Type, event.Resource),
	})

	toolkit := NewToolkit(c.actions, agentID)

	userMsg := fmt.Sprintf("eBPF event: type=%s resource=%s data=%s\nHandle this event.", event.Type, event.Resource, event.Data)

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: c.config.SystemPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, userMsg)

	if err != nil {
		log.Printf("agent %s error: %v", agentID, err)
		c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "error", Result: err.Error(),
		})
	} else {
		c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "completed", Result: result.Response,
		})
	}

	c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
	})
}

func (c *Coordinator) actionLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.actions:
			c.report(Report{
				AgentID:   req.AgentID,
				EventType: "action_requested",
				Detail:    fmt.Sprintf("%s on %s", req.Action.Type, req.Action.Resource),
			})

			// Check for conflict
			if existingAgent, ok := c.inFlight[req.Action.Resource]; ok && existingAgent != req.AgentID {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "conflict",
					Detail:    fmt.Sprintf("resource %s already claimed by %s", req.Action.Resource, existingAgent),
				})
				req.Response <- ActionResult{
					Approved: false,
					Output:   fmt.Sprintf("resource %s is being handled by %s", req.Action.Resource, existingAgent),
				}
				continue
			}

			c.inFlight[req.Action.Resource] = req.AgentID

			executor := c.config.ActionExecutor
			if executor == nil {
				executor = func(a Action) (string, error) { return "ok", nil }
			}

			output, err := executor(req.Action)

			delete(c.inFlight, req.Action.Resource)

			if err != nil {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "action_rejected",
					Detail:    err.Error(),
				})
				req.Response <- ActionResult{Approved: false, Output: err.Error(), Error: err}
			} else {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "action_approved",
					Detail:    output,
				})
				c.store.AppendAgentLog(req.AgentID, state.LogEntry{
					Action: req.Action.Type,
					Result: output,
				})
				req.Response <- ActionResult{Approved: true, Output: output}
			}
		}
	}
}

func (c *Coordinator) report(r Report) {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	select {
	case c.reports <- r:
	default:
		// drop if observer is slow
	}
}

func agentIDFor(event Event) string {
	domain := event.Type
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", domain, hex.EncodeToString(b))
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/coordinator/ -v -run TestCoordinator
```

Expected: all 3 PASS.

- [ ] **Step 5: Run all tests**

```bash
go test ./... -v
```

Expected: all tests across all packages PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/coordinator/coordinator.go internal/coordinator/coordinator_test.go
git commit -m "feat(coordinator): event intake, goroutine spawning, action queue with conflict detection

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Coordinator Integration Test

**Files:**
- Create: `internal/coordinator/integration_test.go`

Full end-to-end: event → coordinator → agent goroutine → LLM → tool call → read local → tool call → request_action → coordinator approves → LLM final → done. Verifies state in buntdb.

- [ ] **Step 1: Write the integration test**

```go
package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func TestIntegration_FullEventLifecycle(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response

		switch callCount {
		case 1:
			// Agent reads a file first (read-only, no coordinator)
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c1", Type: "function",
						Function: llm.FunctionCall{
							Name:      "shell_read",
							Arguments: `{"cmd":"echo","args":["process info"]}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 2:
			// Agent requests an action (goes through coordinator)
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c2", Type: "function",
						Function: llm.FunctionCall{
							Name:      "request_action",
							Arguments: `{"type":"set_cgroup","resource":"pid:4521","args":"{\"mem\":\"4G\"}"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 3:
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "Applied 4G memory limit to pid 4521"},
				FinishReason: "stop",
			}}}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	executedActions := make(chan Action, 1)
	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage Linux systems via eBPF.",
		MaxTurns:     10,
		ActionExecutor: func(a Action) (string, error) {
			executedActions <- a
			return "cgroup limit applied", nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Send an event
	c.HandleEvent(Event{
		Type:     "process_high_cpu",
		Resource: "pid:4521",
		Data:     `{"comm":"nginx","cpu_pct":95}`,
	})

	// Collect reports until we see "completed"
	var gotSpawned, gotActionReq, gotApproved, gotCompleted bool
	deadline := time.After(5 * time.Second)

	for !gotCompleted {
		select {
		case r := <-reports:
			switch r.EventType {
			case "spawned":
				gotSpawned = true
			case "action_requested":
				gotActionReq = true
			case "action_approved":
				gotApproved = true
			case "completed":
				gotCompleted = true
			}
		case <-deadline:
			t.Fatalf("timed out. spawned=%v action_req=%v approved=%v completed=%v",
				gotSpawned, gotActionReq, gotApproved, gotCompleted)
		}
	}

	if !gotSpawned || !gotActionReq || !gotApproved {
		t.Fatalf("missing reports. spawned=%v action_req=%v approved=%v",
			gotSpawned, gotActionReq, gotApproved)
	}

	// Verify the action was executed
	select {
	case a := <-executedActions:
		if a.Type != "set_cgroup" {
			t.Fatalf("expected set_cgroup, got %s", a.Type)
		}
		if a.Resource != "pid:4521" {
			t.Fatalf("expected pid:4521, got %s", a.Resource)
		}
	default:
		t.Fatal("no action was executed")
	}

	// Verify event was recorded in state
	events, _ := store.RecentEvents(10)
	if len(events) == 0 {
		t.Fatal("expected events in store")
	}
	if events[0].Type != "process_high_cpu" {
		t.Fatalf("expected process_high_cpu, got %s", events[0].Type)
	}
}
```

- [ ] **Step 2: Run the test**

```bash
go test ./internal/coordinator/ -v -run TestIntegration
```

Expected: PASS.

- [ ] **Step 3: Run all tests**

```bash
go test ./... -count=1
```

Expected: all packages PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/coordinator/integration_test.go
git commit -m "test(coordinator): full event lifecycle integration test

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Summary

After completing all 6 tasks you have:

| Package | What it does | Tests |
|---|---|---|
| `internal/state` | buntdb wrapper: agent log, policy, events, context builder | 5 |
| `internal/coordinator` | Event intake, goroutine spawning, action queue, conflict detection, toolkit | ~9 |
| **New dep** | `github.com/tidwall/buntdb` | |

Combined with Plan 1's packages, the full daemon core is testable without eBPF or a VM. The only thing missing is the eBPF manager (Plan 3) and the main entrypoint (Plan 4).
