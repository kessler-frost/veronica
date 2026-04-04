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
