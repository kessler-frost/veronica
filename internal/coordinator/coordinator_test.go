package coordinator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/state"
)

type mockRouter struct {
	mu     sync.Mutex
	events []Event
	count  atomic.Int32
}

func (m *mockRouter) RouteEvent(ctx context.Context, event Event, category EventCategory) {
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
	m.count.Add(1)
}

func (m *mockRouter) routedCount() int {
	return int(m.count.Load())
}

func (m *mockRouter) routedEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

func TestCoordinator_UrgentEventRouted(t *testing.T) {
	store, _ := state.Open(":memory:")
	t.Cleanup(func() { _ = store.Close() })

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// chmod on sensitive path → urgent
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"chmod","cmdline":"chmod 777 /etc/shadow","filename":"/usr/bin/chmod"}`,
	})

	deadline := time.After(3 * time.Second)
	for router.routedCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for urgent event to be routed")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	events := router.routedEvents()
	if len(events) == 0 {
		t.Fatal("expected at least one routed event")
	}
	if events[0].Type != "process_exec" {
		t.Fatalf("expected process_exec, got %q", events[0].Type)
	}
}

func TestCoordinator_BatchEventRouted(t *testing.T) {
	store, _ := state.Open(":memory:")
	t.Cleanup(func() { _ = store.Close() })

	router := &mockRouter{}
	// Use a short batch interval for the test
	c := New(router, store, Config{MaxTurns: 10})
	c.batch = NewBatch(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Regular mkdir → batch
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:42",
		Data:     `{"comm":"mkdir","cmdline":"mkdir /tmp/test","filename":"/usr/bin/mkdir"}`,
	})

	// Wait for batch flush + routing
	deadline := time.After(2 * time.Second)
	for router.routedCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for batch event to be routed")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	events := router.routedEvents()
	if len(events) == 0 {
		t.Fatal("expected at least one routed event")
	}
	if events[0].Type != "batch" {
		t.Fatalf("expected batch event type, got %q", events[0].Type)
	}
}

func TestCoordinator_SilentEventDropped(t *testing.T) {
	store, _ := state.Open(":memory:")
	t.Cleanup(func() { _ = store.Close() })

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})
	c.batch = NewBatch(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// systemd-journald → silent, should not be routed
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:1",
		Data:     `{"comm":"systemd-journald","cmdline":"systemd-journald","filename":"/usr/lib/systemd/systemd-journald"}`,
	})

	// Wait a bit beyond the batch interval — nothing should be routed
	time.Sleep(300 * time.Millisecond)

	if router.routedCount() != 0 {
		t.Fatalf("expected no routed events for silent comm, got %d", router.routedCount())
	}
}

func TestCoordinator_Reports(t *testing.T) {
	store, _ := state.Open(":memory:")
	t.Cleanup(func() { _ = store.Close() })

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Urgent event → "routed" report emitted
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:99",
		Data:     `{"comm":"chmod","cmdline":"chmod 777 /etc/shadow","filename":"/usr/bin/chmod"}`,
	})

	select {
	case r := <-reports:
		if r.EventType != "routed" {
			t.Fatalf("expected routed report, got %q", r.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for report")
	}
}

func TestCoordinator_ActionQueueConflict(t *testing.T) {
	store, _ := state.Open(":memory:")
	t.Cleanup(func() { _ = store.Close() })

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	resource := "file:/etc/config"

	// Send agent-1's action and let it complete so the action loop is free.
	resp1 := make(chan ActionResult, 1)
	c.actions <- ActionRequest{
		AgentID:  "agent-1",
		Action:   Action{Type: "shell_exec", Resource: resource, Args: `{"command":"echo 1"}`},
		Response: resp1,
	}
	select {
	case <-resp1:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for agent-1 to complete")
	}

	// Re-inject the claim as if agent-1 is still running (action loop is idle here).
	c.inFlight[resource] = "agent-1"

	// agent-2 requests the same resource → should be rejected due to conflict.
	resp2 := make(chan ActionResult, 1)
	c.actions <- ActionRequest{
		AgentID:  "agent-2",
		Action:   Action{Type: "shell_exec", Resource: resource, Args: `{"command":"echo 2"}`},
		Response: resp2,
	}

	select {
	case result := <-resp2:
		if result.Approved {
			t.Fatal("expected agent-2 to be rejected due to conflict with agent-1")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for conflict rejection")
	}
}
