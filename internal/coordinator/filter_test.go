package coordinator

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func eventWithComm(comm string) Event {
	return Event{
		Type:     "process_exec",
		Resource: fmt.Sprintf("pid:%s", comm),
		Data:     fmt.Sprintf(`{"comm":%q,"uid":1000}`, comm),
	}
}

func eventWithResource(comm, resource string) Event {
	return Event{
		Type:     "process_exec",
		Resource: resource,
		Data:     fmt.Sprintf(`{"comm":%q,"uid":1000}`, comm),
	}
}

// --- Self filtering ---

func TestFilter_IgnoresSelf(t *testing.T) {
	f := NewFilter(10)
	e := eventWithComm("veronica")
	if f.ShouldProcess(e) {
		t.Fatal("expected veronica to be filtered out")
	}
}

// --- Noise filtering ---

func TestFilter_IgnoresNoiseComms(t *testing.T) {
	noisy := []string{"ls", "cat", "grep", "find", "ps", "date", "sleep", "journalctl", "systemctl"}
	f := NewFilter(10)
	for _, comm := range noisy {
		e := eventWithComm(comm)
		if f.ShouldProcess(e) {
			t.Errorf("expected comm %q to be filtered out", comm)
		}
	}
}

func TestFilter_IgnoresNoisePrefixes(t *testing.T) {
	noisy := []string{"systemd-journald", "dbus-daemon", "lima-guestagent", "ssh-agent"}
	f := NewFilter(10)
	for _, comm := range noisy {
		e := eventWithComm(comm)
		if f.ShouldProcess(e) {
			t.Errorf("expected comm %q to be filtered out", comm)
		}
	}
}

func TestFilter_AllowsInterestingComm(t *testing.T) {
	f := NewFilter(10)
	e := eventWithComm("nginx")
	if !f.ShouldProcess(e) {
		t.Fatal("expected nginx to be processed")
	}
}

// --- Rate limiting ---

func TestFilter_RateLimitSameResourceWithinWindow(t *testing.T) {
	f := NewFilter(10)
	e := eventWithResource("nginx", "pid:999")

	if !f.ShouldProcess(e) {
		t.Fatal("first event should be processed")
	}
	// Second event for same resource within 5s window should be dropped.
	if f.ShouldProcess(e) {
		t.Fatal("second event within rate-limit window should be dropped")
	}
}

func TestFilter_RateLimitAllowsAfterWindow(t *testing.T) {
	f := NewFilter(10)
	e := eventWithResource("nginx", "pid:998")

	if !f.ShouldProcess(e) {
		t.Fatal("first event should be processed")
	}

	// Backdate the lastSeen entry to simulate the window having passed.
	f.mu.Lock()
	f.lastSeen[e.Resource] = time.Now().Add(-rateLimitWindow - time.Millisecond)
	f.mu.Unlock()

	if !f.ShouldProcess(e) {
		t.Fatal("event after rate-limit window should be processed")
	}
}

func TestFilter_RateLimitDistinctResourcesAreIndependent(t *testing.T) {
	f := NewFilter(10)
	e1 := eventWithResource("nginx", "pid:101")
	e2 := eventWithResource("nginx", "pid:102")

	if !f.ShouldProcess(e1) {
		t.Fatal("e1 first event should be processed")
	}
	if !f.ShouldProcess(e2) {
		t.Fatal("e2 first event should be processed (different resource)")
	}
}

// --- Max concurrent agents ---

func TestFilter_MaxConcurrentDropsEvents(t *testing.T) {
	f := NewFilter(2)

	// Saturate the active count.
	f.AgentStarted()
	f.AgentStarted()

	e := eventWithResource("nginx", "pid:200")
	if f.ShouldProcess(e) {
		t.Fatal("expected event to be dropped when at max concurrent agents")
	}
}

func TestFilter_MaxConcurrentAllowsAfterFinished(t *testing.T) {
	f := NewFilter(1)
	f.AgentStarted()

	e := eventWithResource("nginx", "pid:300")
	if f.ShouldProcess(e) {
		t.Fatal("should be dropped when at max")
	}

	f.AgentFinished()

	// Use a different resource to bypass rate limiting.
	e2 := eventWithResource("nginx", "pid:301")
	if !f.ShouldProcess(e2) {
		t.Fatal("should be allowed once a slot frees up")
	}
}

func TestFilter_AgentStartedFinishedConcurrency(t *testing.T) {
	f := NewFilter(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.AgentStarted()
			f.AgentFinished()
		}()
	}
	wg.Wait()
	if got := f.activeCount.Load(); got != 0 {
		t.Fatalf("expected activeCount=0 after all agents finished, got %d", got)
	}
}
