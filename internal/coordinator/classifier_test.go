package coordinator

import (
	"testing"
	"time"
)

func TestClassifier_SelfIsSilent(t *testing.T) {
	c := NewClassifier()
	event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"veronicad"}`}
	if got := c.Classify(event); got != CategorySilent {
		t.Fatalf("expected silent for self, got %s", got)
	}
}

func TestClassifier_SystemDaemonIsSilent(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"bash", "systemctl", "journalctl"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_SystemPrefixIsSilent(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"systemd-resolved", "dbus-daemon", "lima-guestagent"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_OurPIDIsSilent(t *testing.T) {
	c := NewClassifier()
	c.IsOurPID = func(pid uint32) bool { return pid == 42 }
	event := Event{Type: "process_exec", Resource: "pid:42", Data: `{"comm":"mkdir","pid":42}`}
	if got := c.Classify(event); got != CategorySilent {
		t.Fatalf("expected silent for our PID, got %s", got)
	}
}

func TestClassifier_EverythingElseGoesToAgent(t *testing.T) {
	c := NewClassifier()
	// User commands, services, tools — all go to agent. LLM decides.
	for _, comm := range []string{"mkdir", "nginx", "git", "curl", "chmod", "docker", "python3", "node"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		got := c.Classify(event)
		if got == CategorySilent {
			t.Fatalf("expected agent for %s, got silent", comm)
		}
	}
}

func TestClassifier_RulesAreReconfigurable(t *testing.T) {
	c := NewClassifier()

	// bash is silent by default
	event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"bash"}`}
	if got := c.Classify(event); got != CategorySilent {
		t.Fatalf("expected silent for bash, got %s", got)
	}

	// Remove bash from silent
	c.mu.Lock()
	delete(c.SilentComms, "bash")
	c.mu.Unlock()

	if got := c.Classify(event); got == CategorySilent {
		t.Fatalf("expected non-silent for bash after reconfig, got silent")
	}
}

func TestDigest_AddAndFlush(t *testing.T) {
	d := NewDigest(5 * time.Second)

	d.Add(Event{Type: "process_exec", Resource: "pid:1"})
	d.Add(Event{Type: "file_open", Resource: "file:/tmp/foo"})
	d.Add(Event{Type: "net_connect", Resource: "ip:1.2.3.4:80"})

	events := d.Flush()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	events = d.Flush()
	if len(events) != 0 {
		t.Fatalf("expected 0 events after second flush, got %d", len(events))
	}
}
