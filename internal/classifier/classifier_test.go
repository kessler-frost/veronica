package classifier

import (
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/event"
)

func TestClassifier_SelfIsSilent(t *testing.T) {
	c := New()
	e := event.Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"veronicad"}`}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("expected silent for self, got %s", got)
	}
}

func TestClassifier_DaemonPrefixIsSilent(t *testing.T) {
	c := New()
	for _, comm := range []string{"systemd-resolved", "dbus-daemon", "lima-guestagent"} {
		e := event.Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(e); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_OurPIDIsSilent(t *testing.T) {
	c := New()
	c.IsOurPID = func(pid uint32) bool { return pid == 42 }
	e := event.Event{Type: "process_exec", Resource: "pid:42", Data: `{"comm":"mkdir","pid":42}`}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("expected silent for our PID, got %s", got)
	}
}

func TestClassifier_SilentCommsAreSilent(t *testing.T) {
	c := New()
	for _, comm := range []string{"sshd", "login", "agetty"} {
		e := event.Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(e); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_RegularCommandPasses(t *testing.T) {
	c := New()
	for _, comm := range []string{"mkdir", "git", "curl", "python3", "ls", "cat", "nginx", "sudo", "bash"} {
		e := event.Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `","filename":"/usr/bin/` + comm + `"}`}
		if got := c.Classify(e); got != CategoryPass {
			t.Fatalf("expected pass for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_ProcessExitPasses(t *testing.T) {
	c := New()
	e := event.Event{Type: "process_exit", Resource: "pid:1", Data: `{"comm":"nginx","exit_code":1}`}
	if got := c.Classify(e); got != CategoryPass {
		t.Fatalf("expected pass for process exit, got %s", got)
	}
}

func TestClassifier_NetConnectPasses(t *testing.T) {
	c := New()
	e := event.Event{Type: "net_connect", Resource: "ip:1.2.3.4:80", Data: `{"comm":"curl","daddr":"1.2.3.4","dport":80}`}
	if got := c.Classify(e); got != CategoryPass {
		t.Fatalf("expected pass for net_connect, got %s", got)
	}
}

func TestBatch_AddAndFlush(t *testing.T) {
	b := NewBatch(5 * time.Second)

	b.Add(event.Event{Type: "process_exec", Resource: "pid:1"})
	b.Add(event.Event{Type: "process_exec", Resource: "pid:2"})
	b.Add(event.Event{Type: "net_connect", Resource: "ip:1.2.3.4:80"})

	events := b.Flush()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	events = b.Flush()
	if len(events) != 0 {
		t.Fatalf("expected 0 events after second flush, got %d", len(events))
	}
}
