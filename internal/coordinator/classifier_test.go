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

func TestClassifier_NoiseCommandIsSilent(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"ls", "cat", "grep", "bash", "echo"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_NoisePrefixIsSilent(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"systemd-resolved", "dbus-daemon", "lima-guestagent", "ssh-agent"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategorySilent {
			t.Fatalf("expected silent for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_ServiceIsImmediate(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"nginx", "postgres", "sudo", "iptables"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategoryImmediate {
			t.Fatalf("expected immediate for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_ProjectToolIsProactive(t *testing.T) {
	c := NewClassifier()
	for _, comm := range []string{"mkdir", "git", "uv", "docker", "curl"} {
		event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"` + comm + `"}`}
		if got := c.Classify(event); got != CategoryProactive {
			t.Fatalf("expected proactive for %s, got %s", comm, got)
		}
	}
}

func TestClassifier_SensitiveFileIsImmediate(t *testing.T) {
	c := NewClassifier()
	event := Event{Type: "file_open", Resource: "file:/etc/shadow", Data: `{"comm":"cat","filename":"/etc/shadow"}`}
	if got := c.Classify(event); got != CategoryImmediate {
		t.Fatalf("expected immediate for sensitive file, got %s", got)
	}
}

func TestClassifier_UnknownBinaryIsImmediate(t *testing.T) {
	c := NewClassifier()
	event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"malware","filename":"/tmp/malware"}`}
	if got := c.Classify(event); got != CategoryImmediate {
		t.Fatalf("expected immediate for unknown binary outside standard path, got %s", got)
	}
}

func TestClassifier_StandardPathUnknownIsDigest(t *testing.T) {
	c := NewClassifier()
	event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"someutil","filename":"/usr/bin/someutil"}`}
	if got := c.Classify(event); got != CategoryDigest {
		t.Fatalf("expected digest for unknown command in standard path, got %s", got)
	}
}

func TestClassifier_RulesAreReconfigurable(t *testing.T) {
	c := NewClassifier()

	// ls is silent by default
	event := Event{Type: "process_exec", Resource: "pid:1", Data: `{"comm":"ls"}`}
	if got := c.Classify(event); got != CategorySilent {
		t.Fatalf("expected silent for ls, got %s", got)
	}

	// Move ls to proactive
	c.mu.Lock()
	delete(c.SilentComms, "ls")
	c.ProactiveComms["ls"] = true
	c.mu.Unlock()

	if got := c.Classify(event); got != CategoryProactive {
		t.Fatalf("expected proactive for ls after reconfig, got %s", got)
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

	// Flush again should be empty
	events = d.Flush()
	if len(events) != 0 {
		t.Fatalf("expected 0 events after second flush, got %d", len(events))
	}
}
