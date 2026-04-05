package classifier

import (
	"testing"

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

func TestClassifier_FileOpenInterestingPathPasses(t *testing.T) {
	c := New()
	for _, path := range []string{"/etc/nginx/nginx.conf", "/home/user/.bashrc", "/tmp/data.csv", "/root/.ssh/id_ed25519"} {
		e := event.Event{Type: "file_open", Resource: "file:" + path, Data: `{"comm":"vim","filename":"` + path + `"}`}
		if got := c.Classify(e); got != CategoryPass {
			t.Fatalf("expected pass for file_open %s, got %s", path, got)
		}
	}
}

func TestClassifier_FileOpenNoisyPathIsSilent(t *testing.T) {
	c := New()
	for _, path := range []string{"/proc/1/stat", "/sys/class/net/eth0", "/dev/null", "/usr/lib/libfoo.so", "/run/lock/file", "/var/cache/apt/pkg"} {
		e := event.Event{Type: "file_open", Resource: "file:" + path, Data: `{"comm":"cat","filename":"` + path + `"}`}
		if got := c.Classify(e); got != CategorySilent {
			t.Fatalf("expected silent for file_open %s, got %s", path, got)
		}
	}
}

func TestClassifier_FileOpenUnknownPathIsSilent(t *testing.T) {
	c := New()
	e := event.Event{Type: "file_open", Resource: "file:/some/random/path", Data: `{"comm":"cat","filename":"/some/random/path"}`}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("expected silent for unknown path, got %s", got)
	}
}
