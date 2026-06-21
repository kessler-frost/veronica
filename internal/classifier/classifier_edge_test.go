package classifier

import (
	"testing"

	"github.com/fimbulwinter/veronica/internal/event"
)

func TestEventCategory_String(t *testing.T) {
	if CategorySilent.String() != "silent" {
		t.Fatalf("CategorySilent.String() = %q", CategorySilent.String())
	}
	if CategoryPass.String() != "pass" {
		t.Fatalf("CategoryPass.String() = %q", CategoryPass.String())
	}
	if EventCategory(99).String() != "unknown" {
		t.Fatalf("unknown category should stringify to unknown")
	}
}

// Self/silent comm precedence beats the IsOurPID and prefix checks.
func TestClassify_SelfBeatsEverything(t *testing.T) {
	c := New()
	c.IsOurPID = func(uint32) bool { return false }
	e := event.Event{Type: "process_exec", Data: `{"comm":"veronicad","pid":5}`}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("self comm must be silent regardless of pid, got %s", got)
	}
}

// IsOurPID is only consulted when pid > 0 and the func is non-nil.
func TestClassify_IsOurPIDGuards(t *testing.T) {
	t.Run("nil_func_does_not_panic", func(t *testing.T) {
		c := New()
		c.IsOurPID = nil
		e := event.Event{Type: "process_exec", Data: `{"comm":"git","pid":5}`}
		if got := c.Classify(e); got != CategoryPass {
			t.Fatalf("expected pass with nil IsOurPID, got %s", got)
		}
	})

	t.Run("pid_zero_skips_check", func(t *testing.T) {
		c := New()
		called := false
		c.IsOurPID = func(uint32) bool { called = true; return true }
		e := event.Event{Type: "process_exec", Data: `{"comm":"git","pid":0}`}
		got := c.Classify(e)
		if called {
			t.Fatal("IsOurPID must not be called for pid=0")
		}
		if got != CategoryPass {
			t.Fatalf("expected pass when pid=0, got %s", got)
		}
	})
}

// A prefix in SilentPrefixes only matches at the start, not mid-string.
func TestClassify_PrefixMatchesStartOnly(t *testing.T) {
	c := New()
	// "my-systemd-helper" starts with "my-", not "systemd-", so it should pass.
	e := event.Event{Type: "process_exec", Data: `{"comm":"my-systemd-helper","pid":5}`}
	if got := c.Classify(e); got != CategoryPass {
		t.Fatalf("expected pass for non-prefix match, got %s", got)
	}
}

// file_open: a write to an interesting path that ALSO matches a silent prefix
// must be dropped (silent prefixes are checked first).
func TestClassify_FileOpenSilentPrefixWins(t *testing.T) {
	c := New()
	// /var/veronica/ is silent even though writes are normally interesting.
	e := event.Event{
		Type: "file_open",
		Data: `{"comm":"veronicad-child","filename":"/var/veronica/state.db","flags":1}`,
	}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("expected silent for write under /var/veronica/, got %s", got)
	}
}

// file_open with O_CREAT but no write access mode (still O_RDONLY) is dropped.
func TestClassify_FileOpenCreatOnlyIsSilent(t *testing.T) {
	c := New()
	e := event.Event{
		Type: "file_open",
		// 0o100 = O_CREAT, low two bits are 0 => O_RDONLY => not a write.
		Data: `{"comm":"touch","filename":"/etc/newfile","flags":64}`,
	}
	if got := c.Classify(e); got != CategorySilent {
		t.Fatalf("expected silent for O_CREAT-only (read mode) open, got %s", got)
	}
}

// A process_exec event with empty/missing comm still passes (not in any silent set).
func TestClassify_EmptyCommPasses(t *testing.T) {
	c := New()
	e := event.Event{Type: "process_exec", Data: `{"pid":5}`}
	if got := c.Classify(e); got != CategoryPass {
		t.Fatalf("expected pass for empty comm, got %s", got)
	}
}

// Malformed JSON data yields empty comm/zero pid and the event passes through
// (non-file_open types default to pass).
func TestClassify_MalformedDataPasses(t *testing.T) {
	c := New()
	e := event.Event{Type: "net_connect", Data: `{not valid`}
	if got := c.Classify(e); got != CategoryPass {
		t.Fatalf("expected pass for malformed net_connect data, got %s", got)
	}
}
