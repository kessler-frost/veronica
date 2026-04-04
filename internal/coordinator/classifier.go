package coordinator

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// EventCategory determines how the coordinator handles an event.
type EventCategory int

const (
	// CategorySilent — drop entirely, no LLM.
	CategorySilent EventCategory = iota
	// CategoryUrgent — spawn agent immediately (security, crashes).
	CategoryUrgent
	// CategoryBatch — accumulate into 5s batch, one agent for all.
	CategoryBatch
)

func (c EventCategory) String() string {
	switch c {
	case CategorySilent:
		return "silent"
	case CategoryUrgent:
		return "urgent"
	case CategoryBatch:
		return "batch"
	default:
		return "unknown"
	}
}

// Classifier decides what's noise, what's urgent, and what gets batched.
// Minimal silent list. Urgent is simple code rules. Everything else batches.
type Classifier struct {
	mu sync.RWMutex

	// SelfComms are Veronica's own process names.
	SelfComms map[string]bool

	// SilentPrefixes are comm prefixes for system daemons.
	SilentPrefixes []string

	// SensitivePaths trigger urgent agents when touched.
	SensitivePaths map[string]bool

	// KnownServices get urgent agents on crash (non-zero exit).
	KnownServices map[string]bool

	// IsOurPID returns true for PIDs spawned by the action executor.
	IsOurPID func(pid uint32) bool
}

// NewClassifier creates a classifier with minimal rules.
func NewClassifier() *Classifier {
	return &Classifier{
		SelfComms: map[string]bool{
			"veronicad": true,
			"veronica":  true,
		},

		SilentPrefixes: []string{
			"systemd-", "dbus-", "lima-",
			"gsd-", "gdm-", "gnome-", "xdg-",
			"podman-", "containerd-",
		},

		SensitivePaths: map[string]bool{
			"/etc/shadow":  true,
			"/etc/passwd":  true,
			"/etc/sudoers": true,
			"/etc/ssh":     true,
			"/root/.ssh":   true,
			"/etc/crontab": true,
			"/etc/cron.d":  true,
		},

		KnownServices: map[string]bool{
			"nginx": true, "postgres": true, "redis-server": true,
			"mongod": true, "mysqld": true, "httpd": true,
			"node": true, "python3": true, "python": true,
			"java": true, "gunicorn": true, "uvicorn": true,
		},
	}
}

// Classify returns the category for an event.
func (c *Classifier) Classify(event Event) EventCategory {
	comm := commFromData(event.Data)
	pid := pidFromData(event.Data)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Self
	if c.SelfComms[comm] {
		return CategorySilent
	}

	// Our own child processes
	if c.IsOurPID != nil && pid > 0 && c.IsOurPID(pid) {
		return CategorySilent
	}

	// System daemon prefixes
	for _, prefix := range c.SilentPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return CategorySilent
		}
	}

	// URGENT: service crash (non-zero exit)
	if event.Type == "process_exit" {
		exitCode := exitCodeFromData(event.Data)
		if exitCode != 0 && c.KnownServices[comm] {
			return CategoryUrgent
		}
		// Normal exits and unknown process crashes → batch
		return CategoryBatch
	}

	// URGENT: sensitive path in cmdline
	cmdline := cmdlineFromData(event.Data)
	for path := range c.SensitivePaths {
		if strings.Contains(cmdline, path) {
			return CategoryUrgent
		}
	}

	// URGENT: binary from non-standard path (only if we have a filename and it's not a lib)
	if event.Type == "process_exec" {
		filename := filenameFromData(event.Data)
		if filename != "" && !isStandardPath(filename) && !strings.HasPrefix(filename, "/lib") {
			return CategoryUrgent
		}
	}

	// Everything else → batch
	return CategoryBatch
}

func filenameFromData(data string) string {
	var payload struct {
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Filename
}

func pidFromData(data string) uint32 {
	var payload struct {
		PID uint32 `json:"pid"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return 0
	}
	return payload.PID
}

func exitCodeFromData(data string) int {
	var payload struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return 0
	}
	return payload.ExitCode
}

func isStandardPath(filename string) bool {
	standardPrefixes := []string{
		"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
		"/usr/lib/", "/usr/libexec/",
		"/root/go/", "/home/", "/usr/local/go/",
		"/root/.local/", "/root/.cargo/", "/root/.bun/",
	}
	for _, p := range standardPrefixes {
		if strings.HasPrefix(filename, p) {
			return true
		}
	}
	return false
}

// Batch collects events for periodic batch processing.
type Batch struct {
	mu       sync.Mutex
	events   []Event
	interval time.Duration
}

// NewBatch creates a batch with the given flush interval.
func NewBatch(interval time.Duration) *Batch {
	return &Batch{
		interval: interval,
	}
}

// Add appends an event to the current batch window.
func (b *Batch) Add(event Event) {
	b.mu.Lock()
	b.events = append(b.events, event)
	b.mu.Unlock()
}

// Flush returns all accumulated events and resets the buffer.
func (b *Batch) Flush() []Event {
	b.mu.Lock()
	events := b.events
	b.events = nil
	b.mu.Unlock()
	return events
}
