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
	// CategorySilent — skip entirely, no LLM.
	CategorySilent EventCategory = iota
	// CategoryAgent — send to LLM, let it decide what to do.
	CategoryAgent
	// CategoryDigest — batch into periodic summary for LLM.
	CategoryDigest
)

func (c EventCategory) String() string {
	switch c {
	case CategorySilent:
		return "silent"
	case CategoryAgent:
		return "agent"
	case CategoryDigest:
		return "digest"
	default:
		return "unknown"
	}
}

// Classifier decides what's noise and what gets sent to the LLM.
// Only filters out things that are definitely not interesting.
// Everything else goes to the LLM — it decides what to do.
type Classifier struct {
	mu sync.RWMutex

	// SilentComms are OS internals that never need intelligence.
	SilentComms map[string]bool

	// SilentPrefixes are comm prefixes for system daemons.
	SilentPrefixes []string

	// SelfComms are Veronica's own process names.
	SelfComms map[string]bool

	// IsOurPID returns true for PIDs spawned by the action executor.
	IsOurPID func(pid uint32) bool
}

// NewClassifier creates a classifier with minimal silence rules.
func NewClassifier() *Classifier {
	return &Classifier{
		SelfComms: map[string]bool{
			"veronicad": true,
			"veronica":  true,
		},

		// Only filter things that are genuinely OS noise — never user-initiated.
		SilentComms: map[string]bool{
			// Shells themselves (not what they run)
			"bash": true, "sh": true, "zsh": true, "dash": true,
			// Pagers
			"less": true, "more": true, "pager": true,
			// System query tools
			"journalctl": true, "systemctl": true,
			"loginctl": true, "timedatectl": true,
			"hostnamectl": true, "localectl": true,
			// SSH session setup noise
			"grepconf.sh": true, "tty": true, "locale": true,
			"dircolors": true, "lesspipe.sh": true, "env": true,
			"id": true, "hostname": true, "uname": true,
			// Dynamic linker and low-level runtime
			"ld-linux-aarch64.so.1": true, "ld-linux-x86-64.so.2": true,
			"ldconfig": true,
			// Common non-interactive tools
			"unix_chkpwd": true, "sudo": true,
			"grep": true, "sed": true, "awk": true, "cut": true,
			"sort": true, "uniq": true, "tr": true, "wc": true,
			"head": true, "tail": true, "cat": true,
			"ls": true, "stat": true, "find": true, "test": true,
			"[": true, "true": true, "false": true,
			"echo": true, "printf": true, "date": true, "sleep": true,
			"rm": true, "cp": true, "mv": true,
			// Package manager internals
			"selinuxenabled": true, "restorecon": true, "chcon": true,
			"gtk-update-icon-cache": true,
			"update-mime-database":  true, "glib-compile-schemas": true,
			"fc-cache": true, "mandb": true, "install-info": true,
			// systemd generators
			"zram-generator": true, "cloud-init-generator": true,
		},

		SilentPrefixes: []string{
			"systemd-", "dbus-", "lima-",
			"gsd-", "gdm-", "gnome-", "xdg-",
			"podman-", "containerd-",
		},
	}
}

// Classify returns the category for an event.
func (c *Classifier) Classify(event Event) EventCategory {
	comm := commFromData(event.Data)
	pid := pidFromData(event.Data)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Self is always silent
	if c.SelfComms[comm] {
		return CategorySilent
	}

	// Commands spawned by our own action executor
	if c.IsOurPID != nil && pid > 0 && c.IsOurPID(pid) {
		return CategorySilent
	}

	// OS internals
	if c.SilentComms[comm] {
		return CategorySilent
	}

	// System daemon prefixes
	for _, prefix := range c.SilentPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return CategorySilent
		}
	}

	// file_open: silence library/locale/cache loads — only interesting for config/sensitive files
	if event.Type == "file_open" {
		filename := filenameFromData(event.Data)
		if isBoringFileOpen(filename) {
			return CategorySilent
		}
	}

	// process_exit: silence exits with code 0 from non-interesting processes
	if event.Type == "process_exit" {
		exitCode := exitCodeFromData(event.Data)
		if exitCode == 0 {
			return CategorySilent
		}
	}

	// Everything else: let the LLM decide
	return CategoryAgent
}

func filenameFromData(data string) string {
	idx := strings.Index(data, `"filename":"`)
	if idx == -1 {
		return ""
	}
	start := idx + len(`"filename":"`)
	end := strings.Index(data[start:], `"`)
	if end == -1 {
		return ""
	}
	return data[start : start+end]
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

// isBoringFileOpen returns true for file opens that are routine OS activity.
func isBoringFileOpen(filename string) bool {
	boringPrefixes := []string{
		"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
		"/usr/share/locale/", "/usr/share/zoneinfo/",
		"/usr/lib/locale/",
		"/proc/", "/sys/", "/dev/",
		"/etc/ld.so", "/etc/nsswitch", "/etc/host",
		"/etc/resolv", "/etc/gai.conf", "/etc/localtime",
	}
	for _, p := range boringPrefixes {
		if strings.HasPrefix(filename, p) {
			return true
		}
	}
	return filename == "" || filename == "." || filename == ".."
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

// Digest collects events for periodic summarization.
type Digest struct {
	mu       sync.Mutex
	events   []Event
	interval time.Duration
}

// NewDigest creates a digest with the given flush interval.
func NewDigest(interval time.Duration) *Digest {
	return &Digest{
		interval: interval,
	}
}

// Add appends an event to the current digest window.
func (d *Digest) Add(event Event) {
	d.mu.Lock()
	d.events = append(d.events, event)
	d.mu.Unlock()
}

// Flush returns all accumulated events and resets the buffer.
func (d *Digest) Flush() []Event {
	d.mu.Lock()
	events := d.events
	d.events = nil
	d.mu.Unlock()
	return events
}
