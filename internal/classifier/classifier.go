package classifier

import (
	"strings"
	"sync"

	"github.com/fimbulwinter/veronica/internal/event"
)

// EventCategory determines whether the daemon publishes an event.
type EventCategory int

const (
	// CategorySilent — drop entirely, never reaches NATS.
	CategorySilent EventCategory = iota
	// CategoryPass — publish to NATS, agents decide what to do.
	CategoryPass
)

func (c EventCategory) String() string {
	switch c {
	case CategorySilent:
		return "silent"
	case CategoryPass:
		return "pass"
	default:
		return "unknown"
	}
}

// Classifier filters daemon/self noise at the kernel boundary.
// Agent-side whitelist filters handle all domain-specific filtering.
type Classifier struct {
	mu sync.RWMutex

	// SelfComms are Veronica's own process names.
	SelfComms map[string]bool

	// SilentPrefixes are comm prefixes for system daemons.
	SilentPrefixes []string

	// SilentComms are individual commands that are never user activity.
	SilentComms map[string]bool

	// IsOurPID returns true for PIDs spawned by the action executor.
	IsOurPID func(pid uint32) bool
}

// New creates a classifier with minimal self/daemon rules.
func New() *Classifier {
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

		SilentComms: map[string]bool{
			"sshd": true, "login": true, "agetty": true,
		},
	}
}

// Classify returns whether an event should be published or dropped.
func (c *Classifier) Classify(e event.Event) EventCategory {
	comm := event.CommFromData(e.Data)
	pid := event.PidFromData(e.Data)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Self or always-silent comms
	if c.SelfComms[comm] || c.SilentComms[comm] {
		return CategorySilent
	}

	// Our own child processes (feedback loop prevention)
	if c.IsOurPID != nil && pid > 0 && c.IsOurPID(pid) {
		return CategorySilent
	}

	// System daemon prefixes
	for _, prefix := range c.SilentPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return CategorySilent
		}
	}

	return CategoryPass
}
