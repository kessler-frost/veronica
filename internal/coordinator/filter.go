package coordinator

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const rateLimitWindow = 5 * time.Second

// noiseComms is the set of comm names that should never spawn agents.
var noiseComms = map[string]bool{
	"veronica":   true, // self
	"ls":         true,
	"cat":        true,
	"head":       true,
	"tail":       true,
	"wc":         true,
	"stat":       true,
	"ps":         true,
	"grep":       true,
	"find":       true,
	"sed":        true,
	"awk":        true,
	"sort":       true,
	"uniq":       true,
	"cut":        true,
	"tr":         true,
	"tee":        true,
	"xargs":      true,
	"which":      true,
	"whoami":     true,
	"hostname":   true,
	"uname":      true,
	"id":         true,
	"echo":       true,
	"printf":     true,
	"test":       true,
	"[":          true,
	"true":       true,
	"false":      true,
	"basename":   true,
	"dirname":    true,
	"realpath":   true,
	"readlink":   true,
	"date":       true,
	"sleep":      true,
	"journalctl": true,
	"systemctl":  true,
}

// noisePrefixes lists prefixes of comm names that are always noise.
var noisePrefixes = []string{
	"systemd-",
	"dbus-",
	"lima-",
	"ssh-",
}

// Filter decides whether an event should spawn an agent.
type Filter struct {
	mu          sync.Mutex
	lastSeen    map[string]time.Time // resource -> last event time
	activeCount atomic.Int32
	maxActive   int32
}

// NewFilter creates a Filter that allows at most maxActive concurrent agents.
func NewFilter(maxActive int) *Filter {
	return &Filter{
		lastSeen:  make(map[string]time.Time),
		maxActive: int32(maxActive),
	}
}

// ShouldProcess returns true if the event should spawn an agent.
func (f *Filter) ShouldProcess(event Event) bool {
	comm := commFromData(event.Data)

	if isNoise(comm) {
		return false
	}

	f.mu.Lock()
	last, seen := f.lastSeen[event.Resource]
	now := time.Now()
	if seen && now.Sub(last) < rateLimitWindow {
		f.mu.Unlock()
		return false
	}
	f.lastSeen[event.Resource] = now
	f.mu.Unlock()

	if f.activeCount.Load() >= f.maxActive {
		log.Printf("filter: max concurrent agents (%d) reached, dropping event %s on %s", f.maxActive, event.Type, event.Resource)
		return false
	}

	return true
}

// AgentStarted increments the active agent count.
func (f *Filter) AgentStarted() {
	f.activeCount.Add(1)
}

// AgentFinished decrements the active agent count.
func (f *Filter) AgentFinished() {
	f.activeCount.Add(-1)
}

// commFromData extracts the "comm" field from a JSON data payload.
// Returns an empty string if the payload is not valid JSON or has no comm field.
func commFromData(data string) string {
	var payload struct {
		Comm string `json:"comm"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Comm
}

// isNoise reports whether a comm name should be filtered out unconditionally.
func isNoise(comm string) bool {
	if noiseComms[comm] {
		return true
	}
	for _, prefix := range noisePrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	return false
}
