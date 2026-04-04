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
	// CategorySilent — log to buntdb only, no agent.
	CategorySilent EventCategory = iota
	// CategoryPolicy — enforce from eBPF map, no agent.
	CategoryPolicy
	// CategoryImmediate — spawn agent now for this single event.
	CategoryImmediate
	// CategoryProactive — spawn agent to take helpful action.
	CategoryProactive
	// CategoryDigest — include in the next periodic digest.
	CategoryDigest
)

func (c EventCategory) String() string {
	switch c {
	case CategorySilent:
		return "silent"
	case CategoryPolicy:
		return "policy"
	case CategoryImmediate:
		return "immediate"
	case CategoryProactive:
		return "proactive"
	case CategoryDigest:
		return "digest"
	default:
		return "unknown"
	}
}

// Classifier categorizes eBPF events into handling categories.
// Classification rules are stored in maps for easy reconfiguration.
type Classifier struct {
	mu sync.RWMutex

	// SilentComms are commands that never trigger agents.
	SilentComms map[string]bool

	// SilentPrefixes are comm prefixes that never trigger agents.
	SilentPrefixes []string

	// ImmediateComms are commands that always get an immediate agent.
	ImmediateComms map[string]bool

	// ProactiveComms are commands that get a proactive scaffolding/setup agent.
	ProactiveComms map[string]bool

	// ImmediateFiles are file paths that trigger immediate agents when accessed.
	ImmediateFiles map[string]bool

	// SelfComms are Veronica's own process names (always silent).
	SelfComms map[string]bool

	// IsOurPID, if non-nil, returns true for PIDs spawned by the coordinator's
	// action executor. Such events are always silent to prevent feedback loops.
	IsOurPID func(pid uint32) bool
}

// NewClassifier creates a classifier with default rules.
func NewClassifier() *Classifier {
	return &Classifier{
		SelfComms: map[string]bool{
			"veronicad": true,
			"veronica":  true,
		},

		SilentComms: map[string]bool{
			// Shell utilities
			"ls": true, "cat": true, "head": true, "tail": true,
			"wc": true, "stat": true, "ps": true, "grep": true,
			"find": true, "sed": true, "awk": true, "sort": true,
			"uniq": true, "cut": true, "tr": true, "tee": true,
			"xargs": true, "which": true, "whoami": true,
			"hostname": true, "uname": true, "id": true,
			"echo": true, "printf": true, "test": true,
			"[": true, "true": true, "false": true,
			"basename": true, "dirname": true, "realpath": true,
			"readlink": true, "date": true, "sleep": true,
			"env": true, "printenv": true, "expr": true,
			"seq": true, "yes": true, "nproc": true,
			"arch": true, "getconf": true,
			// System daemons (queried frequently)
			"journalctl": true, "systemctl": true,
			"loginctl": true, "timedatectl": true,
			"hostnamectl": true, "localectl": true,
			// Shells (the shell itself, not what it runs)
			"bash": true, "sh": true, "zsh": true, "dash": true,
			// Pagers
			"less": true, "more": true, "pager": true,
			// Editors (opening an editor is not interesting by itself)
			"vim": true, "vi": true, "nano": true, "emacs": true,
		},

		SilentPrefixes: []string{
			"systemd-", "dbus-", "lima-", "ssh-",
			"gsd-", "gdm-", "gnome-", "xdg-",
		},

		ImmediateComms: map[string]bool{
			// Service management
			"nginx": true, "postgres": true, "redis-server": true,
			"mongod": true, "mysqld": true, "httpd": true,
			"containerd": true, "dockerd": true,
			// Security-sensitive
			"sudo": true, "su": true, "passwd": true,
			"chown": true, "chmod": true,
			"useradd": true, "userdel": true, "usermod": true,
			// Network tools
			"iptables": true, "nft": true, "firewall-cmd": true,
			"ss": true, "netstat": true,
		},

		ProactiveComms: map[string]bool{
			// Directory creation (might be a project)
			"mkdir": true,
			// Package/project management
			"git": true, "uv": true, "pip": true, "pip3": true,
			"npm": true, "bun": true, "yarn": true, "pnpm": true,
			"cargo": true, "go": true, "rustup": true,
			"docker": true, "podman": true,
			// Downloading
			"curl": true, "wget": true,
			// Key generation (ssh-keygen fires before ssh- prefix silences it)
			"ssh-keygen": true,
		},

		ImmediateFiles: map[string]bool{
			"/etc/shadow":                true,
			"/etc/passwd":                true,
			"/etc/sudoers":               true,
			"/etc/ssh/sshd_config":       true,
			"/root/.ssh/authorized_keys": true,
			// Config files
			"/etc/nginx/nginx.conf":           true,
			"/etc/nginx/conf.d":               true,
			"/etc/apache2/apache2.conf":       true,
			"/etc/postgresql/postgresql.conf": true,
			"/etc/redis/redis.conf":           true,
			"/etc/docker/daemon.json":         true,
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

	// Commands spawned by our own action executor are always silent
	if c.IsOurPID != nil && pid > 0 && c.IsOurPID(pid) {
		return CategorySilent
	}

	// Check immediate files (for file_open events)
	if event.Type == "file_open" {
		filename := filenameFromData(event.Data)
		if c.ImmediateFiles[filename] {
			return CategoryImmediate
		}
	}

	// Check immediate comms
	if c.ImmediateComms[comm] {
		return CategoryImmediate
	}

	// Check proactive comms
	if c.ProactiveComms[comm] {
		return CategoryProactive
	}

	// Check silent comms
	if c.SilentComms[comm] {
		return CategorySilent
	}

	// Check silent prefixes
	for _, prefix := range c.SilentPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return CategorySilent
		}
	}

	// Unknown commands: if binary is outside standard paths, immediate
	filename := filenameFromData(event.Data)
	if filename != "" && event.Type == "process_exec" {
		if !isStandardPath(filename) {
			return CategoryImmediate
		}
	}

	// Everything else goes to digest
	return CategoryDigest
}

func filenameFromData(data string) string {
	// Quick JSON extraction without full parse
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

func pidFromData(data string) uint32 {
	var payload struct {
		PID uint32 `json:"pid"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return 0
	}
	return payload.PID
}

func isStandardPath(filename string) bool {
	standardPrefixes := []string{
		"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
		"/usr/lib/", "/usr/libexec/",
	}
	for _, p := range standardPrefixes {
		if strings.HasPrefix(filename, p) {
			return true
		}
	}
	return false
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
