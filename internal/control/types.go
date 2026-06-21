// Package control is the host-testable core of veronica's kernel control plane:
// the vetted eBPF-LSM primitive catalog, the audit-first policy lifecycle, the
// pure app resolver, and the observation aggregator. Kernel-touching code
// (eBPF load/attach, /proc + cgroup reads) lives behind VM-gated build tags and
// drives these pure cores with real data.
package control

import "time"

// Mode is a policy's enforcement mode. New policies are always created in
// ModeAudit; ModeEnforce is reachable only via PolicyStore.SetMode.
type Mode string

const (
	// ModeAudit logs would-block events without denying anything.
	ModeAudit Mode = "audit"
	// ModeEnforce denies the operation (kernel returns -EPERM).
	ModeEnforce Mode = "enforce"
)

// AppRef identifies a resolved application: its name, the common cgroup v2 path
// of its process tree, and the live PIDs that belong to it.
type AppRef struct {
	Name       string `json:"name"`
	CgroupPath string `json:"cgroup_path"`
	PIDs       []int  `json:"pids"`
}

// Primitive is one entry in the vetted enforcement catalog. Params is the JSON
// Schema (draft-style subset) that a policy's params must satisfy. Hooks names
// the LSM hook(s) the primitive attaches to.
type Primitive struct {
	ID     string         `json:"id"`
	Desc   string         `json:"desc"`
	Params map[string]any `json:"params"`
	Hooks  []string       `json:"hooks"`
}

// Policy is an applied primitive scoped to an app. AuditCount is the number of
// would-block events seen while in audit mode.
type Policy struct {
	ID          string         `json:"id"`
	PrimitiveID string         `json:"primitive_id"`
	Params      map[string]any `json:"params"`
	Mode        Mode           `json:"mode"`
	App         AppRef         `json:"app"`
	AuditCount  int            `json:"audit_count"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Activity is a windowed snapshot of one app's kernel activity, grouped by kind.
type Activity struct {
	App    string       `json:"app"`
	Window int          `json:"window"` // seconds
	Files  []FileEvent  `json:"files"`
	Net    []NetEvent   `json:"net"`
	Execs  []ExecEvent  `json:"execs"`
	Mounts []MountEvent `json:"mounts"`
}

// FileEvent is a grouped file access (e.g. write to a path), with a repeat count.
type FileEvent struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
	Count int    `json:"count"`
}

// NetEvent is a grouped outbound connection, with a repeat count.
type NetEvent struct {
	DestAddr string `json:"dest_addr"`
	DestPort int    `json:"dest_port"`
	Count    int    `json:"count"`
}

// ExecEvent is a grouped program execution, with a repeat count.
type ExecEvent struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// MountEvent is a grouped mount operation, with a repeat count.
type MountEvent struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Count  int    `json:"count"`
}

// EventKind tags a raw Event by the kind of activity it represents.
type EventKind string

const (
	KindFile  EventKind = "file"
	KindNet   EventKind = "net"
	KindExec  EventKind = "exec"
	KindMount EventKind = "mount"
)

// Event is a single raw kernel-sourced activity record fed into the Aggregator.
// The fields used depend on Kind; the eBPF event source (VM-gated) fills these.
type Event struct {
	Kind EventKind
	At   time.Time

	// File
	Path  string
	Write bool

	// Net
	DestAddr string
	DestPort int

	// Exec — uses Path

	// Mount
	Source string
	Target string
}

// ProcInfo is one process's identity, supplied to MatchApp by the caller. Real
// data is read from /proc + cgroup in the VM (Task 10); the resolver core is
// pure so it stays host-testable.
type ProcInfo struct {
	PID        int
	Comm       string
	CgroupPath string
}
