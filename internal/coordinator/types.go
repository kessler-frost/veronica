package coordinator

import "time"

// Event is an eBPF event received by the coordinator.
type Event struct {
	Type      string // "process_exec", "file_write", "net_connect", etc.
	Resource  string // "pid:4521", "file:/etc/shadow", "ip:185.x.x.x"
	Data      string // raw JSON payload from eBPF
	Timestamp time.Time
}

// Action is something an agent wants to do to the system.
type Action struct {
	Type     string // "shell_exec", "write_file", "kill", "set_cgroup", "write_map", etc.
	Resource string // what resource this touches: "pid:4521", "file:/etc/config", "ip:1.2.3.4"
	Args     string // JSON-encoded type-specific arguments
}

// ActionRequest is sent from a conversation goroutine to the coordinator.
type ActionRequest struct {
	AgentID  string
	Action   Action
	Response chan ActionResult // coordinator sends result back on this channel
}

// ActionResult is the coordinator's response to an action request.
type ActionResult struct {
	Approved bool
	Output   string // result of execution if approved, reason if rejected
	Error    error
}

// Report is an activity update sent to observers (TUI).
type Report struct {
	AgentID   string
	EventType string // "spawned", "action_requested", "action_approved", "action_rejected", "conflict", "completed"
	Detail    string
	Timestamp time.Time
}
