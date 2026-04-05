package event

import (
	"time"

	json "github.com/goccy/go-json"
)

// Event is an eBPF event received from the kernel.
type Event struct {
	Type      string // "process_exec", "file_write", "net_connect", etc.
	Resource  string // "pid:4521", "file:/etc/shadow", "ip:185.x.x.x"
	Data      string // raw JSON payload from eBPF
	Timestamp time.Time
}

// CommFromData extracts the comm field from an Event.Data JSON string.
func CommFromData(data string) string {
	var payload struct {
		Comm string `json:"comm"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Comm
}

// PidFromData extracts the pid field from an Event.Data JSON string.
func PidFromData(data string) uint32 {
	var payload struct {
		PID uint32 `json:"pid"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return 0
	}
	return payload.PID
}

// FilenameFromData extracts the filename field from an Event.Data JSON string.
func FilenameFromData(data string) string {
	var payload struct {
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Filename
}
