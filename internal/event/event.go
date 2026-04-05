package event

import (
	"time"

	json "github.com/goccy/go-json"
)

// Event is an eBPF event received from the kernel.
type Event struct {
	Type      string // "process_exec", "process_exit", "file_open", "net_connect"
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

// FlagsFromData extracts the flags field from an Event.Data JSON string.
func FlagsFromData(data string) int32 {
	var payload struct {
		Flags int32 `json:"flags"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return 0
	}
	return payload.Flags
}

// IsWriteOpen returns true if open flags indicate writing (O_WRONLY=1 or O_RDWR=2).
func IsWriteOpen(flags int32) bool {
	return flags&0x3 != 0 // O_WRONLY (1) or O_RDWR (2)
}
