package ebpf

// EventType identifies the kind of eBPF event.
type EventType uint32

const (
	EventProcessExec EventType = 1
	EventFileOpen    EventType = 2
	EventNetConnect  EventType = 3
	EventProcessExit EventType = 4
)

// EventHeader is the common header for all eBPF events.
type EventHeader struct {
	Type      EventType
	PID       uint32
	UID       uint32
	_         uint32 // padding to match C struct
	Timestamp uint64
	Comm      [64]byte
}

// ProcessExecEvent is emitted when a new process starts.
type ProcessExecEvent struct {
	Header   EventHeader
	Filename [256]byte
	Args     [256]byte
}

// ArgsString returns the args as a trimmed string.
// Args are null-separated (like /proc/pid/cmdline), converted to spaces.
func ArgsString(b [256]byte) string {
	// Find the last non-null byte
	end := 0
	for i, c := range b {
		if c != 0 {
			end = i + 1
		}
	}
	// Replace nulls with spaces
	result := make([]byte, end)
	for i := range end {
		if b[i] == 0 {
			result[i] = ' '
		} else {
			result[i] = b[i]
		}
	}
	return string(result)
}

// FileOpenEvent is emitted when a file is opened.
type FileOpenEvent struct {
	Header   EventHeader
	Filename [256]byte
	Flags    int32
	_        uint32 // padding
}

// NetConnectEvent is emitted when a TCP connection is initiated.
type NetConnectEvent struct {
	Header EventHeader
	DAddr  uint32
	DPort  uint16
	Family uint16
}

// ProcessExitEvent is emitted when a process exits.
type ProcessExitEvent struct {
	Header   EventHeader
	ExitCode int32
	_        uint32 // padding
}

// CommString returns the command name as a trimmed string.
func (h *EventHeader) CommString() string {
	for i, b := range h.Comm {
		if b == 0 {
			return string(h.Comm[:i])
		}
	}
	return string(h.Comm[:])
}

// FilenameString returns a null-terminated byte array as a trimmed string.
func FilenameString(b [256]byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b[:])
}
