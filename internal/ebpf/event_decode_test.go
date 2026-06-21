package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/fimbulwinter/veronica/internal/event"
)

func TestCommString(t *testing.T) {
	tests := []struct {
		name string
		fill string
		want string
	}{
		{"null_terminated", "bash", "bash"},
		{"empty", "", ""},
		{"single_char", "x", "x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h EventHeader
			copy(h.Comm[:], tc.fill)
			if got := h.CommString(); got != tc.want {
				t.Fatalf("CommString() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("no_null_terminator_uses_full_buffer", func(t *testing.T) {
		var h EventHeader
		for i := range h.Comm {
			h.Comm[i] = 'a'
		}
		if got := h.CommString(); len(got) != 64 {
			t.Fatalf("expected full 64-byte string, got len %d", len(got))
		}
	})
}

func TestFilenameString(t *testing.T) {
	tests := []struct {
		name string
		fill string
		want string
	}{
		{"path", "/etc/shadow", "/etc/shadow"},
		{"empty", "", ""},
		{"root", "/", "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b [256]byte
			copy(b[:], tc.fill)
			if got := FilenameString(b); got != tc.want {
				t.Fatalf("FilenameString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestArgsString(t *testing.T) {
	tests := []struct {
		name string
		raw  string // \x00 = null separator, like /proc/pid/cmdline
		want string
	}{
		{"multi_arg", "git\x00commit\x00-m\x00hello\x00", "git commit -m hello"},
		{"single", "ls", "ls"},
		{"empty", "", ""},
		{"trailing_nulls_trimmed", "echo\x00hi\x00\x00\x00", "echo hi"},
		{"leading_null", "\x00a", " a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b [256]byte
			copy(b[:], tc.raw)
			if got := ArgsString(b); got != tc.want {
				t.Fatalf("ArgsString(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// decodePayload runs parseEvent and unmarshals the JSON Data field.
func decodePayload(t *testing.T, raw []byte) (*event.Event, map[string]any) {
	t.Helper()
	m := New(make(chan event.Event, 1))
	ev := m.parseEvent(raw)
	if ev == nil {
		t.Fatal("parseEvent returned nil")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return ev, payload
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	return buf.Bytes()
}

func TestParseEvent_ProcessExit(t *testing.T) {
	e := ProcessExitEvent{ExitCode: 137}
	e.Header.Type = EventProcessExit
	e.Header.PID = 4521
	e.Header.UID = 1000
	copy(e.Header.Comm[:], "nginx")

	ev, payload := decodePayload(t, encode(t, &e))

	if ev.Type != "process_exit" {
		t.Fatalf("type = %q, want process_exit", ev.Type)
	}
	if ev.Resource != "pid:4521" {
		t.Fatalf("resource = %q, want pid:4521", ev.Resource)
	}
	if payload["comm"] != "nginx" {
		t.Fatalf("comm = %v, want nginx", payload["comm"])
	}
	if payload["exit_code"].(float64) != 137 {
		t.Fatalf("exit_code = %v, want 137", payload["exit_code"])
	}
	if payload["uid"].(float64) != 1000 {
		t.Fatalf("uid = %v, want 1000", payload["uid"])
	}
}

func TestParseEvent_FileOpen(t *testing.T) {
	e := FileOpenEvent{Flags: 1}
	e.Header.Type = EventFileOpen
	e.Header.PID = 11
	copy(e.Header.Comm[:], "vim")
	copy(e.Filename[:], "/etc/hosts")

	ev, payload := decodePayload(t, encode(t, &e))

	if ev.Type != "file_open" {
		t.Fatalf("type = %q, want file_open", ev.Type)
	}
	if ev.Resource != "file:/etc/hosts" {
		t.Fatalf("resource = %q, want file:/etc/hosts", ev.Resource)
	}
	if payload["filename"] != "/etc/hosts" {
		t.Fatalf("filename = %v", payload["filename"])
	}
	if payload["flags"].(float64) != 1 {
		t.Fatalf("flags = %v, want 1", payload["flags"])
	}
}

func TestParseEvent_NetConnect(t *testing.T) {
	e := NetConnectEvent{
		// skc_daddr is network byte order; in memory bytes are 01 02 03 04,
		// loaded little-endian then re-split byte-by-byte to "1.2.3.4".
		DAddr:  binary.LittleEndian.Uint32([]byte{1, 2, 3, 4}),
		DPort:  443, // already host-order (kernel side does __builtin_bswap16)
		Family: 2,
	}
	e.Header.Type = EventNetConnect
	e.Header.PID = 7
	copy(e.Header.Comm[:], "curl")

	ev, payload := decodePayload(t, encode(t, &e))

	if ev.Type != "net_connect" {
		t.Fatalf("type = %q, want net_connect", ev.Type)
	}
	if payload["daddr"] != "1.2.3.4" {
		t.Fatalf("daddr = %v, want 1.2.3.4", payload["daddr"])
	}
	if payload["dport"].(float64) != 443 {
		t.Fatalf("dport = %v, want 443", payload["dport"])
	}
	if ev.Resource != "ip:1.2.3.4:443" {
		t.Fatalf("resource = %q, want ip:1.2.3.4:443", ev.Resource)
	}
}

func TestParseEvent_Malformed(t *testing.T) {
	m := New(make(chan event.Event, 1))

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short_for_header_word", []byte{1, 2}},
		{"unknown_event_type", []byte{99, 0, 0, 0}},
		{"valid_type_truncated_body", []byte{1, 0, 0, 0, 5}}, // EventProcessExec but no full struct
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.parseEvent(tc.data); got != nil {
				t.Fatalf("expected nil for %s, got %+v", tc.name, got)
			}
		})
	}
}
