package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/fimbulwinter/veronica/internal/event"
)

// writeFakeStat creates a fake /proc/<pid>/stat file under baseDir.
func writeFakeStat(t *testing.T, baseDir string, pid int, content string) {
	t.Helper()
	dir := filepath.Join(baseDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
}

func TestReadPPID(t *testing.T) {
	origBase := procBasePath
	t.Cleanup(func() { procBasePath = origBase })

	t.Run("correct parsing", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		// Normal stat line: pid (comm) state ppid ...
		writeFakeStat(t, dir, 1234, "1234 (bash) S 5678 1234 1234 0 -1 4194560 100 0 0 0")
		got := readPPID(1234)
		if got != 5678 {
			t.Fatalf("expected ppid 5678, got %d", got)
		}
	})

	t.Run("comm with spaces", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		writeFakeStat(t, dir, 2000, "2000 (Web Content) S 1999 2000 2000 0 -1 4194560 50 0 0 0")
		got := readPPID(2000)
		if got != 1999 {
			t.Fatalf("expected ppid 1999, got %d", got)
		}
	})

	t.Run("comm with parentheses", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		writeFakeStat(t, dir, 3000, "3000 (foo (bar) baz) S 2999 3000 3000 0 -1 4194560 50 0 0 0")
		got := readPPID(3000)
		if got != 2999 {
			t.Fatalf("expected ppid 2999, got %d", got)
		}
	})

	t.Run("non-existent PID returns 0", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		got := readPPID(99999999)
		if got != 0 {
			t.Fatalf("expected 0 for non-existent PID, got %d", got)
		}
	})

	t.Run("kernel PID 1", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		// PID 1 (init/systemd) has PPID 0
		writeFakeStat(t, dir, 1, "1 (systemd) S 0 1 1 0 -1 4194560 100 0 0 0")
		got := readPPID(1)
		if got != 0 {
			t.Fatalf("expected ppid 0 for kernel PID 1, got %d", got)
		}
	})

	t.Run("malformed stat file", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		writeFakeStat(t, dir, 4000, "garbage data")
		got := readPPID(4000)
		if got != 0 {
			t.Fatalf("expected 0 for malformed stat, got %d", got)
		}
	})

	t.Run("truncated stat after comm", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		writeFakeStat(t, dir, 5000, "5000 (bash)")
		got := readPPID(5000)
		if got != 0 {
			t.Fatalf("expected 0 for truncated stat, got %d", got)
		}
	})

	t.Run("only state no ppid", func(t *testing.T) {
		dir := t.TempDir()
		procBasePath = dir
		writeFakeStat(t, dir, 6000, "6000 (bash) S")
		got := readPPID(6000)
		if got != 0 {
			t.Fatalf("expected 0 for stat with only state, got %d", got)
		}
	})
}

func TestProcessExecPayloadContainsPPID(t *testing.T) {
	origBase := procBasePath
	t.Cleanup(func() { procBasePath = origBase })

	dir := t.TempDir()
	procBasePath = dir

	// Create a fake /proc entry for the PID we'll encode in the event
	var pid uint32 = 42
	var expectedPPID uint32 = 100
	writeFakeStat(t, dir, int(pid), fmt.Sprintf("42 (test) S %d 42 42 0 -1 4194560 10 0 0 0", expectedPPID))

	// Also create fake cwd symlink (readCwd uses Readlink, which won't work with files,
	// so cwd will be empty — that's fine, we're testing ppid)

	// Build a binary ProcessExecEvent
	e := ProcessExecEvent{}
	e.Header.Type = EventProcessExec
	e.Header.PID = pid
	e.Header.UID = 1000
	copy(e.Header.Comm[:], "test")
	copy(e.Filename[:], "/usr/bin/test")
	copy(e.Args[:], "test\x00--flag")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &e); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	// Create a manager with a dummy event channel
	ch := make(chan event.Event, 1)
	m := New(ch)

	result := m.parseEvent(buf.Bytes())
	if result == nil {
		t.Fatal("parseEvent returned nil")
	}

	if result.Type != "process_exec" {
		t.Fatalf("expected type process_exec, got %s", result.Type)
	}

	// Unmarshal the JSON payload
	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Verify ppid is present and correct
	ppidVal, ok := payload["ppid"]
	if !ok {
		t.Fatal("ppid key missing from payload")
	}

	// JSON numbers unmarshal to float64 by default
	ppidFloat, ok := ppidVal.(float64)
	if !ok {
		t.Fatalf("ppid is not a number, got %T: %v", ppidVal, ppidVal)
	}
	if uint32(ppidFloat) != expectedPPID {
		t.Fatalf("expected ppid %d, got %d", expectedPPID, uint32(ppidFloat))
	}

	// Verify existing fields are still present
	for _, key := range []string{"comm", "filename", "uid", "pid", "cmdline", "cwd"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("expected key %q in payload", key)
		}
	}

	// Verify ppid survives JSON round-trip as a number (not string)
	reEncoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	rtPPID, ok := roundTripped["ppid"].(float64)
	if !ok {
		t.Fatal("ppid did not survive round-trip as number")
	}
	if uint32(rtPPID) != expectedPPID {
		t.Fatalf("ppid changed after round-trip: got %d, want %d", uint32(rtPPID), expectedPPID)
	}
}
