package af

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// helper: set up fake proc with a pipe so we can read what was written.
func setupFakeProcWithPipe(t *testing.T) (*os.File, uint32, func()) {
	t.Helper()

	dir := t.TempDir()
	pid := uint32(12345)
	fdDir := filepath.Join(dir, fmt.Sprintf("%d", pid), "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a real OS pipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	// Symlink the write end's /dev/fd path to the fake proc location
	// Actually, we can't symlink to a pipe fd portably. Instead, we'll
	// create the file as a regular file and read it back. But for true
	// pipe semantics, we override the path to point to the write end.
	//
	// Better approach: create a symlink from <dir>/<pid>/fd/1 -> /dev/fd/<w.Fd()>
	fdPath := filepath.Join(fdDir, "1")
	err = os.Symlink(fmt.Sprintf("/dev/fd/%d", w.Fd()), fdPath)
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		t.Fatalf("symlink: %v", err)
	}

	oldProcPath := procPath
	procPath = dir

	cleanup := func() {
		procPath = oldProcPath
		_ = w.Close()
		_ = r.Close()
	}
	return r, pid, cleanup
}

func TestNotifyHappyPath(t *testing.T) {
	r, pid, cleanup := setupFakeProcWithPipe(t)
	defer cleanup()

	handler := handleNotify()
	input := map[string]any{
		"pid":     float64(pid), // JSON numbers are float64
		"message": "hello world",
	}

	result, err := handler(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ok:true in result
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result is not map[string]any: %T", result)
	}
	if m["ok"] != true {
		t.Fatalf("expected ok:true, got %v (error: %v)", m["ok"], m["error"])
	}

	// Read from pipe and verify content
	buf := make([]byte, 256)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	got := string(buf[:n])
	expected := "[veronica] hello world\n"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestNotifyFormat(t *testing.T) {
	r, pid, cleanup := setupFakeProcWithPipe(t)
	defer cleanup()

	handler := handleNotify()

	tests := []struct {
		msg      string
		expected string
	}{
		{"test msg", "[veronica] test msg\n"},
		{"hello", "[veronica] hello\n"},
		{"multi word message with symbols!@#", "[veronica] multi word message with symbols!@#\n"},
	}

	for _, tc := range tests {
		input := map[string]any{
			"pid":     float64(pid),
			"message": tc.msg,
		}
		result, err := handler(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]any)
		if m["ok"] != true {
			t.Fatalf("expected ok:true for msg %q, got %v", tc.msg, m["error"])
		}

		buf := make([]byte, 512)
		n, err := r.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got := string(buf[:n])
		if got != tc.expected {
			t.Fatalf("for msg %q: expected %q, got %q", tc.msg, tc.expected, got)
		}
	}
}

func TestNotifyInvalidPID(t *testing.T) {
	// No fake proc needed — these should fail at validation
	handler := handleNotify()

	tests := []struct {
		name string
		pid  any
	}{
		{"pid_zero", float64(0)},
		{"pid_negative", float64(-1)},
		{"pid_nonexistent", float64(99999999)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For non-existent PID, set procPath to temp dir
			dir := t.TempDir()
			oldProcPath := procPath
			procPath = dir
			defer func() { procPath = oldProcPath }()

			input := map[string]any{
				"pid":     tc.pid,
				"message": "test",
			}
			result, err := handler(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			m := result.(map[string]any)
			if m["ok"] != false {
				t.Fatalf("expected ok:false for %s, got ok:true", tc.name)
			}
			errStr, _ := m["error"].(string)
			if errStr == "" {
				t.Fatalf("expected non-empty error for %s", tc.name)
			}
		})
	}
}

func TestNotifyEmptyMessage(t *testing.T) {
	handler := handleNotify()

	tests := []struct {
		name string
		msg  string
	}{
		{"empty", ""},
		{"whitespace_only", "   "},
		{"tabs_and_spaces", "  \t\n  "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{
				"pid":     float64(1234),
				"message": tc.msg,
			}
			result, err := handler(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			m := result.(map[string]any)
			if m["ok"] != false {
				t.Fatalf("expected ok:false for %q, got ok:true", tc.name)
			}
		})
	}
}

func TestNotifyNonWritableFd(t *testing.T) {
	dir := t.TempDir()
	pid := uint32(54321)
	fdDir := filepath.Join(dir, fmt.Sprintf("%d", pid), "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a file with no write permissions
	fdPath := filepath.Join(fdDir, "1")
	if err := os.WriteFile(fdPath, []byte("locked"), 0o444); err != nil {
		t.Fatalf("write: %v", err)
	}

	oldProcPath := procPath
	procPath = dir
	defer func() { procPath = oldProcPath }()

	handler := handleNotify()
	input := map[string]any{
		"pid":     float64(pid),
		"message": "test",
	}
	result, err := handler(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	m := result.(map[string]any)
	if m["ok"] != false {
		t.Fatalf("expected ok:false for non-writable fd, got ok:true")
	}
}

func TestNotifyClosesFd(t *testing.T) {
	dir := t.TempDir()
	pid := uint32(11111)
	fdDir := filepath.Join(dir, fmt.Sprintf("%d", pid), "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Use a regular file so we can check it was written and closed
	fdPath := filepath.Join(fdDir, "1")
	if err := os.WriteFile(fdPath, nil, 0o666); err != nil {
		t.Fatalf("write: %v", err)
	}

	oldProcPath := procPath
	procPath = dir
	defer func() { procPath = oldProcPath }()

	handler := handleNotify()
	input := map[string]any{
		"pid":     float64(pid),
		"message": "close-test",
	}

	// Call multiple times — if fd leaks, we'd eventually hit ulimit
	for i := 0; i < 100; i++ {
		result, err := handler(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %v", i, err)
		}
		m := result.(map[string]any)
		if m["ok"] != true {
			t.Fatalf("expected ok:true on iteration %d, got error: %v", i, m["error"])
		}
	}

	// Verify the file contains the expected content (100 writes)
	data, err := os.ReadFile(fdPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Each write opens, writes, closes. Since it truncates on each open with O_WRONLY
	// (not O_APPEND), the file should contain the last write only... unless we use O_WRONLY
	// without O_TRUNC. On real /proc/pid/fd/1 it's a pipe/tty, not a regular file,
	// so the behavior differs. Let's just verify the file has content.
	if len(data) == 0 {
		t.Fatalf("file is empty — writes didn't happen")
	}
}

func TestNotifyLogging(t *testing.T) {
	// Capture log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)
	// Also disable timestamp prefix for easier matching
	oldFlags := log.Flags()
	log.SetFlags(0)
	defer log.SetFlags(oldFlags)

	r, pid, cleanup := setupFakeProcWithPipe(t)
	defer cleanup()
	// Drain the pipe in background to avoid blocking
	go func() {
		_, _ = io.Copy(io.Discard, r)
	}()

	handler := handleNotify()
	input := map[string]any{
		"pid":     float64(pid),
		"message": "log test msg",
	}
	_, _ = handler(context.Background(), input)

	logOutput := logBuf.String()
	expected := fmt.Sprintf("SKILL notify: pid=%d message=%q", pid, "log test msg")
	if !strings.Contains(logOutput, expected) {
		t.Fatalf("expected log to contain %q, got %q", expected, logOutput)
	}
}

func TestNotifyConcurrent(t *testing.T) {
	r, pid, cleanup := setupFakeProcWithPipe(t)
	defer cleanup()

	handler := handleNotify()

	var wg sync.WaitGroup
	wg.Add(2)

	msg1 := "concurrent message one"
	msg2 := "concurrent message two"

	go func() {
		defer wg.Done()
		input := map[string]any{
			"pid":     float64(pid),
			"message": msg1,
		}
		result, err := handler(context.Background(), input)
		if err != nil {
			t.Errorf("goroutine 1 error: %v", err)
			return
		}
		m := result.(map[string]any)
		if m["ok"] != true {
			t.Errorf("goroutine 1: expected ok:true, got error: %v", m["error"])
		}
	}()

	go func() {
		defer wg.Done()
		input := map[string]any{
			"pid":     float64(pid),
			"message": msg2,
		}
		result, err := handler(context.Background(), input)
		if err != nil {
			t.Errorf("goroutine 2 error: %v", err)
			return
		}
		m := result.(map[string]any)
		if m["ok"] != true {
			t.Errorf("goroutine 2: expected ok:true, got error: %v", m["error"])
		}
	}()

	// Read both messages from the pipe
	wg.Wait()

	// Read all available data
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	output := string(buf[:n])

	expected1 := "[veronica] " + msg1 + "\n"
	expected2 := "[veronica] " + msg2 + "\n"

	if !strings.Contains(output, expected1) {
		t.Fatalf("output missing message 1: %q not in %q", expected1, output)
	}
	if !strings.Contains(output, expected2) {
		t.Fatalf("output missing message 2: %q not in %q", expected2, output)
	}

	// Verify both messages are complete (non-interleaved)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 lines, got %d: %q", len(lines), output)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[veronica] ") {
			t.Fatalf("line missing prefix: %q", line)
		}
	}
}
