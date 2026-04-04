package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fimbulwinter/veronica/internal/state"
)

func TestToolkit_ReadFileRegistered(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	defs := reg.Definitions()
	found := false
	for _, d := range defs {
		if d.Function.Name == "read_file" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected read_file tool to be registered")
	}
}

func TestToolkit_ReadFileExecutes(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	result, err := reg.Call(context.Background(), "read_file", `{"path":"`+testFile+`"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if s != "hello world" {
		t.Fatalf("expected 'hello world', got %q", s)
	}
}

func TestToolkit_RequestActionSendsToChannel(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	go func() {
		req := <-actionCh
		if req.AgentID != "test-agent" {
			t.Errorf("expected agent test-agent, got %s", req.AgentID)
		}
		if req.Action.Type != "shell_exec" {
			t.Errorf("expected shell_exec, got %s", req.Action.Type)
		}
		if req.Action.Args != "systemctl restart nginx" {
			t.Errorf("expected command, got %s", req.Action.Args)
		}
		req.Response <- ActionResult{Approved: true, Output: "done"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"command":"systemctl restart nginx","reason":"restart web server"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if s != "approved: done" {
		t.Fatalf("expected 'approved: done', got %q", s)
	}
}

func TestToolkit_RequestActionRejected(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	go func() {
		req := <-actionCh
		req.Response <- ActionResult{Approved: false, Output: "conflicts with another agent"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"command":"kill -9 1","reason":"kill process"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.(string)
	if s != "rejected: conflicts with another agent" {
		t.Fatalf("unexpected result: %q", s)
	}
}

func TestToolkit_ShellReadAllowlisted(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	result, err := reg.Call(context.Background(), "shell_read", `{"cmd":"echo","args":["hello"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.(string)
	if s != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", s)
	}
}

func TestToolkit_ShellReadBlocksDisallowed(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent", store)

	_, err := reg.Call(context.Background(), "shell_read", `{"cmd":"rm","args":["-rf","/"]}`)
	if err == nil {
		t.Fatal("expected error for disallowed command")
	}
}

func TestToolkit_NewToolsRegistered(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-session", store)
	defs := reg.Definitions()
	names := make(map[string]bool)
	for _, d := range defs {
		names[d.Function.Name] = true
	}
	expected := []string{
		"read_file", "shell_read", "request_action",
		"state_query", "state_write",
		"map_read", "map_write", "map_delete",
		"program_list", "program_load", "program_detach",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected tool %q to be registered", name)
		}
	}
}

func TestToolkit_StateQuery(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	if err := store.SetPolicy("ip", "10.0.0.5", state.Policy{Rule: "block", Value: "true", Reason: "suspicious"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-session", store)
	result, err := reg.Call(context.Background(), "state_query", `{"pattern":"policy:*"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if len(m) == 0 {
		t.Fatal("expected at least one result")
	}
}

func TestToolkit_MapReadStub(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer func() { _ = store.Close() }()
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-session", store)
	_, err := reg.Call(context.Background(), "map_read", `{"map":"connections"}`)
	if err == nil {
		t.Fatal("expected stub error")
	}
}
