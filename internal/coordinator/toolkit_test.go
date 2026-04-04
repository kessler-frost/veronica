package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestToolkit_ReadFileRegistered(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

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
	os.WriteFile(testFile, []byte("hello world"), 0644)

	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

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
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	go func() {
		req := <-actionCh
		if req.AgentID != "test-agent" {
			t.Errorf("expected agent test-agent, got %s", req.AgentID)
		}
		if req.Action.Type != "shell_exec" {
			t.Errorf("expected shell_exec, got %s", req.Action.Type)
		}
		req.Response <- ActionResult{Approved: true, Output: "done"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"type":"shell_exec","resource":"pid:123","args":"{\"cmd\":\"systemctl restart nginx\"}"}`)
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
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	go func() {
		req := <-actionCh
		req.Response <- ActionResult{Approved: false, Output: "conflicts with another agent"}
	}()

	result, err := reg.Call(context.Background(), "request_action", `{"type":"kill","resource":"pid:1","args":"{}"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.(string)
	if s != "rejected: conflicts with another agent" {
		t.Fatalf("unexpected result: %q", s)
	}
}

func TestToolkit_ShellReadAllowlisted(t *testing.T) {
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

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
	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-agent")

	_, err := reg.Call(context.Background(), "shell_read", `{"cmd":"rm","args":["-rf","/"]}`)
	if err == nil {
		t.Fatal("expected error for disallowed command")
	}
}
