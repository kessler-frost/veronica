package nats

import (
	"encoding/json"
	"testing"
	"time"
)

func TestToolExec_EchoSucceeds(t *testing.T) {
	srv, err := Start(Config{Port: 0, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	if err := RegisterToolResponders(srv.Conn(), nil); err != nil {
		t.Fatalf("register: %v", err)
	}

	req, _ := json.Marshal(ExecRequest{Command: "echo hello"})
	msg, err := srv.Conn().Request("tools.exec", req, 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	var result ToolResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !result.Ok {
		t.Fatalf("expected ok=true, got error: %s", result.Error)
	}
	if result.Data != "hello" {
		t.Fatalf("expected data=%q, got %q", "hello", result.Data)
	}
}

func TestToolExec_DangerousCommandBlocked(t *testing.T) {
	srv, err := Start(Config{Port: 0, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	if err := RegisterToolResponders(srv.Conn(), nil); err != nil {
		t.Fatalf("register: %v", err)
	}

	req, _ := json.Marshal(ExecRequest{Command: "rm -rf /"})
	msg, err := srv.Conn().Request("tools.exec", req, 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	var result ToolResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Ok {
		t.Fatal("expected ok=false for dangerous command")
	}
	if result.Error == "" || result.Error[:6] != "DENIED" {
		t.Fatalf("expected DENIED error, got: %s", result.Error)
	}
}

func TestToolExec_BadJSONReturnsError(t *testing.T) {
	srv, err := Start(Config{Port: 0, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	if err := RegisterToolResponders(srv.Conn(), nil); err != nil {
		t.Fatalf("register: %v", err)
	}

	msg, err := srv.Conn().Request("tools.exec", []byte("not json at all"), 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	var result ToolResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Ok {
		t.Fatal("expected ok=false for bad JSON")
	}
	if result.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}
