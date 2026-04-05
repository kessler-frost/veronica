package nats

import (
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/fimbulwinter/veronica/internal/classifier"
)

func TestToolExec_EchoSucceeds(t *testing.T) {
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
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
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
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
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
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

// startWithResponders is a shared helper that starts a server and registers all tool responders.
func startWithResponders(t *testing.T) *Server {
	t.Helper()
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	pub := NewPublisher(srv.JS(), classifier.New())
	if err := RegisterToolResponders(srv.Conn(), pub); err != nil {
		srv.Close()
		t.Fatalf("register: %v", err)
	}
	return srv
}

// requestOK sends a NATS request and asserts the response has Ok=true.
func requestOK(t *testing.T, srv *Server, subject string, payload any) ToolResult {
	t.Helper()
	data, _ := json.Marshal(payload)
	msg, err := srv.Conn().Request(subject, data, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subject, err)
	}
	var result ToolResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !result.Ok {
		t.Fatalf("expected ok=true for %s, got error: %s", subject, result.Error)
	}
	return result
}

func TestToolEnforce(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.enforce", EnforceRequest{
		Hook: "file_open", Target: "/etc/shadow", Action: "deny", Reason: "security",
	})
}

func TestToolTransform(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.transform", TransformRequest{
		Interface: "eth0", Match: "192.168.1.1", Rewrite: "10.0.0.1", Reason: "NAT test",
	})
}

func TestToolSchedule(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.schedule", ScheduleRequest{
		Target: "1234", Priority: "latency-sensitive", Reason: "audio process",
	})
}

func TestToolMeasure(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.measure", MeasureRequest{
		Target: "nginx", Metric: "cache_misses", Duration: "5s",
	})
}

func TestToolMapRead(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.map.read", MapReadRequest{Map: "deny_list", Key: "/etc/shadow"})
}

func TestToolMapRead_DumpAll(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	// empty key = dump all
	requestOK(t, srv, "tools.map.read", MapReadRequest{Map: "deny_list"})
}

func TestToolMapWrite(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.map.write", MapWriteRequest{Map: "deny_list", Key: "/etc/shadow", Value: "1"})
}

func TestToolMapDelete(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.map.delete", MapDeleteRequest{Map: "deny_list", Key: "/etc/shadow"})
}

func TestToolProgramList(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.program.list", ProgramListRequest{})
}

func TestToolProgramLoad(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.program.load", ProgramLoadRequest{Name: "xdp_drop"})
}

func TestToolProgramDetach(t *testing.T) {
	srv := startWithResponders(t)
	defer srv.Close()
	requestOK(t, srv, "tools.program.detach", ProgramDetachRequest{Name: "xdp_drop"})
}
