package ws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/tool"
	"github.com/fimbulwinter/veronica/internal/ws"
)

func testToolkitFactory(sessionID string) *tool.Registry {
	reg := tool.NewRegistry()
	type echoArgs struct {
		Msg string `json:"msg" desc:"Message to echo"`
	}
	tool.Register(reg, "echo", "Echo a message", func(ctx context.Context, args echoArgs) (any, error) {
		return "echo: " + args.Msg, nil
	})
	return reg
}

// startTestServer creates and starts a server bound to ":0" and returns its address.
func startTestServer(t *testing.T, ctx context.Context) *ws.Server {
	t.Helper()
	srv := ws.NewServer(":0", testToolkitFactory)
	go func() {
		if err := srv.Start(ctx); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()
	// Wait for listener to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Addr() != ":0" && srv.Addr() != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return srv
}

// agentClient wraps a websocket connection for test helpers.
type agentClient struct {
	conn *websocket.Conn
}

// connectAgent dials the server and sends a subscribe message.
func connectAgent(t *testing.T, ctx context.Context, addr, agentID string, events []string) *agentClient {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, "ws://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	sub := map[string]any{
		"type":     "subscribe",
		"agent_id": agentID,
		"events":   events,
	}
	data, _ := json.Marshal(sub)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("subscribe write: %v", err)
	}
	return &agentClient{conn: conn}
}

func (a *agentClient) readMsg(ctx context.Context) (map[string]json.RawMessage, error) {
	_, data, err := a.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (a *agentClient) send(ctx context.Context, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return a.conn.Write(ctx, websocket.MessageText, data)
}

func (a *agentClient) close() {
	_ = a.conn.Close(websocket.StatusNormalClosure, "done")
}

func testEvent(eventType string) coordinator.Event {
	return coordinator.Event{
		Type:      eventType,
		Resource:  "pid:1234",
		Data:      `{"comm":"test","pid":1234}`,
		Timestamp: time.Now(),
	}
}

// waitFor polls a condition until it's true or timeout expires.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestServer_AgentConnectsAndSubscribes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)

	ac := connectAgent(t, ctx, srv.Addr(), "agent-1", []string{"net_connect"})
	defer ac.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 1
	})

	if got := srv.ConnectedAgents(); got != 1 {
		t.Errorf("ConnectedAgents() = %d, want 1", got)
	}
}

func TestServer_RouteEventToSubscribedAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	ac := connectAgent(t, ctx, srv.Addr(), "agent-2", []string{"net_connect"})
	defer ac.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 1
	})

	event := testEvent("net_connect")
	srv.RouteEvent(ctx, event, coordinator.CategoryUrgent)

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()

	msg, err := ac.readMsg(readCtx)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}

	var msgType string
	if err := json.Unmarshal(msg["type"], &msgType); err != nil {
		t.Fatalf("unmarshal type: %v", err)
	}
	if msgType != "event" {
		t.Errorf("msg type = %q, want %q", msgType, "event")
	}

	if _, ok := msg["session"]; !ok {
		t.Error("missing session field in event message")
	}
}

func TestServer_EventNotRoutedToUnsubscribed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	// subscribe to file_open, but route net_connect
	ac := connectAgent(t, ctx, srv.Addr(), "agent-3", []string{"file_open"})
	defer ac.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 1
	})

	event := testEvent("net_connect")
	srv.RouteEvent(ctx, event, coordinator.CategoryBatch)

	// Give a short window — no message should arrive
	readCtx, readCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer readCancel()

	_, err := ac.readMsg(readCtx)
	if err == nil {
		t.Error("expected no message but received one")
	}
}

func TestServer_ToolCallAndResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	ac := connectAgent(t, ctx, srv.Addr(), "agent-4", []string{"process_exec"})
	defer ac.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 1
	})

	event := testEvent("process_exec")
	srv.RouteEvent(ctx, event, coordinator.CategoryUrgent)

	// Read the event message to get the session ID
	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()

	eventRaw, err := ac.readMsg(readCtx)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}

	var sessionID string
	if err := json.Unmarshal(eventRaw["session"], &sessionID); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}

	// Send a tool_call
	toolCall := map[string]any{
		"type":    "tool_call",
		"session": sessionID,
		"call_id": "call-1",
		"name":    "echo",
		"args":    json.RawMessage(`{"msg":"hello"}`),
	}
	if err := ac.send(ctx, toolCall); err != nil {
		t.Fatalf("send tool_call: %v", err)
	}

	// Read the tool_result
	resultRaw, err := ac.readMsg(readCtx)
	if err != nil {
		t.Fatalf("read tool_result: %v", err)
	}

	var msgType string
	if err := json.Unmarshal(resultRaw["type"], &msgType); err != nil {
		t.Fatalf("unmarshal type: %v", err)
	}
	if msgType != "tool_result" {
		t.Errorf("msg type = %q, want %q", msgType, "tool_result")
	}

	var result string
	if err := json.Unmarshal(resultRaw["result"], &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result != "echo: hello" {
		t.Errorf("result = %q, want %q", result, "echo: hello")
	}
}

func TestServer_SessionDoneCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	ac := connectAgent(t, ctx, srv.Addr(), "agent-5", []string{"file_write"})
	defer ac.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 1
	})

	event := testEvent("file_write")
	srv.RouteEvent(ctx, event, coordinator.CategoryBatch)

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()

	eventRaw, err := ac.readMsg(readCtx)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}

	var sessionID string
	if err := json.Unmarshal(eventRaw["session"], &sessionID); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}

	// Active session should exist
	waitFor(t, time.Second, func() bool {
		return srv.ActiveSessions() == 1
	})

	// Send session_done
	done := map[string]any{
		"type":    "session_done",
		"session": sessionID,
	}
	if err := ac.send(ctx, done); err != nil {
		t.Fatalf("send session_done: %v", err)
	}

	// Session should be cleaned up
	waitFor(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == 0
	})

	if got := srv.ActiveSessions(); got != 0 {
		t.Errorf("ActiveSessions() = %d after session_done, want 0", got)
	}
}

func TestServer_FanOutToMultipleAgents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)

	ac1 := connectAgent(t, ctx, srv.Addr(), "agent-6a", []string{"net_connect"})
	defer ac1.close()
	ac2 := connectAgent(t, ctx, srv.Addr(), "agent-6b", []string{"net_connect"})
	defer ac2.close()

	waitFor(t, 2*time.Second, func() bool {
		return srv.ConnectedAgents() == 2
	})

	event := testEvent("net_connect")
	srv.RouteEvent(ctx, event, coordinator.CategoryUrgent)

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()

	// Both agents should receive the event
	msg1, err := ac1.readMsg(readCtx)
	if err != nil {
		t.Fatalf("agent-6a read: %v", err)
	}
	msg2, err := ac2.readMsg(readCtx)
	if err != nil {
		t.Fatalf("agent-6b read: %v", err)
	}

	var session1, session2 string
	if err := json.Unmarshal(msg1["session"], &session1); err != nil {
		t.Fatalf("unmarshal session1: %v", err)
	}
	if err := json.Unmarshal(msg2["session"], &session2); err != nil {
		t.Fatalf("unmarshal session2: %v", err)
	}

	if session1 == session2 {
		t.Errorf("expected different session IDs for fan-out, both got %q", session1)
	}
	fmt.Printf("fan-out: agent1 session=%s, agent2 session=%s\n", session1, session2)
}
