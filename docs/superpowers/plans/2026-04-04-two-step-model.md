# Two-Step Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split Veronica from a monolithic Go daemon into a thin Go eBPF daemon (VM) + Python host agents connected via WebSocket.

**Architecture:** Go daemon becomes a WebSocket tool server exposing eBPF and state operations. Python agents on the host connect, subscribe to event types, and run LLM loops independently. JSON wire format. Single connection per agent, multiplexed sessions per event.

**Tech Stack:** Go (coder/websocket, goccy/go-json, cilium/ebpf, buntdb), Python (msgspec, pydantic-settings, typer, websockets)

**Spec:** `docs/superpowers/specs/2026-04-04-two-step-model-design.md`

**Parallelization:** Tasks 1+2 are independent. Tasks 3+7+8 are independent (after 1,2). Tasks 4+5+9 are independent (after 3,7). Task 6 depends on 4+5.

---

### Task 1: Python project scaffolding + protocol + config

**Files:**
- Create: `pyproject.toml`
- Create: `src/veronica/__init__.py`
- Create: `src/veronica/protocol/__init__.py`
- Create: `src/veronica/protocol/messages.py`
- Create: `src/veronica/config.py`
- Create: `src/veronica/cli/__init__.py`
- Create: `src/veronica/agents/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/test_protocol.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "veronica"
version = "0.1.0"
description = "Veronica host agents and CLI"
requires-python = ">=3.12"
dependencies = [
    "msgspec>=0.19",
    "pydantic-settings>=2.0",
    "typer>=0.15",
    "websockets>=15.0",
]

[project.scripts]
veronica = "veronica.cli.main:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/veronica"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create __init__.py files**

Create empty `src/veronica/__init__.py`, `src/veronica/protocol/__init__.py`, `src/veronica/cli/__init__.py`, `src/veronica/agents/__init__.py`, `tests/__init__.py`.

- [ ] **Step 3: Create protocol/messages.py**

```python
"""WebSocket protocol message types shared between daemon and agents."""

from __future__ import annotations

import msgspec


class EventData(msgspec.Struct):
    """Payload of an eBPF event from the daemon."""

    type: str
    resource: str
    data: dict
    timestamp: str


class Subscribe(msgspec.Struct):
    """Agent → Daemon: register and subscribe to event types."""

    type: str = "subscribe"
    agent_id: str = ""
    events: list[str] = []


class Event(msgspec.Struct):
    """Daemon → Agent: new event, creates a session."""

    type: str = "event"
    session: str = ""
    event: EventData | None = None


class ToolCall(msgspec.Struct):
    """Agent → Daemon: call a tool within a session."""

    type: str = "tool_call"
    session: str = ""
    call_id: str = ""
    name: str = ""
    args: dict = {}


class ToolResult(msgspec.Struct):
    """Daemon → Agent: result of a tool call."""

    type: str = "tool_result"
    session: str = ""
    call_id: str = ""
    result: dict = {}


class SessionDone(msgspec.Struct):
    """Agent → Daemon: agent is done with this session."""

    type: str = "session_done"
    session: str = ""


# Union type for decoding any incoming message
IncomingMessage = Subscribe | ToolCall | SessionDone

# Decoder that routes by "type" field
incoming_decoder = msgspec.json.Decoder(IncomingMessage, strict=False)

# Typed decoders for specific message types
event_decoder = msgspec.json.Decoder(Event)
tool_result_decoder = msgspec.json.Decoder(ToolResult)
```

- [ ] **Step 4: Create config.py**

```python
"""Veronica configuration. No env var overrides for now."""

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    daemon_ws_url: str = "ws://localhost:9090"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_build_path: str = "/tmp/veronica"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    session_timeout: int = 60
    project_path: str = "/Users/fimbulwinter/dev/veronica"
```

- [ ] **Step 5: Write protocol tests**

```python
"""tests/test_protocol.py"""

import msgspec
from veronica.protocol.messages import (
    EventData,
    Subscribe,
    Event,
    ToolCall,
    ToolResult,
    SessionDone,
    incoming_decoder,
)


def test_subscribe_roundtrip():
    msg = Subscribe(agent_id="net-01", events=["net_connect", "process_exec"])
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=Subscribe)
    assert decoded.agent_id == "net-01"
    assert decoded.events == ["net_connect", "process_exec"]
    assert decoded.type == "subscribe"


def test_event_roundtrip():
    event = Event(
        session="abc123",
        event=EventData(
            type="net_connect",
            resource="ip:10.0.0.5:443",
            data={"comm": "curl", "pid": 1234},
            timestamp="2026-04-04T12:00:00Z",
        ),
    )
    data = msgspec.json.encode(event)
    decoded = msgspec.json.decode(data, type=Event)
    assert decoded.session == "abc123"
    assert decoded.event.type == "net_connect"
    assert decoded.event.data["comm"] == "curl"


def test_tool_call_roundtrip():
    msg = ToolCall(
        session="abc123",
        call_id="1",
        name="map_read",
        args={"map": "connections"},
    )
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=ToolCall)
    assert decoded.name == "map_read"
    assert decoded.args["map"] == "connections"


def test_tool_result_roundtrip():
    msg = ToolResult(
        session="abc123",
        call_id="1",
        result={"ok": True, "data": {"key": "value"}},
    )
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=ToolResult)
    assert decoded.result["ok"] is True


def test_session_done_roundtrip():
    msg = SessionDone(session="abc123")
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=SessionDone)
    assert decoded.session == "abc123"


def test_incoming_decoder_routes_subscribe():
    data = msgspec.json.encode(Subscribe(agent_id="a", events=["x"]))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, Subscribe)


def test_incoming_decoder_routes_tool_call():
    data = msgspec.json.encode(ToolCall(session="s", call_id="1", name="read_file", args={"path": "/tmp"}))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, ToolCall)


def test_incoming_decoder_routes_session_done():
    data = msgspec.json.encode(SessionDone(session="s"))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, SessionDone)
```

- [ ] **Step 6: Write config test**

```python
"""tests/test_config.py"""

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.daemon_ws_url == "ws://localhost:9090"
    assert cfg.vm_name == "veronica"
    assert cfg.session_timeout == 60
```

- [ ] **Step 7: Run tests**

```bash
cd /Users/fimbulwinter/dev/veronica
uv sync
uv run pytest tests/test_protocol.py tests/test_config.py -v
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml src/ tests/
git commit -m "feat: python project scaffolding — protocol types, config, tests"
```

---

### Task 2: Go — Move ToolDef types from llm to tool package

**Files:**
- Create: `internal/tool/types.go`
- Modify: `internal/tool/registry.go` — change import from `llm` to local types
- Test: `internal/tool/registry_test.go` — verify existing tests still pass

The `internal/llm` package will be deleted later. First we extract the types that `tool` needs.

- [ ] **Step 1: Create internal/tool/types.go**

```go
package tool

// ToolDef defines a tool the LLM can call (OpenAI function calling format).
type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

// FunctionDef is the tool's name, description, and parameter schema.
type FunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}
```

- [ ] **Step 2: Update internal/tool/registry.go — remove llm import**

Replace the import of `github.com/fimbulwinter/veronica/internal/llm` and all references to `llm.ToolDef`, `llm.FunctionDef` with the local types.

The updated `registry.go`:

```go
package tool

import (
	"context"
	"encoding/json"
	"fmt"
)

// entry holds a tool's definition and its untyped executor.
type entry struct {
	def     ToolDef
	execute func(ctx context.Context, rawArgs string) (any, error)
}

// Registry holds registered tools and dispatches calls by name.
type Registry struct {
	tools map[string]entry
	order []string
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]entry),
	}
}

// Register adds a typed tool to the registry. Schema is generated from TArgs struct tags.
func Register[TArgs any](r *Registry, name string, description string, fn func(ctx context.Context, args TArgs) (any, error)) {
	schema := SchemaFromStruct[TArgs]()

	r.tools[name] = entry{
		def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        name,
				Description: description,
				Parameters:  schema,
			},
		},
		execute: func(ctx context.Context, rawArgs string) (any, error) {
			var args TArgs
			if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
				return nil, fmt.Errorf("unmarshal args for %s: %w", name, err)
			}
			return fn(ctx, args)
		},
	}
	r.order = append(r.order, name)
}

// Definitions returns all registered tool definitions in registration order.
func (r *Registry) Definitions() []ToolDef {
	defs := make([]ToolDef, len(r.order))
	for i, name := range r.order {
		defs[i] = r.tools[name].def
	}
	return defs
}

// Call dispatches a tool call by name with raw JSON arguments.
func (r *Registry) Call(ctx context.Context, name string, rawArgs string) (any, error) {
	e, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	return e.execute(ctx, rawArgs)
}
```

- [ ] **Step 3: Run existing tool tests**

```bash
cd /Users/fimbulwinter/dev/veronica
go test ./internal/tool/ -v
```

Expected: all tests pass. The registry_test.go and schema_test.go don't import llm directly — they use `reg.Definitions()` which now returns `[]tool.ToolDef` instead of `[]llm.ToolDef`. Since the tests are in the `tool` package, this is transparent.

- [ ] **Step 4: Add goccy/go-json dependency**

```bash
cd /Users/fimbulwinter/dev/veronica
go get github.com/goccy/go-json
```

- [ ] **Step 5: Commit**

```bash
git add internal/tool/types.go internal/tool/registry.go go.mod go.sum
git commit -m "refactor: move ToolDef types from llm to tool package"
```

---

### Task 3: Go — WebSocket server

**Files:**
- Create: `internal/ws/server.go`
- Create: `internal/ws/server_test.go`

**Depends on:** Task 2 (ToolDef in tool package)

The WS server handles agent connections, subscriptions, event routing, and session-based tool call proxying.

- [ ] **Step 1: Add coder/websocket dependency**

```bash
cd /Users/fimbulwinter/dev/veronica
go get github.com/coder/websocket
```

- [ ] **Step 2: Create internal/ws/server.go**

```go
package ws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/tool"
)

// --- Protocol message types ---

type subscribeMsg struct {
	Type    string   `json:"type"`
	AgentID string   `json:"agent_id"`
	Events  []string `json:"events"`
}

type eventMsg struct {
	Type    string   `json:"type"`
	Session string   `json:"session"`
	Event   eventData `json:"event"`
}

type eventData struct {
	Type      string `json:"type"`
	Resource  string `json:"resource"`
	Data      json.RawMessage `json:"data"`
	Timestamp string `json:"timestamp"`
}

type toolCallMsg struct {
	Type    string          `json:"type"`
	Session string          `json:"session"`
	CallID  string          `json:"call_id"`
	Name    string          `json:"name"`
	Args    json.RawMessage `json:"args"`
}

type toolResultMsg struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	CallID  string `json:"call_id"`
	Result  any    `json:"result"`
}

type sessionDoneMsg struct {
	Type    string `json:"type"`
	Session string `json:"session"`
}

// --- Server ---

// Server is the WebSocket server that host agents connect to.
type Server struct {
	addr      string
	toolkitFn func(sessionID string) *tool.Registry
	listener  net.Listener

	mu       sync.RWMutex
	agents   map[string]*agentConn
	sessions map[string]*session
}

type agentConn struct {
	id      string
	conn    *websocket.Conn
	events  []string // subscribed event types
	writeMu sync.Mutex
}

type session struct {
	id       string
	agentID  string
	toolkit  *tool.Registry
	incoming chan toolCallMsg
	done     chan struct{}
}

// NewServer creates a WebSocket server.
// toolkitFn creates a tool.Registry for each session (with the session ID as agent ID).
func NewServer(addr string, toolkitFn func(sessionID string) *tool.Registry) *Server {
	return &Server{
		addr:      addr,
		toolkitFn: toolkitFn,
		agents:    make(map[string]*agentConn),
		sessions:  make(map[string]*session),
	}
}

// Start begins listening for WebSocket connections. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		s.handleWS(ctx, w, r)
	})

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	s.listener = ln
	log.Printf("ws server listening on %s", s.addr)

	server := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		server.Close()
	}()

	err = server.Serve(ln)
	if ctx.Err() != nil {
		return nil // clean shutdown
	}
	return err
}

// Addr returns the listener address (useful in tests when using ":0").
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// RouteEvent implements coordinator.Router. Routes an event to all subscribed agents.
func (s *Server) RouteEvent(ctx context.Context, event coordinator.Event, category coordinator.EventCategory) {
	s.mu.RLock()
	var targets []*agentConn
	for _, agent := range s.agents {
		for _, et := range agent.events {
			if et == event.Type {
				targets = append(targets, agent)
				break
			}
		}
	}
	s.mu.RUnlock()

	for _, agent := range targets {
		sessionID := generateID()
		toolkit := s.toolkitFn(sessionID)

		sess := &session{
			id:       sessionID,
			agentID:  agent.id,
			toolkit:  toolkit,
			incoming: make(chan toolCallMsg, 16),
			done:     make(chan struct{}),
		}

		s.mu.Lock()
		s.sessions[sessionID] = sess
		s.mu.Unlock()

		// Marshal event data as raw JSON
		rawData := json.RawMessage(event.Data)
		msg := eventMsg{
			Type:    "event",
			Session: sessionID,
			Event: eventData{
				Type:      event.Type,
				Resource:  event.Resource,
				Data:      rawData,
				Timestamp: event.Timestamp.Format(time.RFC3339Nano),
			},
		}

		data, _ := json.Marshal(msg)
		agent.writeMu.Lock()
		agent.conn.Write(ctx, websocket.MessageText, data)
		agent.writeMu.Unlock()

		go s.runSession(ctx, sess, agent)
	}
}

// ConnectedAgents returns the number of connected agents.
func (s *Server) ConnectedAgents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

// ActiveSessions returns the number of active sessions.
func (s *Server) ActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *Server) handleWS(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("ws accept: %v", err)
		return
	}

	// First message must be subscribe
	_, data, err := conn.Read(ctx)
	if err != nil {
		conn.Close(websocket.StatusProtocolError, "expected subscribe")
		return
	}

	var sub subscribeMsg
	if err := json.Unmarshal(data, &sub); err != nil || sub.Type != "subscribe" {
		conn.Close(websocket.StatusProtocolError, "first message must be subscribe")
		return
	}

	agent := &agentConn{
		id:     sub.AgentID,
		conn:   conn,
		events: sub.Events,
	}

	s.mu.Lock()
	s.agents[agent.id] = agent
	s.mu.Unlock()

	log.Printf("agent %s connected, subscribed to %v", agent.id, agent.events)

	defer func() {
		s.mu.Lock()
		delete(s.agents, agent.id)
		s.mu.Unlock()
		conn.Close(websocket.StatusNormalClosure, "")
		log.Printf("agent %s disconnected", agent.id)
	}()

	s.readLoop(ctx, agent)
}

func (s *Server) readLoop(ctx context.Context, agent *agentConn) {
	for {
		_, data, err := agent.conn.Read(ctx)
		if err != nil {
			return
		}

		var base struct {
			Type    string `json:"type"`
			Session string `json:"session"`
		}
		if err := json.Unmarshal(data, &base); err != nil {
			continue
		}

		switch base.Type {
		case "tool_call":
			var tc toolCallMsg
			if err := json.Unmarshal(data, &tc); err != nil {
				continue
			}
			s.mu.RLock()
			sess := s.sessions[tc.Session]
			s.mu.RUnlock()
			if sess != nil {
				sess.incoming <- tc
			}

		case "session_done":
			s.mu.RLock()
			sess := s.sessions[base.Session]
			s.mu.RUnlock()
			if sess != nil {
				select {
				case <-sess.done:
				default:
					close(sess.done)
				}
			}
		}
	}
}

func (s *Server) runSession(ctx context.Context, sess *session, agent *agentConn) {
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess.id)
		s.mu.Unlock()
	}()

	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.done:
			return
		case <-timeout.C:
			log.Printf("session %s timed out", sess.id)
			return
		case tc := <-sess.incoming:
			timeout.Reset(60 * time.Second)

			result, err := sess.toolkit.Call(ctx, tc.Name, string(tc.Args))

			var resultMap any
			if err != nil {
				resultMap = map[string]any{"ok": false, "error": err.Error()}
			} else {
				resultMap = map[string]any{"ok": true, "data": result}
			}

			resp := toolResultMsg{
				Type:    "tool_result",
				Session: sess.id,
				CallID:  tc.CallID,
				Result:  resultMap,
			}
			data, _ := json.Marshal(resp)

			agent.writeMu.Lock()
			agent.conn.Write(ctx, websocket.MessageText, data)
			agent.writeMu.Unlock()
		}
	}
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

- [ ] **Step 3: Write WebSocket server test**

```go
// internal/ws/server_test.go
package ws

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/tool"
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

func startTestServer(t *testing.T, ctx context.Context) *Server {
	t.Helper()
	srv := NewServer(":0", testToolkitFactory)
	go srv.Start(ctx)
	// Wait for listener
	for srv.listener == nil {
		time.Sleep(5 * time.Millisecond)
	}
	return srv
}

func connectAgent(t *testing.T, ctx context.Context, addr, agentID string, events []string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, "ws://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	sub := subscribeMsg{Type: "subscribe", AgentID: agentID, Events: events}
	data, _ := json.Marshal(sub)
	conn.Write(ctx, websocket.MessageText, data)

	return conn
}

func TestServer_AgentConnectsAndSubscribes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn := connectAgent(t, ctx, srv.Addr(), "test-01", []string{"process_exec"})
	defer conn.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)
	if srv.ConnectedAgents() != 1 {
		t.Fatalf("expected 1 agent, got %d", srv.ConnectedAgents())
	}
}

func TestServer_RouteEventToSubscribedAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn := connectAgent(t, ctx, srv.Addr(), "net-01", []string{"net_connect"})
	defer conn.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)

	srv.RouteEvent(ctx, coordinator.Event{
		Type:      "net_connect",
		Resource:  "ip:10.0.0.5:443",
		Data:      `{"comm":"curl","pid":1234}`,
		Timestamp: time.Now(),
	}, coordinator.CategoryUrgent)

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var msg eventMsg
	json.Unmarshal(data, &msg)
	if msg.Type != "event" {
		t.Fatalf("expected event, got %s", msg.Type)
	}
	if msg.Event.Type != "net_connect" {
		t.Fatalf("expected net_connect, got %s", msg.Event.Type)
	}
}

func TestServer_EventNotRoutedToUnsubscribed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn := connectAgent(t, ctx, srv.Addr(), "fs-01", []string{"file_open"})
	defer conn.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)

	srv.RouteEvent(ctx, coordinator.Event{
		Type:     "net_connect",
		Resource: "ip:10.0.0.5:443",
		Data:     `{"comm":"curl"}`,
	}, coordinator.CategoryUrgent)

	// Agent should not receive this event — read should time out
	readCtx, readCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer readCancel()
	_, _, err := conn.Read(readCtx)
	if err == nil {
		t.Fatal("expected no message for unsubscribed event type")
	}
}

func TestServer_ToolCallAndResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn := connectAgent(t, ctx, srv.Addr(), "test-01", []string{"process_exec"})
	defer conn.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)

	// Route an event
	srv.RouteEvent(ctx, coordinator.Event{
		Type:      "process_exec",
		Resource:  "pid:42",
		Data:      `{"comm":"ls"}`,
		Timestamp: time.Now(),
	}, coordinator.CategoryUrgent)

	// Read event, get session ID
	_, data, _ := conn.Read(ctx)
	var ev eventMsg
	json.Unmarshal(data, &ev)
	sessionID := ev.Session

	// Send tool_call
	tc := toolCallMsg{
		Type:    "tool_call",
		Session: sessionID,
		CallID:  "call-1",
		Name:    "echo",
		Args:    json.RawMessage(`{"msg":"hello"}`),
	}
	tcData, _ := json.Marshal(tc)
	conn.Write(ctx, websocket.MessageText, tcData)

	// Read tool_result
	_, resultData, _ := conn.Read(ctx)
	var tr toolResultMsg
	json.Unmarshal(resultData, &tr)

	if tr.Type != "tool_result" {
		t.Fatalf("expected tool_result, got %s", tr.Type)
	}
	if tr.CallID != "call-1" {
		t.Fatalf("expected call-1, got %s", tr.CallID)
	}
	resultMap, ok := tr.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", tr.Result)
	}
	if resultMap["ok"] != true {
		t.Fatalf("expected ok=true, got %v", resultMap["ok"])
	}
	if resultMap["data"] != "echo: hello" {
		t.Fatalf("expected 'echo: hello', got %v", resultMap["data"])
	}
}

func TestServer_SessionDoneCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn := connectAgent(t, ctx, srv.Addr(), "test-01", []string{"process_exec"})
	defer conn.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)

	srv.RouteEvent(ctx, coordinator.Event{
		Type:      "process_exec",
		Resource:  "pid:42",
		Data:      `{"comm":"ls"}`,
		Timestamp: time.Now(),
	}, coordinator.CategoryUrgent)

	_, data, _ := conn.Read(ctx)
	var ev eventMsg
	json.Unmarshal(data, &ev)

	// Send session_done
	done := sessionDoneMsg{Type: "session_done", Session: ev.Session}
	doneData, _ := json.Marshal(done)
	conn.Write(ctx, websocket.MessageText, doneData)

	time.Sleep(100 * time.Millisecond)
	if srv.ActiveSessions() != 0 {
		t.Fatalf("expected 0 sessions after done, got %d", srv.ActiveSessions())
	}
}

func TestServer_FanOutToMultipleAgents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := startTestServer(t, ctx)
	conn1 := connectAgent(t, ctx, srv.Addr(), "agent-1", []string{"process_exec"})
	defer conn1.Close(websocket.StatusNormalClosure, "")
	conn2 := connectAgent(t, ctx, srv.Addr(), "agent-2", []string{"process_exec"})
	defer conn2.Close(websocket.StatusNormalClosure, "")

	time.Sleep(50 * time.Millisecond)

	srv.RouteEvent(ctx, coordinator.Event{
		Type:      "process_exec",
		Resource:  "pid:42",
		Data:      `{"comm":"ls"}`,
		Timestamp: time.Now(),
	}, coordinator.CategoryUrgent)

	// Both agents should receive the event
	_, data1, err1 := conn1.Read(ctx)
	_, data2, err2 := conn2.Read(ctx)
	if err1 != nil || err2 != nil {
		t.Fatalf("expected both agents to receive event: err1=%v err2=%v", err1, err2)
	}

	var ev1, ev2 eventMsg
	json.Unmarshal(data1, &ev1)
	json.Unmarshal(data2, &ev2)

	if ev1.Event.Type != "process_exec" || ev2.Event.Type != "process_exec" {
		t.Fatal("both agents should get process_exec event")
	}
	// Sessions should be different
	if ev1.Session == ev2.Session {
		t.Fatal("each agent should get a unique session")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/fimbulwinter/dev/veronica
go test ./internal/ws/ -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/ws/ go.mod go.sum
git commit -m "feat: WebSocket server for host agent connections"
```

---

### Task 4: Go — Add Router interface, rewrite coordinator

**Files:**
- Modify: `internal/coordinator/types.go` — add Router interface
- Modify: `internal/coordinator/coordinator.go` — remove llm.Client, use Router
- Modify: `internal/coordinator/coordinator_test.go` — rewrite tests for new API
- Delete prompts (urgentPrompt, batchPrompt)

**Depends on:** Task 3 (WS server implements Router)

- [ ] **Step 1: Add Router interface to types.go**

Add to `internal/coordinator/types.go`:

```go
// Router dispatches events to host agents.
type Router interface {
	RouteEvent(ctx context.Context, event Event, category EventCategory)
}
```

- [ ] **Step 2: Rewrite coordinator.go**

```go
package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	MaxTurns       int
	TurnTimeout    time.Duration
	ActionExecutor func(Action) (string, error)
}

// Coordinator receives events, routes to host agents via Router, and serializes actions.
type Coordinator struct {
	router       Router
	store        *state.Store
	config       Config
	classifier   *Classifier
	batch        *Batch
	events       chan Event
	actions      chan ActionRequest
	reports      chan Report
	inFlight     map[string]string
	executorPIDs sync.Map
	batchRunning atomic.Bool
}

// IsOurPID reports whether the given PID belongs to a command we spawned.
func (c *Coordinator) IsOurPID(pid uint32) bool {
	_, ok := c.executorPIDs.Load(pid)
	return ok
}

// TrackPID records a PID as belonging to a command we spawned.
func (c *Coordinator) TrackPID(pid uint32) {
	c.executorPIDs.Store(pid, true)
}

// UntrackPID removes a PID from our tracking set.
func (c *Coordinator) UntrackPID(pid uint32) {
	c.executorPIDs.Delete(pid)
}

// ActionChannel returns the action request channel for toolkit wiring.
func (c *Coordinator) ActionChannel() chan ActionRequest {
	return c.actions
}

// New creates a coordinator.
func New(router Router, store *state.Store, cfg Config) *Coordinator {
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 10
	}
	if cfg.TurnTimeout <= 0 {
		cfg.TurnTimeout = 30 * time.Second
	}
	c := &Coordinator{
		router:     router,
		store:      store,
		config:     cfg,
		classifier: NewClassifier(),
		batch:      NewBatch(5 * time.Second),
		events:     make(chan Event, 256),
		actions:    make(chan ActionRequest, 64),
		reports:    make(chan Report, 256),
		inFlight:   make(map[string]string),
	}
	c.classifier.IsOurPID = c.IsOurPID
	return c
}

// Start begins the coordinator's event processing, action queue, and batch loops.
func (c *Coordinator) Start(ctx context.Context) {
	go c.eventLoop(ctx)
	go c.actionLoop(ctx)
	go c.batchLoop(ctx)
}

// HandleEvent sends an event to the coordinator for processing.
func (c *Coordinator) HandleEvent(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	c.events <- event
}

// Reports returns the channel for observing coordinator activity.
func (c *Coordinator) Reports() <-chan Report {
	return c.reports
}

func (c *Coordinator) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-c.events:
			category := c.classifier.Classify(event)

			switch category {
			case CategorySilent:
				// drop
			case CategoryUrgent:
				if err := c.store.RecordEvent(state.Event{
					Type: event.Type, Resource: event.Resource,
					Data: event.Data, Timestamp: event.Timestamp,
				}); err != nil {
					log.Printf("record event: %v", err)
				}

				comm := commFromData(event.Data)
				cmdline := cmdlineFromData(event.Data)
				agentID := fmt.Sprintf("urgent-%s", hex.EncodeToString(randBytes()))
				c.report(Report{
					AgentID:   agentID,
					EventType: "routed",
					Detail:    fmt.Sprintf("URGENT %s comm=%s cmdline=%s", event.Resource, comm, cmdline),
				})

				c.router.RouteEvent(ctx, event, CategoryUrgent)
			case CategoryBatch:
				c.batch.Add(event)
			}
		}
	}
}

func (c *Coordinator) batchLoop(ctx context.Context) {
	ticker := time.NewTicker(c.batch.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := c.batch.Flush()
			if len(events) == 0 {
				continue
			}

			// Record events
			for _, e := range events {
				_ = c.store.RecordEvent(state.Event{
					Type: e.Type, Resource: e.Resource,
					Data: e.Data, Timestamp: e.Timestamp,
				})
			}

			// Build batch event data
			batchData := marshalBatchData(events, c.batch.interval)

			batchEvent := Event{
				Type:      "batch",
				Resource:  fmt.Sprintf("batch:%d", len(events)),
				Data:      batchData,
				Timestamp: time.Now(),
			}

			c.report(Report{
				EventType: "batch_routed",
				Detail:    fmt.Sprintf("%d events", len(events)),
			})

			c.router.RouteEvent(ctx, batchEvent, CategoryBatch)
		}
	}
}

func marshalBatchData(events []Event, interval time.Duration) string {
	// Deduplicate
	seen := make(map[string]bool)
	var unique []Event
	for _, e := range events {
		key := commFromData(e.Data) + "|" + cmdlineFromData(e.Data)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}

	type batchEntry struct {
		Type     string `json:"type"`
		Resource string `json:"resource"`
		Comm     string `json:"comm,omitempty"`
		Cmdline  string `json:"cmdline,omitempty"`
		Cwd      string `json:"cwd,omitempty"`
	}

	limit := len(unique)
	if limit > 20 {
		limit = 20
	}

	entries := make([]batchEntry, limit)
	for i, e := range unique[:limit] {
		entries[i] = batchEntry{
			Type:     e.Type,
			Resource: e.Resource,
			Comm:     commFromData(e.Data),
			Cmdline:  cmdlineFromData(e.Data),
			Cwd:      cwdFromData(e.Data),
		}
	}

	payload := map[string]any{
		"total":    len(events),
		"unique":   len(unique),
		"interval": interval.String(),
		"events":   entries,
	}

	b, _ := json.Marshal(payload)
	return string(b)
}

func (c *Coordinator) actionLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.actions:
			c.report(Report{
				AgentID:   req.AgentID,
				EventType: "action_requested",
				Detail:    fmt.Sprintf("%s: %s", req.Action.Resource, truncate(req.Action.Args, 80)),
			})

			if existingAgent, ok := c.inFlight[req.Action.Resource]; ok && existingAgent != req.AgentID {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "conflict",
					Detail:    fmt.Sprintf("resource %s already claimed by %s", req.Action.Resource, existingAgent),
				})
				req.Response <- ActionResult{
					Approved: false,
					Output:   fmt.Sprintf("resource %s is being handled by %s", req.Action.Resource, existingAgent),
				}
				continue
			}

			c.inFlight[req.Action.Resource] = req.AgentID

			executor := c.config.ActionExecutor
			if executor == nil {
				executor = func(a Action) (string, error) { return "ok", nil }
			}

			output, err := executor(req.Action)
			delete(c.inFlight, req.Action.Resource)

			if err != nil {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "action_rejected",
					Detail:    err.Error(),
				})
				req.Response <- ActionResult{Approved: false, Output: err.Error(), Error: err}
			} else {
				c.report(Report{
					AgentID:   req.AgentID,
					EventType: "action_approved",
					Detail:    truncate(output, 100),
				})
				_ = c.store.AppendAgentLog(req.AgentID, state.LogEntry{
					Action: req.Action.Type,
					Result: output,
				})
				req.Response <- ActionResult{Approved: true, Output: output}
			}
		}
	}
}

func (c *Coordinator) report(r Report) {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	select {
	case c.reports <- r:
	default:
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func randBytes() []byte {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return b
}

func commFromData(data string) string {
	var payload struct {
		Comm string `json:"comm"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Comm
}

func cwdFromData(data string) string {
	var payload struct {
		Cwd string `json:"cwd"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Cwd
}

func cmdlineFromData(data string) string {
	var payload struct {
		Cmdline string `json:"cmdline"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Cmdline
}
```

- [ ] **Step 3: Rewrite coordinator_test.go**

```go
package coordinator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/state"
)

// mockRouter records routed events.
type mockRouter struct {
	mu     sync.Mutex
	events []Event
	count  atomic.Int32
}

func (m *mockRouter) RouteEvent(ctx context.Context, event Event, category EventCategory) {
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
	m.count.Add(1)
}

func TestCoordinator_UrgentEventRouted(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// chmod on sensitive path → urgent → routed
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"chmod","cmdline":"chmod 777 /etc/shadow","filename":"/usr/bin/chmod"}`,
	})

	deadline := time.After(3 * time.Second)
	for router.count.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for event to be routed")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	router.mu.Lock()
	defer router.mu.Unlock()
	if len(router.events) != 1 {
		t.Fatalf("expected 1 routed event, got %d", len(router.events))
	}
	if router.events[0].Type != "process_exec" {
		t.Fatalf("expected process_exec, got %s", router.events[0].Type)
	}
}

func TestCoordinator_BatchEventRouted(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Regular event → batch
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:42",
		Data:     `{"comm":"mkdir","cmdline":"mkdir /tmp/test","filename":"/usr/bin/mkdir"}`,
	})

	// Wait for batch flush (5s)
	deadline := time.After(8 * time.Second)
	for router.count.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for batch to be routed")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	router.mu.Lock()
	defer router.mu.Unlock()
	if router.events[0].Type != "batch" {
		t.Fatalf("expected batch event, got %s", router.events[0].Type)
	}
}

func TestCoordinator_SilentEventDropped(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// systemd event → silent
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:1",
		Data:     `{"comm":"systemd-logind","cmdline":"","filename":"/usr/lib/systemd/systemd-logind"}`,
	})

	time.Sleep(500 * time.Millisecond)
	if router.count.Load() != 0 {
		t.Fatal("silent event should not be routed")
	}
}

func TestCoordinator_Reports(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	router := &mockRouter{}
	c := New(router, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Urgent event → report
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:99",
		Data:     `{"comm":"suspicious","filename":"/tmp/suspicious"}`,
	})

	select {
	case r := <-reports:
		if r.EventType != "routed" {
			t.Fatalf("expected routed report, got %q", r.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for report")
	}
}

func TestCoordinator_ActionQueueConflict(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	router := &mockRouter{}
	c := New(router, store, Config{
		ActionExecutor: func(a Action) (string, error) {
			time.Sleep(200 * time.Millisecond)
			return "done", nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// First action
	resp1 := make(chan ActionResult, 1)
	c.actions <- ActionRequest{
		AgentID:  "agent-1",
		Action:   Action{Type: "shell_exec", Resource: "pid:42", Args: "kill 42"},
		Response: resp1,
	}

	time.Sleep(50 * time.Millisecond)

	// Second action on same resource from different agent
	resp2 := make(chan ActionResult, 1)
	c.actions <- ActionRequest{
		AgentID:  "agent-2",
		Action:   Action{Type: "shell_exec", Resource: "pid:42", Args: "kill 42"},
		Response: resp2,
	}

	r2 := <-resp2
	if r2.Approved {
		t.Fatal("conflicting action should be rejected")
	}

	r1 := <-resp1
	if !r1.Approved {
		t.Fatal("first action should be approved")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/fimbulwinter/dev/veronica
go test ./internal/coordinator/ -v -run "TestCoordinator"
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/coordinator/types.go internal/coordinator/coordinator.go internal/coordinator/coordinator_test.go
git commit -m "refactor: coordinator uses Router interface, no more internal LLM"
```

---

### Task 5: Go — Add state tools and eBPF tool stubs to toolkit

**Files:**
- Modify: `internal/coordinator/toolkit.go` — add new tools
- Modify: `internal/coordinator/toolkit_test.go` — test new tools

**Depends on:** Task 2 (ToolDef in tool package)

- [ ] **Step 1: Update toolkit.go with new tools**

```go
package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/fimbulwinter/veronica/internal/state"
	"github.com/fimbulwinter/veronica/internal/tool"
)

var allowedCommands = map[string]bool{
	"cat": true, "ls": true, "ps": true, "stat": true, "df": true,
	"ip": true, "ss": true, "whoami": true, "hostname": true, "uname": true,
	"uptime": true, "free": true, "id": true, "echo": true, "head": true,
	"tail": true, "wc": true, "du": true, "mount": true, "lsblk": true,
	"top": true, "netstat": true, "lsof": true, "file": true, "which": true,
	"sleep": true, "test": true, "find": true, "grep": true,
	"nginx": true, "python3": true, "node": true, "go": true,
	"journalctl": true, "systemctl": true, "docker": true,
	"dig": true, "nslookup": true, "curl": true, "wget": true,
}

// --- Existing tool arg types ---

type readFileArgs struct {
	Path string `json:"path" desc:"Absolute path to the file to read"`
}

type shellReadArgs struct {
	Cmd  string   `json:"cmd" desc:"Command to run (must be in allowlist)"`
	Args []string `json:"args,omitempty" desc:"Command arguments"`
}

type requestActionArgs struct {
	Command string `json:"command" desc:"Shell command to execute"`
	Reason  string `json:"reason" desc:"Brief explanation of why this action is needed"`
}

// --- New tool arg types ---

type stateQueryArgs struct {
	Pattern string `json:"pattern" desc:"Key pattern to query (e.g. 'policy:*', 'event:*')"`
	Limit   int    `json:"limit,omitempty" desc:"Max results to return (default 50)"`
}

type stateWriteArgs struct {
	Key   string `json:"key" desc:"Key to write"`
	Value string `json:"value" desc:"JSON value to store"`
	TTL   int    `json:"ttl,omitempty" desc:"Time-to-live in seconds (0 = no expiry)"`
}

type mapReadArgs struct {
	Map string `json:"map" desc:"eBPF map name"`
	Key string `json:"key,omitempty" desc:"Specific key to read (omit to dump all)"`
}

type mapWriteArgs struct {
	Map   string `json:"map" desc:"eBPF map name"`
	Key   string `json:"key" desc:"Map key"`
	Value string `json:"value" desc:"Map value"`
}

type mapDeleteArgs struct {
	Map string `json:"map" desc:"eBPF map name"`
	Key string `json:"key" desc:"Key to delete"`
}

type programListArgs struct{}

type programLoadArgs struct {
	Name string `json:"name" desc:"Program name to load and attach"`
}

type programDetachArgs struct {
	Name string `json:"name" desc:"Program name to detach and unload"`
}

// NewToolkit creates a tool.Registry with all daemon tools.
func NewToolkit(actionCh chan<- ActionRequest, sessionID string, store *state.Store) *tool.Registry {
	reg := tool.NewRegistry()

	// --- Existing tools ---

	tool.Register(reg, "read_file", "Read a file's contents (VM filesystem only)", func(ctx context.Context, args readFileArgs) (any, error) {
		b, err := os.ReadFile(args.Path)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	})

	tool.Register(reg, "shell_read", "Run a read-only shell command (allowlisted commands only)", func(ctx context.Context, args shellReadArgs) (any, error) {
		if !allowedCommands[args.Cmd] {
			return nil, fmt.Errorf("command %q not in allowlist", args.Cmd)
		}
		out, err := exec.CommandContext(ctx, args.Cmd, args.Args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %w\noutput: %s", args.Cmd, err, string(out))
		}
		return string(out), nil
	})

	tool.Register(reg, "request_action", "Request the coordinator to execute a shell command", func(ctx context.Context, args requestActionArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: sessionID,
			Action: Action{
				Type:     "shell_exec",
				Resource: args.Reason,
				Args:     args.Command,
			},
			Response: respCh,
		}
		select {
		case result := <-respCh:
			if result.Error != nil {
				return nil, result.Error
			}
			if result.Approved {
				return "approved: " + result.Output, nil
			}
			return "rejected: " + result.Output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	// --- State tools ---

	tool.Register(reg, "state_query", "Query buntdb state by key pattern", func(ctx context.Context, args stateQueryArgs) (any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 50
		}
		results, err := store.QueryByPattern(args.Pattern, limit)
		if err != nil {
			return nil, err
		}
		return results, nil
	})

	tool.Register(reg, "state_write", "Write a key-value pair to buntdb state", func(ctx context.Context, args stateWriteArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: sessionID,
			Action: Action{
				Type:     "state_write",
				Resource: "state:" + args.Key,
				Args:     fmt.Sprintf(`{"key":%q,"value":%q,"ttl":%d}`, args.Key, args.Value, args.TTL),
			},
			Response: respCh,
		}
		select {
		case result := <-respCh:
			if result.Error != nil {
				return nil, result.Error
			}
			return result.Output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	// --- eBPF tools (stubs — real implementation requires eBPF manager wiring) ---

	tool.Register(reg, "map_read", "Read an eBPF map entry or dump entire map", func(ctx context.Context, args mapReadArgs) (any, error) {
		return nil, fmt.Errorf("map_read not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "map_write", "Write an entry to an eBPF map", func(ctx context.Context, args mapWriteArgs) (any, error) {
		return nil, fmt.Errorf("map_write not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "map_delete", "Delete an entry from an eBPF map", func(ctx context.Context, args mapDeleteArgs) (any, error) {
		return nil, fmt.Errorf("map_delete not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_list", "List loaded eBPF programs and their attach points", func(ctx context.Context, args programListArgs) (any, error) {
		return nil, fmt.Errorf("program_list not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_load", "Load and attach an eBPF program", func(ctx context.Context, args programLoadArgs) (any, error) {
		return nil, fmt.Errorf("program_load not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_detach", "Detach and unload an eBPF program", func(ctx context.Context, args programDetachArgs) (any, error) {
		return nil, fmt.Errorf("program_detach not yet implemented — requires eBPF manager wiring")
	})

	return reg
}

// AllowedCommands returns the set of allowed shell_read commands. Exported for testing.
func AllowedCommands() map[string]bool {
	result := make(map[string]bool, len(allowedCommands))
	for k, v := range allowedCommands {
		result[k] = v
	}
	return result
}
```

- [ ] **Step 2: Add QueryByPattern to state/store.go**

Add to `internal/state/store.go`:

```go
// QueryByPattern returns key-value pairs matching a buntdb pattern.
func (s *Store) QueryByPattern(pattern string, limit int) (map[string]string, error) {
	results := make(map[string]string)
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys(pattern, func(key, val string) bool {
			results[key] = val
			return len(results) < limit
		})
	})
	return results, err
}
```

- [ ] **Step 3: Update toolkit_test.go**

Add to existing `internal/coordinator/toolkit_test.go`:

```go
func TestToolkit_NewToolsRegistered(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

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
	defer store.Close()

	// Write some test data
	store.SetPolicy("ip", "10.0.0.5", state.Policy{Rule: "block", Value: "true", Reason: "suspicious"})

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
	defer store.Close()

	actionCh := make(chan ActionRequest, 1)
	reg := NewToolkit(actionCh, "test-session", store)

	_, err := reg.Call(context.Background(), "map_read", `{"map":"connections"}`)
	if err == nil {
		t.Fatal("expected stub error")
	}
}
```

- [ ] **Step 4: Update existing toolkit tests for new signature**

The existing tests in `toolkit_test.go` call `NewToolkit(actionCh, agentID)` — update them to `NewToolkit(actionCh, agentID, store)`:

Update the import to include `state` and update all `NewToolkit` calls:

```go
// At top of file, add import:
import "github.com/fimbulwinter/veronica/internal/state"

// In each existing test, create store and pass it:
// Replace: reg := NewToolkit(actionCh, "test-agent")
// With:
store, _ := state.Open(":memory:")
defer store.Close()
reg := NewToolkit(actionCh, "test-agent", store)
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/fimbulwinter/dev/veronica
go test ./internal/coordinator/ -v -run "TestToolkit"
go test ./internal/state/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/coordinator/toolkit.go internal/coordinator/toolkit_test.go internal/state/store.go
git commit -m "feat: add state tools and eBPF tool stubs to toolkit"
```

---

### Task 6: Go — Update main.go, delete old packages, clean up

**Files:**
- Modify: `cmd/veronicad/main.go` — wire WS server + coordinator
- Delete: `internal/agent/` (agent.go, types.go, agent_test.go, integration_test.go)
- Delete: `internal/llm/` (client.go, types.go, client_test.go)
- Delete: `cmd/cli/` (main.go, commands.go)
- Modify: `go.mod` — remove cobra, add coder/websocket and goccy/go-json

**Depends on:** Tasks 3, 4, 5

- [ ] **Step 1: Rewrite cmd/veronicad/main.go**

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/state"
	"github.com/fimbulwinter/veronica/internal/tool"
	"github.com/fimbulwinter/veronica/internal/ws"
)

func main() {
	wsAddr := envOr("VERONICA_WS_ADDR", ":9090")
	stateDB := envOr("VERONICA_STATE_DB", "/var/veronica/state.db")

	log.Printf("veronica starting")
	log.Printf("  ws: %s", wsAddr)
	log.Printf("  state: %s", stateDB)

	os.MkdirAll("/var/veronica", 0755)
	store, err := state.Open(stateDB)
	if err != nil {
		log.Fatalf("open state: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create coordinator first (need its action channel for toolkit)
	var coord *coordinator.Coordinator

	// Toolkit factory: creates a tool registry per session
	toolkitFn := func(sessionID string) *tool.Registry {
		return coordinator.NewToolkit(coord.ActionChannel(), sessionID, store)
	}

	// WebSocket server (implements coordinator.Router)
	wsSrv := ws.NewServer(wsAddr, toolkitFn)

	coord = coordinator.New(wsSrv, store, coordinator.Config{
		MaxTurns: 10,
		ActionExecutor: func(a coordinator.Action) (string, error) {
			log.Printf("ACTION [%s]: %s", a.Resource, a.Args)

			if isDangerous(a.Args) {
				log.Printf("ACTION DENIED (dangerous): %s", a.Args)
				return "DENIED: command matches dangerous pattern", fmt.Errorf("dangerous command blocked")
			}

			cmd := exec.CommandContext(ctx, "bash", "-c", a.Args)
			out, err := cmd.CombinedOutput()
			output := strings.TrimSpace(string(out))

			if err != nil {
				if strings.Contains(output, "command not found") || strings.Contains(output, "No such file") {
					tool := extractToolName(output)
					if tool != "" {
						log.Printf("ACTION: tool %q not found, attempting install...", tool)
						installOut, installErr := installTool(ctx, tool)
						if installErr != nil {
							return output + "\ninstall attempt: " + installOut, err
						}
						retryOut, retryErr := exec.CommandContext(ctx, "bash", "-c", a.Args).CombinedOutput()
						if retryErr != nil {
							return strings.TrimSpace(string(retryOut)), retryErr
						}
						return strings.TrimSpace(string(retryOut)), nil
					}
				}
				return output, err
			}
			return output, nil
		},
	})

	coord.Start(ctx)

	go func() {
		for r := range coord.Reports() {
			log.Printf("[%s] %s: %s", r.AgentID, r.EventType, r.Detail)
		}
	}()

	// Start WebSocket server
	go func() {
		if err := wsSrv.Start(ctx); err != nil {
			log.Printf("ws server stopped: %v", err)
		}
	}()

	// Start eBPF
	events := make(chan coordinator.Event, 256)
	go func() {
		for e := range events {
			coord.HandleEvent(e)
		}
	}()

	ebpfMgr := vebpf.New(events)
	if err := ebpfMgr.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf: %v", err)
	}
	defer ebpfMgr.Close()
	log.Printf("ebpf probes attached")

	go func() {
		if err := ebpfMgr.ReadEvents(ctx); err != nil {
			log.Printf("ebpf reader stopped: %v", err)
		}
	}()

	log.Printf("veronica running. ws=%s. ctrl+c to stop.", wsAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down...")
	cancel()
}

func isDangerous(cmd string) bool {
	dangerousPatterns := []string{
		"rm -rf /", "rm -rf /*", "mkfs",
		"dd if=/dev/zero", "dd if=/dev/urandom",
		":(){ :|:& };:", "> /dev/sda",
		"chmod -R 777 /", "chown -R",
		"shutdown", "reboot", "init 0", "halt", "poweroff",
	}
	lower := strings.ToLower(cmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func extractToolName(errOutput string) string {
	if idx := strings.Index(errOutput, ": command not found"); idx != -1 {
		before := errOutput[:idx]
		lastColon := strings.LastIndex(before, ": ")
		if lastColon != -1 {
			return strings.TrimSpace(before[lastColon+2:])
		}
	}
	return ""
}

func installTool(ctx context.Context, tool string) (string, error) {
	var installCmd string
	switch tool {
	case "uv", "uvx":
		installCmd = "curl -LsSf https://astral.sh/uv/install.sh | bash && ln -sf /root/.local/bin/uv /usr/local/bin/uv && ln -sf /root/.local/bin/uvx /usr/local/bin/uvx"
	case "bun", "bunx":
		installCmd = "curl -fsSL https://bun.sh/install | bash && ln -sf /root/.bun/bin/bun /usr/local/bin/bun"
	default:
		installCmd = "dnf install -y " + tool
	}
	log.Printf("ACTION: installing %s via: %s", tool, installCmd)
	out, err := exec.CommandContext(ctx, "bash", "-c", installCmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
```

**Note:** The `toolkitFn` type needs to match what `ws.NewServer` expects. Since `NewToolkit` returns `*tool.Registry`, add a type alias in coordinator or adjust the ws.NewServer signature. The simplest fix: `ws.NewServer` takes `func(string) *tool.Registry` and `coordinator.NewToolkit` returns `*tool.Registry`. Both are already the case, so this should work. Just make sure the import of `tool` is correct in main.go — it's used indirectly through `ws.NewServer`'s function parameter.

- [ ] **Step 2: Delete old packages**

```bash
rm -rf /Users/fimbulwinter/dev/veronica/internal/agent/
rm -rf /Users/fimbulwinter/dev/veronica/internal/llm/
rm -rf /Users/fimbulwinter/dev/veronica/cmd/cli/
```

- [ ] **Step 3: Clean up go.mod**

```bash
cd /Users/fimbulwinter/dev/veronica
go mod tidy
```

This should remove `github.com/spf13/cobra` (no longer imported) and add `github.com/coder/websocket` and `github.com/goccy/go-json` (if not already added).

- [ ] **Step 4: Remove integration_test.go from coordinator (imports deleted packages)**

Check if `internal/coordinator/integration_test.go` imports `internal/agent` or `internal/llm`. If so, delete it — it tested the old monolithic flow.

```bash
rm -f /Users/fimbulwinter/dev/veronica/internal/coordinator/integration_test.go
```

- [ ] **Step 5: Run all tests**

```bash
cd /Users/fimbulwinter/dev/veronica
go test ./internal/tool/ ./internal/state/ ./internal/coordinator/ ./internal/ws/ -v
```

Expected: all tests pass. The eBPF tests (`internal/ebpf/`) can only run in the VM.

- [ ] **Step 6: Verify build compiles**

```bash
cd /Users/fimbulwinter/dev/veronica
go build ./cmd/veronicad/
```

Expected: compiles without errors (even on macOS — the eBPF code has build tags).

**Note:** If this fails because eBPF imports are Linux-only, that's expected. The build will succeed in the VM. On macOS, verify with: `go vet ./internal/tool/ ./internal/state/ ./internal/coordinator/ ./internal/ws/`

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: hollow out daemon — remove agent loop, LLM, Go CLI; wire WS server"
```

---

### Task 7: Python — Base agent

**Files:**
- Create: `src/veronica/agents/base.py`
- Create: `tests/test_base_agent.py`

**Depends on:** Task 1 (protocol types)

- [ ] **Step 1: Create agents/base.py**

```python
"""Base agent class — WebSocket client with session handling."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from itertools import count

import msgspec
import websockets

from veronica.protocol.messages import (
    Event,
    EventData,
    SessionDone,
    Subscribe,
    ToolCall,
    ToolResult,
    tool_result_decoder,
)

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for Veronica host agents.

    Subclasses declare event subscriptions and implement handle_event.
    The base class manages the WebSocket connection and session multiplexing.
    """

    agent_id: str
    subscribed_events: list[str]

    def __init__(self, agent_id: str, daemon_url: str = "ws://localhost:9090/ws"):
        self.agent_id = agent_id
        self.daemon_url = daemon_url
        self._call_counter = count(1)
        self._pending: dict[str, asyncio.Future[dict]] = {}
        self._ws: websockets.ClientConnection | None = None

    @abstractmethod
    async def handle_event(self, session: str, event: EventData) -> None:
        """Process an event. Use self.call_tool() for daemon tools."""

    async def call_tool(self, session: str, name: str, args: dict) -> dict:
        """Call a daemon tool and wait for the result."""
        call_id = str(next(self._call_counter))
        msg = ToolCall(session=session, call_id=call_id, name=name, args=args)

        future: asyncio.Future[dict] = asyncio.get_event_loop().create_future()
        self._pending[call_id] = future

        await self._send(msg)
        return await future

    async def run(self) -> None:
        """Connect to daemon and process events."""
        async for ws in websockets.connect(self.daemon_url):
            self._ws = ws
            logger.info("agent %s connected to %s", self.agent_id, self.daemon_url)

            sub = Subscribe(agent_id=self.agent_id, events=self.subscribed_events)
            await self._send(sub)

            await self._read_loop(ws)
            logger.warning("agent %s disconnected, reconnecting...", self.agent_id)

    async def _read_loop(self, ws: websockets.ClientConnection) -> None:
        async for raw in ws:
            data = raw if isinstance(raw, bytes) else raw.encode()
            base = msgspec.json.decode(data, type=dict)
            msg_type = base.get("type")

            if msg_type == "event":
                event = msgspec.json.decode(data, type=Event)
                asyncio.create_task(self._handle_session(event.session, event.event))

            elif msg_type == "tool_result":
                result = msgspec.json.decode(data, type=ToolResult)
                future = self._pending.pop(result.call_id, None)
                if future and not future.done():
                    future.set_result(result.result)

    async def _handle_session(self, session: str, event: EventData) -> None:
        logger.info("session %s: %s on %s", session, event.type, event.resource)
        await self.handle_event(session, event)
        await self._send(SessionDone(session=session))
        logger.info("session %s: done", session)

    async def _send(self, msg: msgspec.Struct) -> None:
        if self._ws:
            await self._ws.send(msgspec.json.encode(msg))
```

- [ ] **Step 2: Write base agent test**

```python
"""tests/test_base_agent.py"""

import asyncio
import json

import pytest
import websockets

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData


class EchoAgent(BaseAgent):
    """Test agent that echoes events back via a tool call."""

    subscribed_events = ["process_exec"]
    handled_events: list[EventData]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handled_events = []

    async def handle_event(self, session: str, event: EventData) -> None:
        self.handled_events.append(event)
        result = await self.call_tool(session, "echo", {"msg": event.resource})
        self.last_result = result


async def mock_daemon(host: str, port: int, ready: asyncio.Event):
    """Mock daemon that accepts one agent, sends one event, handles one tool call."""
    async def handler(ws):
        # Read subscribe
        sub = json.loads(await ws.recv())
        assert sub["type"] == "subscribe"
        assert sub["agent_id"] == "test-echo"

        # Send event
        await ws.send(json.dumps({
            "type": "event",
            "session": "sess-1",
            "event": {
                "type": "process_exec",
                "resource": "pid:42",
                "data": {"comm": "ls"},
                "timestamp": "2026-04-04T12:00:00Z",
            },
        }))

        # Read tool_call
        tc = json.loads(await ws.recv())
        assert tc["type"] == "tool_call"
        assert tc["session"] == "sess-1"
        assert tc["name"] == "echo"

        # Send tool_result
        await ws.send(json.dumps({
            "type": "tool_result",
            "session": "sess-1",
            "call_id": tc["call_id"],
            "result": {"ok": True, "data": "echo: pid:42"},
        }))

        # Read session_done
        done = json.loads(await ws.recv())
        assert done["type"] == "session_done"
        assert done["session"] == "sess-1"

        # Close cleanly
        await ws.close()

    async with websockets.serve(handler, host, port):
        ready.set()
        await asyncio.sleep(2)


@pytest.mark.asyncio
async def test_base_agent_connects_and_handles_event():
    ready = asyncio.Event()
    daemon_task = asyncio.create_task(mock_daemon("127.0.0.1", 19090, ready))

    await ready.wait()

    agent = EchoAgent(agent_id="test-echo", daemon_url="ws://127.0.0.1:19090")
    agent_task = asyncio.create_task(agent.run())

    # Wait for the agent to handle the event
    await asyncio.sleep(1)

    assert len(agent.handled_events) == 1
    assert agent.handled_events[0].resource == "pid:42"
    assert agent.last_result == {"ok": True, "data": "echo: pid:42"}

    agent_task.cancel()
    daemon_task.cancel()
```

- [ ] **Step 3: Run tests**

```bash
cd /Users/fimbulwinter/dev/veronica
uv add --dev pytest-asyncio
uv run pytest tests/test_base_agent.py -v
```

Expected: test passes.

- [ ] **Step 4: Commit**

```bash
git add src/veronica/agents/base.py tests/test_base_agent.py pyproject.toml
git commit -m "feat: base agent with WebSocket client and session handling"
```

---

### Task 8: Python — Typer CLI

**Files:**
- Create: `src/veronica/cli/main.py`

**Depends on:** Task 1 (config)

This ports the Go CLI commands to Python/typer.

- [ ] **Step 1: Create cli/main.py**

```python
"""Veronica CLI — manage daemon and VM lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import typer

from veronica.config import VeronicaConfig

app = typer.Typer(help="Control the Veronica daemon running inside the Lima VM.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

cfg = VeronicaConfig()


def _vm_running() -> bool:
    result = subprocess.run(
        ["limactl", "list", "--json"],
        capture_output=True, text=True,
    )
    for line in result.stdout.strip().splitlines():
        inst = json.loads(line)
        if inst.get("name") == cfg.vm_name:
            return inst.get("status") == "Running"
    return False


def _vm_shell(*args: str, check: bool = True, stream: bool = True) -> subprocess.CompletedProcess:
    cmd = ["limactl", "shell", cfg.vm_name, "--", *args]
    if stream:
        return subprocess.run(cmd, check=check)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _exec_vm_shell(*args: str) -> None:
    """Replace current process with limactl shell (for interactive use)."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name, "--", *args])


# --- Top-level commands ---


@app.command()
def start():
    """Ensure the Lima VM is running and start the Veronica systemd service."""
    if not _vm_running():
        typer.echo(f"Starting Lima VM {cfg.vm_name!r}...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        typer.echo(f"Lima VM {cfg.vm_name!r} is already running.")

    typer.echo("Starting systemd service veronica...")
    _vm_shell("sudo", "systemctl", "start", "veronica")


@app.command()
def stop():
    """Stop the Veronica systemd service."""
    typer.echo("Stopping systemd service veronica...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show VM status and daemon service status."""
    typer.echo("=== Lima VM status ===")
    subprocess.run(["limactl", "list", cfg.vm_name])

    typer.echo("\n=== Systemd service status ===")
    _vm_shell("sudo", "systemctl", "status", "veronica", check=False)


@app.command()
def logs():
    """Stream journalctl logs for the Veronica service (Ctrl+C to stop)."""
    _exec_vm_shell("sudo", "journalctl", "-u", "veronica", "-f")


@app.command()
def build():
    """Build the daemon in the VM, install it, and restart the service."""
    typer.echo("Building daemon inside VM...")
    _vm_shell(
        "bash", "-c",
        f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}",
    )
    typer.echo("Restarting service...")
    _vm_shell("sudo", "systemctl", "restart", "veronica")


@app.command()
def setup():
    """Full setup: vmlinux.h, compile eBPF, generate Go bindings, build daemon, install service."""
    if not _vm_running():
        typer.echo("VM is not running — run `veronica vm start` first", err=True)
        raise typer.Exit(1)

    ebpf_dir = f"{cfg.project_path}/internal/ebpf/programs"

    typer.echo("1/5 Generating vmlinux.h...")
    _vm_shell("bash", "-c", f"cd {ebpf_dir} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")

    typer.echo("2/5 Compiling eBPF programs...")
    for prog in ["process_exec", "file_open", "net_connect", "process_exit"]:
        _vm_shell("bash", "-c", f"cd {ebpf_dir} && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c {prog}.c -o {prog}.o")
        typer.echo(f"   {prog}.o OK")

    typer.echo("3/5 Generating Go bindings (bpf2go)...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto go generate ./internal/ebpf/bpf/")

    typer.echo("4/5 Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")

    typer.echo("5/5 Installing systemd service...")
    _vm_shell("sudo", "cp", f"{cfg.project_path}/lima/veronica.service", "/etc/systemd/system/veronica.service")
    _vm_shell("sudo", "systemctl", "daemon-reload")
    _vm_shell("sudo", "systemctl", "enable", "veronica")

    typer.echo("Setup complete. Run `veronica start` to start the daemon.")


@app.command()
def run(args: list[str] = typer.Argument(help="Command to run inside the VM")):
    """Run a command inside the VM."""
    _vm_shell(*args)


# --- VM subcommands ---


@vm_app.command("start")
def vm_start():
    """Start the Lima VM."""
    subprocess.run(["limactl", "start", cfg.vm_name], check=True)


@vm_app.command("stop")
def vm_stop():
    """Stop the Lima VM."""
    subprocess.run(["limactl", "stop", cfg.vm_name], check=True)


@vm_app.command("ssh")
def vm_ssh():
    """Open an interactive shell in the Lima VM."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name])
```

- [ ] **Step 2: Verify CLI installs**

```bash
cd /Users/fimbulwinter/dev/veronica
uv tool install -e .
veronica --help
```

Expected: shows help with all commands (start, stop, status, logs, build, setup, run, vm).

- [ ] **Step 3: Commit**

```bash
git add src/veronica/cli/main.py
git commit -m "feat: python typer CLI replacing Go CLI"
```

---

### Task 9: Python — Individual agents

**Files:**
- Create: `src/veronica/agents/network.py`
- Create: `src/veronica/agents/filesystem.py`
- Create: `src/veronica/agents/process.py`

**Depends on:** Task 7 (base agent)

These are starter agents — each subscribes to its event types and has a system prompt. The LLM integration is left as a placeholder (the handle_event logs the event and demonstrates a tool call). Real LLM harness integration comes later.

- [ ] **Step 1: Create agents/network.py**

```python
"""Network agent — handles net_connect events."""

from __future__ import annotations

import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's network agent. You monitor TCP connections via eBPF.
When you receive a net_connect event, analyze the destination IP and port.
Flag suspicious outbound connections. Use shell_read to investigate (ss, ip, dig).
Use request_action to block traffic if needed."""


class NetworkAgent(BaseAgent):
    subscribed_events = ["net_connect"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("network event: %s %s", event.resource, event.data)
        # TODO: wire LLM harness here — for now, just investigate with a tool call
        result = await self.call_tool(session, "shell_read", {"cmd": "ss", "args": ["-tnp"]})
        logger.info("ss output: %s", result)


def main():
    import asyncio
    logging.basicConfig(level=logging.INFO)
    agent = NetworkAgent(agent_id="network-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create agents/filesystem.py**

```python
"""Filesystem agent — handles file_open events."""

from __future__ import annotations

import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's filesystem agent. You monitor file access via eBPF.
When you receive a file_open event, check if the access is expected.
Flag access to sensitive files (shadow, SSH keys, crontabs).
Use read_file and shell_read to investigate. Use request_action to enforce policies."""


class FilesystemAgent(BaseAgent):
    subscribed_events = ["file_open"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("filesystem event: %s %s", event.resource, event.data)
        filename = event.data.get("filename", "")
        result = await self.call_tool(session, "shell_read", {"cmd": "stat", "args": [filename]})
        logger.info("stat output: %s", result)


def main():
    import asyncio
    logging.basicConfig(level=logging.INFO)
    agent = FilesystemAgent(agent_id="filesystem-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create agents/process.py**

```python
"""Process agent — handles process_exec, process_exit, and batch events."""

from __future__ import annotations

import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's process agent. You monitor process lifecycle via eBPF.
When you receive a process_exec event, analyze the command. Look for:
- Project scaffolding opportunities (user created a directory, cloned a repo)
- Suspicious binaries from non-standard paths
- Service crashes (process_exit with non-zero code)
Use shell_read to investigate (ps, ls, cat). Use request_action to take action."""


class ProcessAgent(BaseAgent):
    subscribed_events = ["process_exec", "process_exit", "batch"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("process event: %s %s", event.resource, event.data)
        comm = event.data.get("comm", "")
        result = await self.call_tool(session, "shell_read", {"cmd": "ps", "args": ["aux"]})
        logger.info("ps output length: %d", len(str(result)))


def main():
    import asyncio
    logging.basicConfig(level=logging.INFO)
    agent = ProcessAgent(agent_id="process-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all Python tests**

```bash
cd /Users/fimbulwinter/dev/veronica
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/veronica/agents/
git commit -m "feat: network, filesystem, and process agents"
```

---

## Post-Implementation Notes

**What's deferred:**
- eBPF map/program tool implementations (stubs for now — needs eBPF manager interface refactor to avoid circular deps)
- Real LLM harness integration in individual agents (each agent has a system prompt ready, but handle_event just does a demo tool call)
- `goccy/go-json` drop-in replacement in Go code (added as dep, can swap `encoding/json` imports later)

**Integration test flow (manual, in VM):**
1. `veronica build` — build and deploy daemon
2. `veronica start` — start daemon in VM
3. `python -m veronica.agents.process` — run process agent on host
4. Run something in VM → eBPF event → daemon routes to agent → agent calls tool → done
