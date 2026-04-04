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

const sessionTimeout = 60 * time.Second

// Protocol message types

type subscribeMsg struct {
	Type    string   `json:"type"`
	AgentID string   `json:"agent_id"`
	Events  []string `json:"events"`
}

type eventMsg struct {
	Type    string    `json:"type"`
	Session string    `json:"session"`
	Event   eventData `json:"event"`
}

type eventData struct {
	Type      string          `json:"type"`
	Resource  string          `json:"resource"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
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

// agentConn represents a connected agent with its subscriptions.
type agentConn struct {
	id     string
	conn   *websocket.Conn
	events map[string]bool
	mu     sync.Mutex
}

func (a *agentConn) send(ctx context.Context, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conn.Write(ctx, websocket.MessageText, data)
}

// session represents an active event session for one agent.
type session struct {
	id       string
	agent    *agentConn
	toolkit  *tool.Registry
	incoming chan toolCallMsg
	done     chan struct{}
}

// Server accepts WebSocket connections from host agents, routes events, and proxies tool calls.
type Server struct {
	addr      string
	toolkitFn func(sessionID string) *tool.Registry
	listener  net.Listener
	mu        sync.RWMutex
	agents    map[string]*agentConn
	sessions  map[string]*session
}

// NewServer creates a WebSocket server on the given address.
func NewServer(addr string, toolkitFn func(sessionID string) *tool.Registry) *Server {
	return &Server{
		addr:      addr,
		toolkitFn: toolkitFn,
		agents:    make(map[string]*agentConn),
		sessions:  make(map[string]*session),
	}
}

// Start binds the listener, serves HTTP, and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	err = srv.Serve(ln)
	if err != nil && ctx.Err() != nil {
		return nil // clean shutdown
	}
	return err
}

// Addr returns the listening address (useful when bound to ":0").
func (s *Server) Addr() string {
	if s.listener == nil {
		return s.addr
	}
	return s.listener.Addr().String()
}

// ConnectedAgents returns the number of currently connected agents.
func (s *Server) ConnectedAgents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

// ActiveSessions returns the number of currently active sessions.
func (s *Server) ActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// RouteEvent implements coordinator.Router — fans out to all subscribed agents.
func (s *Server) RouteEvent(ctx context.Context, event coordinator.Event, category coordinator.EventCategory) {
	s.mu.RLock()
	var targets []*agentConn
	for _, ac := range s.agents {
		if ac.events[event.Type] {
			targets = append(targets, ac)
		}
	}
	s.mu.RUnlock()

	for _, ac := range targets {
		sid := newID()
		sess := s.createSession(sid, ac)
		go s.runSession(ctx, sess)
		s.sendEvent(ctx, ac, sess.id, event)
	}
}

// handleWS upgrades the connection, reads the subscribe message, then starts the read loop.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("ws accept: %v", err)
		return
	}

	ac, err := s.readSubscribe(r.Context(), conn)
	if err != nil {
		log.Printf("ws subscribe: %v", err)
		_ = conn.Close(websocket.StatusPolicyViolation, "subscribe required")
		return
	}

	s.mu.Lock()
	s.agents[ac.id] = ac
	s.mu.Unlock()

	log.Printf("ws: agent %s connected, subscribed to %v", ac.id, ac.events)

	s.readLoop(r.Context(), ac)

	s.mu.Lock()
	delete(s.agents, ac.id)
	// Close all sessions for this agent
	for id, sess := range s.sessions {
		if sess.agent == ac {
			select {
			case <-sess.done:
			default:
				close(sess.done)
			}
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()

	log.Printf("ws: agent %s disconnected", ac.id)
	_ = conn.Close(websocket.StatusNormalClosure, "bye")
}

// readSubscribe reads the first message and expects a subscribe payload.
func (s *Server) readSubscribe(ctx context.Context, conn *websocket.Conn) (*agentConn, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var msg subscribeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if msg.Type != "subscribe" || msg.AgentID == "" {
		return nil, fmt.Errorf("expected subscribe with agent_id, got type=%q agent_id=%q", msg.Type, msg.AgentID)
	}
	evSet := make(map[string]bool, len(msg.Events))
	for _, e := range msg.Events {
		evSet[e] = true
	}
	return &agentConn{id: msg.AgentID, conn: conn, events: evSet}, nil
}

// readLoop reads messages from the agent and dispatches tool_call / session_done.
func (s *Server) readLoop(ctx context.Context, ac *agentConn) {
	for {
		_, data, err := ac.conn.Read(ctx)
		if err != nil {
			return
		}

		var raw struct {
			Type    string `json:"type"`
			Session string `json:"session"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			log.Printf("ws readloop: unmarshal type: %v", err)
			continue
		}

		switch raw.Type {
		case "tool_call":
			var msg toolCallMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				log.Printf("ws readloop: unmarshal tool_call: %v", err)
				continue
			}
			s.mu.RLock()
			sess, ok := s.sessions[msg.Session]
			s.mu.RUnlock()
			if ok {
				sess.incoming <- msg
			}

		case "session_done":
			s.mu.RLock()
			sess, ok := s.sessions[raw.Session]
			s.mu.RUnlock()
			if ok {
				select {
				case <-sess.done:
				default:
					close(sess.done)
				}
			}
		}
	}
}

// createSession registers a new session and returns it.
func (s *Server) createSession(sid string, ac *agentConn) *session {
	sess := &session{
		id:       sid,
		agent:    ac,
		toolkit:  s.toolkitFn(sid),
		incoming: make(chan toolCallMsg, 16),
		done:     make(chan struct{}),
	}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.mu.Unlock()
	return sess
}

// runSession waits for tool_calls, dispatches them, and sends results back.
func (s *Server) runSession(ctx context.Context, sess *session) {
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess.id)
		s.mu.Unlock()
	}()

	timer := time.NewTimer(sessionTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.done:
			return
		case <-timer.C:
			log.Printf("ws: session %s timed out", sess.id)
			return
		case msg := <-sess.incoming:
			result, err := sess.toolkit.Call(ctx, msg.Name, string(msg.Args))
			var resultVal any
			if err != nil {
				resultVal = map[string]string{"error": err.Error()}
			} else {
				resultVal = result
			}
			resp := toolResultMsg{
				Type:    "tool_result",
				Session: sess.id,
				CallID:  msg.CallID,
				Result:  resultVal,
			}
			if err := sess.agent.send(ctx, resp); err != nil {
				log.Printf("ws: session %s send result error: %v", sess.id, err)
				return
			}
			// Reset timeout on activity
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(sessionTimeout)
		}
	}
}

// sendEvent marshals an event message and sends it to the agent.
func (s *Server) sendEvent(ctx context.Context, ac *agentConn, sessionID string, event coordinator.Event) {
	raw := json.RawMessage(event.Data)
	msg := eventMsg{
		Type:    "event",
		Session: sessionID,
		Event: eventData{
			Type:      event.Type,
			Resource:  event.Resource,
			Data:      raw,
			Timestamp: event.Timestamp.Format(time.RFC3339Nano),
		},
	}
	if err := ac.send(ctx, msg); err != nil {
		log.Printf("ws: send event to agent %s: %v", ac.id, err)
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
