package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	MaxTurns       int
	TurnTimeout    time.Duration // per-LLM-call timeout; default 30s
	ActionExecutor func(Action) (string, error)
}

// Coordinator receives events, spawns agent goroutines, and serializes actions.
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

// ActionChannel returns the channel for receiving action requests from agents.
func (c *Coordinator) ActionChannel() chan ActionRequest {
	return c.actions
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
				agentID := fmt.Sprintf("urgent-%s", hex.EncodeToString(randBytes()))
				comm := commFromData(event.Data)
				cmdline := cmdlineFromData(event.Data)
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
			for _, e := range events {
				_ = c.store.RecordEvent(state.Event{
					Type: e.Type, Resource: e.Resource,
					Data: e.Data, Timestamp: e.Timestamp,
				})
			}
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

func marshalBatchData(events []Event, interval time.Duration) string {
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
			Type: e.Type, Resource: e.Resource,
			Comm: commFromData(e.Data), Cmdline: cmdlineFromData(e.Data), Cwd: cwdFromData(e.Data),
		}
	}
	payload := map[string]any{
		"total": len(events), "unique": len(unique),
		"interval": interval.String(), "events": entries,
	}
	b, _ := json.Marshal(payload)
	return string(b)
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
