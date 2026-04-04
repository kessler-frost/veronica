package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/fimbulwinter/veronica/internal/agent"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	SystemPrompt   string
	MaxTurns       int
	ActionExecutor func(Action) (string, error) // executes approved actions; nil = auto-approve with "ok"
}

// Coordinator receives events, spawns agent goroutines, and serializes actions.
type Coordinator struct {
	client   *llm.Client
	store    *state.Store
	config   Config
	events   chan Event
	actions  chan ActionRequest
	reports  chan Report
	inFlight map[string]string // resource -> agentID currently acting on it
}

// New creates a coordinator.
func New(client *llm.Client, store *state.Store, cfg Config) *Coordinator {
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 10
	}
	return &Coordinator{
		client:   client,
		store:    store,
		config:   cfg,
		events:   make(chan Event, 64),
		actions:  make(chan ActionRequest, 64),
		reports:  make(chan Report, 256),
		inFlight: make(map[string]string),
	}
}

// Start begins the coordinator's event processing and action queue loops.
func (c *Coordinator) Start(ctx context.Context) {
	go c.eventLoop(ctx)
	go c.actionLoop(ctx)
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
			c.store.RecordEvent(state.Event{
				Type:      event.Type,
				Resource:  event.Resource,
				Data:      event.Data,
				Timestamp: event.Timestamp,
			})
			go c.spawnAgent(ctx, event)
		}
	}
}

func (c *Coordinator) spawnAgent(ctx context.Context, event Event) {
	agentID := agentIDFor(event)

	c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "active",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("%s on %s", event.Type, event.Resource),
	})

	toolkit := NewToolkit(c.actions, agentID)

	userMsg := fmt.Sprintf("eBPF event: type=%s resource=%s data=%s\nHandle this event.", event.Type, event.Resource, event.Data)

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: c.config.SystemPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, userMsg)

	if err != nil {
		log.Printf("agent %s error: %v", agentID, err)
		c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "error", Result: err.Error(),
		})
	} else {
		c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "completed", Result: result.Response,
		})
	}

	c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
	})
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
				Detail:    fmt.Sprintf("%s on %s", req.Action.Type, req.Action.Resource),
			})

			// Check for conflict
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
					Detail:    output,
				})
				c.store.AppendAgentLog(req.AgentID, state.LogEntry{
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
		// drop if observer is slow
	}
}

func agentIDFor(event Event) string {
	domain := event.Type
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", domain, hex.EncodeToString(b))
}
