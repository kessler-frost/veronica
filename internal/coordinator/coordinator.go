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
	"time"

	"github.com/fimbulwinter/veronica/internal/agent"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	SystemPrompt   string
	MaxTurns       int
	TurnTimeout    time.Duration // per-LLM-call timeout; default 30s
	ActionExecutor func(Action) (string, error)
}

// Coordinator receives events, spawns agent goroutines, and serializes actions.
type Coordinator struct {
	client       *llm.Client
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
func New(client *llm.Client, store *state.Store, cfg Config) *Coordinator {
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 10
	}
	if cfg.TurnTimeout <= 0 {
		cfg.TurnTimeout = 30 * time.Second
	}
	c := &Coordinator{
		client:     client,
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
				go c.spawnUrgentAgent(ctx, event)
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
			go c.spawnBatchAgent(ctx, events)
		}
	}
}

func (c *Coordinator) spawnUrgentAgent(ctx context.Context, event Event) {
	agentID := fmt.Sprintf("urgent-%s", hex.EncodeToString(randBytes()))
	startTime := time.Now()

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("URGENT: %s on %s", event.Type, event.Resource),
		Status: "active",
	})

	comm := commFromData(event.Data)
	cmdline := cmdlineFromData(event.Data)
	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("URGENT %s comm=%s cmdline=%s", event.Resource, comm, cmdline),
	})

	toolkit := NewToolkit(c.actions, agentID)
	userMsg := fmt.Sprintf("URGENT eBPF event: type=%s resource=%s data=%s", event.Type, event.Resource, event.Data)

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: urgentPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, userMsg)

	duration := time.Since(startTime)
	if err != nil {
		log.Printf("urgent agent %s error after %s: %v", agentID, duration.Round(time.Second), err)
	} else {
		log.Printf("urgent agent %s done in %s (%d turns): %s", agentID, duration.Round(time.Second), result.Turns, truncate(result.Response, 100))
		_ = c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "completed", Result: result.Response,
		})
	}

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("URGENT: %s on %s", event.Type, event.Resource),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
		Detail:    fmt.Sprintf("took %s", duration.Round(time.Second)),
	})
}

func (c *Coordinator) spawnBatchAgent(ctx context.Context, events []Event) {
	agentID := fmt.Sprintf("batch-%s", hex.EncodeToString(randBytes()))
	startTime := time.Now()

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("batch: %d events", len(events)),
		Status: "active",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("batch: %d events", len(events)),
	})

	// Record non-trivial events to store
	for _, e := range events {
		_ = c.store.RecordEvent(state.Event{
			Type: e.Type, Resource: e.Resource,
			Data: e.Data, Timestamp: e.Timestamp,
		})
	}

	toolkit := NewToolkit(c.actions, agentID)

	// Build summary for LLM
	var summary strings.Builder
	typeCounts := make(map[string]int)
	for _, e := range events {
		typeCounts[e.Type]++
	}
	fmt.Fprintf(&summary, "Batch of %d eBPF events from the last %s:\n\n", len(events), c.batch.interval)
	for t, count := range typeCounts {
		fmt.Fprintf(&summary, "  %s: %d events\n", t, count)
	}
	summary.WriteString("\nEvents (newest last):\n")
	// Show all events (up to 30)
	start := 0
	if len(events) > 30 {
		start = len(events) - 30
	}
	for _, e := range events[start:] {
		comm := commFromData(e.Data)
		cmdline := cmdlineFromData(e.Data)
		if cmdline == "" {
			cmdline = comm
		}
		fmt.Fprintf(&summary, "  [%s] %s — %s\n", e.Type, e.Resource, cmdline)
	}

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: batchPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, summary.String())

	duration := time.Since(startTime)
	if err != nil {
		log.Printf("batch agent %s error after %s: %v", agentID, duration.Round(time.Second), err)
	} else {
		log.Printf("batch agent %s done in %s (%d turns): %s", agentID, duration.Round(time.Second), result.Turns, truncate(result.Response, 150))
		_ = c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "batch", Result: result.Response,
		})
	}

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("batch: %d events", len(events)),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
		Detail:    fmt.Sprintf("batch: %d events, took %s", len(events), duration.Round(time.Second)),
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

func cmdlineFromData(data string) string {
	var payload struct {
		Cmdline string `json:"cmdline"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ""
	}
	return payload.Cmdline
}

// urgentPrompt is for immediate high-priority events (security, crashes).
const urgentPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux OS. You received an URGENT event that needs immediate attention.

This event bypassed the normal batch queue because it matches a critical pattern:
- Service crash (non-zero exit code)
- Sensitive file access (shadow, passwd, sudoers, SSH keys)
- Unknown binary from non-standard path

You have three tools:
- read_file: read any file
- shell_read: run read-only commands (ls, ps, cat, stat, nginx -t, journalctl, etc.)
- request_action: execute any shell command ({"command": "...", "reason": "..."})

Investigate immediately and take corrective action if needed. Be decisive.`

// batchPrompt is for periodic batch of events — the main workhorse.
const batchPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux OS. You see everything happening via eBPF.

You will receive a batch of recent events (last 5 seconds). Most events are routine OS activity. Your job:

1. Scan ALL events in the batch
2. Identify anything that needs action (project scaffolding, setup, optimization)
3. Ignore routine events (ls, ps, system processes, etc.)
4. Take action on interesting events

You have three tools:
- read_file: read any file
- shell_read: run read-only commands (ls, ps, cat, stat, find, grep, nginx -t, etc.)
- request_action: execute any shell command ({"command": "...", "reason": "..."})

Common actions:
- User created a project directory → scaffold it (uv init for Python, go mod init for Go, etc.)
- User cloned a repo → check for dependency files and install them
- Service exited with error → investigate and fix
- Download completed → extract if archive

If nothing needs action, respond with just: "No action needed."
If a tool is not installed, request_action will auto-install it.
Be concise. Act or don't.`
