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

	"github.com/fimbulwinter/veronica/internal/agent"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

// Config configures the coordinator.
type Config struct {
	SystemPrompt   string
	MaxTurns       int
	ActionExecutor func(Action) (string, error)
}

// Coordinator receives events, spawns agent goroutines, and serializes actions.
type Coordinator struct {
	client       *llm.Client
	store        *state.Store
	config       Config
	classifier   *Classifier
	digest       *Digest
	filter       *Filter
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
	c := &Coordinator{
		client:     client,
		store:      store,
		config:     cfg,
		classifier: NewClassifier(),
		digest:     NewDigest(5 * time.Second),
		filter:     NewFilter(10),
		events:     make(chan Event, 64),
		actions:    make(chan ActionRequest, 64),
		reports:    make(chan Report, 256),
		inFlight:   make(map[string]string),
	}
	c.classifier.IsOurPID = c.IsOurPID
	return c
}

// Start begins the coordinator's event processing, action queue, and digest loops.
func (c *Coordinator) Start(ctx context.Context) {
	go c.eventLoop(ctx)
	go c.actionLoop(ctx)
	go c.digestLoop(ctx)
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
				// nothing
			case CategoryAgent:
				if err := c.store.RecordEvent(state.Event{
					Type: event.Type, Resource: event.Resource,
					Data: event.Data, Timestamp: event.Timestamp,
				}); err != nil {
					log.Printf("record event: %v", err)
				}
				if c.filter.ShouldProcess(event) {
					c.filter.AgentStarted()
					go func() {
						defer c.filter.AgentFinished()
						c.spawnAgent(ctx, event)
					}()
				}
			case CategoryDigest:
				c.digest.Add(event)
			}
		}
	}
}

func (c *Coordinator) digestLoop(ctx context.Context) {
	ticker := time.NewTicker(c.digest.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := c.digest.Flush()
			if len(events) == 0 {
				continue
			}
			c.filter.AgentStarted()
			go func() {
				defer c.filter.AgentFinished()
				c.spawnDigestAgent(ctx, events)
			}()
		}
	}
}

func (c *Coordinator) spawnAgent(ctx context.Context, event Event) {
	agentID := agentIDFor(event)
	startTime := time.Now()

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "active",
	})

	comm := commFromData(event.Data)
	cmdline := cmdlineFromData(event.Data)
	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("%s comm=%s cmdline=%s", event.Resource, comm, cmdline),
	})

	toolkit := NewToolkit(c.actions, agentID)

	userMsg := fmt.Sprintf("eBPF event: type=%s resource=%s data=%s", event.Type, event.Resource, event.Data)

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: agentPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, userMsg)

	duration := time.Since(startTime)

	if err != nil {
		log.Printf("agent %s error after %s: %v", agentID, duration.Round(time.Second), err)
		_ = c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "error", Result: err.Error(),
		})
	} else {
		log.Printf("agent %s done in %s (%d turns): %s", agentID, duration.Round(time.Second), result.Turns, truncate(result.Response, 100))
		_ = c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "completed", Result: result.Response,
		})
	}
	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("%s on %s", event.Type, event.Resource),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
		Detail:    fmt.Sprintf("took %s", duration.Round(time.Second)),
	})
}

func (c *Coordinator) spawnDigestAgent(ctx context.Context, events []Event) {
	agentID := fmt.Sprintf("digest-%s", hex.EncodeToString(randBytes()))

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("digest: %d events", len(events)),
		Status: "active",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "spawned",
		Detail:    fmt.Sprintf("digest: %d events", len(events)),
	})

	toolkit := NewToolkit(c.actions, agentID)

	typeCounts := make(map[string]int)
	for _, e := range events {
		typeCounts[e.Type]++
	}
	summary := fmt.Sprintf("Activity digest (%d events in last %s):\n", len(events), c.digest.interval)
	for t, count := range typeCounts {
		summary += fmt.Sprintf("  %s: %d events\n", t, count)
	}
	summary += "\nRecent events:\n"
	start := len(events) - 10
	if start < 0 {
		start = 0
	}
	for _, e := range events[start:] {
		summary += fmt.Sprintf("  [%s] %s: %s\n", e.Type, e.Resource, e.Data)
	}

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: digestPrompt,
		MaxTurns:     c.config.MaxTurns,
	}, summary)

	if err != nil {
		log.Printf("digest agent %s error: %v", agentID, err)
	} else {
		_ = c.store.AppendAgentLog(agentID, state.LogEntry{
			Action: "digest", Result: result.Response,
		})
	}

	_ = c.store.SetAgentMeta(agentID, state.AgentMeta{
		Task:   fmt.Sprintf("digest: %d events", len(events)),
		Status: "done",
	})

	c.report(Report{
		AgentID:   agentID,
		EventType: "completed",
		Detail:    fmt.Sprintf("digest: %d events processed", len(events)),
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

func agentIDFor(event Event) string {
	domain := event.Type
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", domain, hex.EncodeToString(b))
}

func randBytes() []byte {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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

// agentPrompt is the single generalized prompt for all event agents.
// No hardcoded scenarios — the LLM decides what's interesting and what to do.
const agentPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux operating system. You see everything happening via eBPF — every process, file access, network connection.

You will receive a single eBPF event. Decide if it needs action.

You have three tools:
- read_file: read any file on the system
- shell_read: run read-only commands (ls, ps, cat, stat, df, ip, ss, etc.)
- request_action: execute any shell command ({"command": "...", "reason": "..."})

Guidelines:
- If a user is creating something (directory, project, repo), help set it up.
- If something looks dangerous or unusual, investigate and act.
- If a service crashes, diagnose and fix it.
- If a tool is missing, request_action will auto-install it.
- For long-running commands (git clone, downloads), use shell_read to check if the operation completed and what was created before deciding what to do. For example: check if a cloned repo has pyproject.toml, package.json, go.mod, etc. and install dependencies accordingly.
- If the event is routine and needs no action, respond with just: "No action needed."

Be concise. Don't over-explain. Act or don't.`

// digestPrompt is for the periodic batch summary agent.
const digestPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux operating system. You are reviewing a batch of recent eBPF events.

Look for patterns that individual events wouldn't reveal:
- Repeated failures or crashes
- Unusual spikes in activity
- Security anomalies
- Opportunities to automate or optimize

You have three tools: read_file, shell_read, request_action.

If everything looks normal, respond with just: "System nominal."
If you spot something actionable, use request_action: {"command": "...", "reason": "..."}
Be concise.`
