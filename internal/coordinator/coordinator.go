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
	ActionExecutor func(Action) (string, error) // executes approved actions; nil = auto-approve with "ok"
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
	inFlight     map[string]string // resource -> agentID currently acting on it
	executorPIDs sync.Map          // pid (uint32) -> true; PIDs of commands we spawned
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

			// Only record non-silent events
			if category != CategorySilent {
				if err := c.store.RecordEvent(state.Event{
					Type:      event.Type,
					Resource:  event.Resource,
					Data:      event.Data,
					Timestamp: event.Timestamp,
				}); err != nil {
					log.Printf("record event: %v", err)
				}
			}

			switch category {
			case CategorySilent:
				// nothing to do
			case CategoryPolicy:
				// TODO: enforce from eBPF map directly
			case CategoryImmediate:
				if c.filter.ShouldProcess(event) {
					c.filter.AgentStarted()
					go func() {
						defer c.filter.AgentFinished()
						c.spawnAgent(ctx, event, promptForImmediate(event))
					}()
				}
			case CategoryProactive:
				if c.filter.ShouldProcess(event) {
					c.filter.AgentStarted()
					go func() {
						defer c.filter.AgentFinished()
						c.spawnAgent(ctx, event, promptForProactive(event))
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

func (c *Coordinator) spawnAgent(ctx context.Context, event Event, systemPrompt string) {
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

	userMsg := fmt.Sprintf("eBPF event: type=%s resource=%s data=%s", event.Type, event.Resource, event.Data)

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: systemPrompt,
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

	// Build summary
	typeCounts := make(map[string]int)
	for _, e := range events {
		typeCounts[e.Type]++
	}
	summary := fmt.Sprintf("Activity digest (%d events in last %s):\n", len(events), c.digest.interval)
	for t, count := range typeCounts {
		summary += fmt.Sprintf("  %s: %d events\n", t, count)
	}
	summary += "\nRecent events:\n"
	// Show last 10 events
	start := len(events) - 10
	if start < 0 {
		start = 0
	}
	for _, e := range events[start:] {
		summary += fmt.Sprintf("  [%s] %s: %s\n", e.Type, e.Resource, e.Data)
	}

	result, err := agent.Run(ctx, c.client, toolkit, agent.Config{
		SystemPrompt: promptForDigest(),
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

func randBytes() []byte {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return b
}

func promptForImmediate(event Event) string {
	comm := commFromData(event.Data)
	cmdline := cmdlineFromData(event.Data)
	return fmt.Sprintf(`You are Veronica, an autonomous OS intelligence layer. You received a HIGH-PRIORITY event.

Command: %s
Full cmdline: %s
Event type: %s
Resource: %s

Assess and act:
- Sensitive file access (shadow, passwd, sudoers, SSH keys) → check if the access is legitimate, revert unauthorized changes
- Service crash (process_exit with non-zero code) → read the error log, diagnose, fix if possible, restart
- Dangerous permission changes (chmod 777 on sensitive files) → revert to safe permissions
- Suspicious network connection → investigate the destination, block if unknown
- Unknown binary from non-standard path → investigate what it is, check if it's malicious

Use read_file and shell_read to investigate. Use request_action with type "shell_exec" to take action.
Be decisive. Act first, log your reasoning.`, comm, cmdline, event.Type, event.Resource)
}

func promptForProactive(event Event) string {
	comm := commFromData(event.Data)
	cmdline := cmdlineFromData(event.Data)
	return fmt.Sprintf(`You are Veronica, an autonomous OS intelligence layer. The user just ran a command that may benefit from proactive assistance.

Command: %s
Full cmdline: %s
Event type: %s
Resource: %s

Analyze the command and its arguments. Take helpful action if appropriate:

- mkdir with a project-like name → scaffold the project:
  - Python-sounding name (api, flask, fastapi, django, cli, bot, scraper) → uv init, uv add appropriate packages, create main entry file
  - JS/TS-sounding name (app, web, next, react, vue) → bun init, set up basic structure
  - Go-sounding name (service, server, cmd) → go mod init, create main.go
  - Generic → just create a README.md

- git clone → after clone completes, check what's in the repo:
  - pyproject.toml or requirements.txt → run uv sync or uv pip install -r requirements.txt
  - package.json → run bun install
  - go.mod → run go mod download
  - .env.example → copy to .env

- curl/wget downloading an archive (.tar.gz, .zip, .tgz) → extract after download completes

- docker/podman run without --memory or --cpus → set reasonable defaults

- uv/pip/npm/bun adding a package → note it in the log (future: security scan)

- ssh-keygen with -t rsa → suggest ed25519 instead

If the command is routine and needs no action, respond with just: "No action needed."
Otherwise, use request_action with type "shell_exec" and args like: {"cmd":"bash","args":["-c","cd /path && uv init && uv add fastapi"]}
`, comm, cmdline, event.Type, event.Resource)
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

func promptForDigest() string {
	return `You are Veronica, an autonomous OS intelligence layer. You are reviewing a periodic digest of system activity.

Analyze the summary and recent events. Look for:
- Anomalies: unusual patterns, unexpected processes, spikes in activity
- Security concerns: suspicious file access, network connections, privilege changes
- Performance issues: resource-heavy processes, repeated crashes
- Opportunities: things you could optimize or automate

If everything looks normal, respond with "System nominal."
If you spot something actionable, use request_action to address it.
Be concise.`
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
