package af

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/fimbulwinter/veronica/internal/classifier"
	"github.com/fimbulwinter/veronica/internal/event"
)

// Publisher classifies eBPF events and pushes them to behavior agents
// via the Agentfield control plane.
type Publisher struct {
	ag         *agent.Agent
	classifier *classifier.Classifier
	tracker    *PIDTracker
}

type eventPayload struct {
	Type      string          `json:"type"`
	Resource  string          `json:"resource"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
	Category  string          `json:"category"`
}

func NewPublisher(ag *agent.Agent, cls *classifier.Classifier, tracker *PIDTracker) *Publisher {
	p := &Publisher{ag: ag, classifier: cls, tracker: tracker}
	cls.IsOurPID = p.IsOurPID
	return p
}

func (p *Publisher) IsOurPID(pid uint32) bool {
	current := pid
	for range 10 {
		if p.tracker.IsTracked(current) {
			return true
		}
		parent := readPPID(current)
		if parent == 0 || parent == 1 || parent == current {
			return false
		}
		current = parent
	}
	return false
}

func readPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	i := strings.LastIndex(s, ")")
	if i == -1 || i+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(ppid)
}

// Publish classifies an event and pushes it to behavior agents via the control plane.
func (p *Publisher) Publish(ctx context.Context, ev event.Event) classifier.EventCategory {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	category := p.classifier.Classify(ev)
	if category == classifier.CategorySilent {
		return category
	}

	payload := eventPayload{
		Type:      ev.Type,
		Resource:  ev.Resource,
		Data:      json.RawMessage(ev.Data),
		Timestamp: ev.Timestamp.Format(time.RFC3339Nano),
		Category:  category.String(),
	}

	// Push event to all behavior agents subscribed to this event type
	// via the "receive_event" reasoner on the behavior agents.
	data, _ := json.Marshal(payload)
	_, err := p.ag.Call(ctx, "behavior/receive_event", map[string]any{
		"event": string(data),
	})
	if err != nil {
		// Not fatal — behavior agents may not be running yet
		log.Printf("publish %s: %v", ev.Type, err)
	}

	return category
}

// Run reads events from the channel, classifies, and publishes.
func (p *Publisher) Run(ctx context.Context, events <-chan event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			p.Publish(ctx, ev)
		}
	}
}
