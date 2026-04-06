package af

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/fimbulwinter/veronica/internal/classifier"
	"github.com/fimbulwinter/veronica/internal/event"
)

// Subscriber is a behavior agent that has registered for specific events.
type Subscriber struct {
	NodeID      string   `json:"node_id"`      // e.g. "veronica-a1b2c3d4"
	Events      []string `json:"events"`        // e.g. ["process_exec", "file_open"]
	CommFilter  []string `json:"comm_filter"`   // e.g. ["mkdir", "chmod"] — empty = all
}

// Publisher classifies eBPF events and pushes them only to subscribed
// behavior agents via the Agentfield control plane.
type Publisher struct {
	ag         *agent.Agent
	classifier *classifier.Classifier
	tracker    *PIDTracker

	mu          sync.RWMutex
	subscribers map[string]*Subscriber // keyed by node_id
}

type eventPayload struct {
	Type      string          `json:"type"`
	Resource  string          `json:"resource"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
	Category  string          `json:"category"`
}

func NewPublisher(ag *agent.Agent, cls *classifier.Classifier, tracker *PIDTracker) *Publisher {
	p := &Publisher{
		ag:          ag,
		classifier:  cls,
		tracker:     tracker,
		subscribers: make(map[string]*Subscriber),
	}
	cls.IsOurPID = p.IsOurPID
	return p
}

// Subscribe registers a behavior agent for specific event types.
// Called via the "subscribe" skill on the daemon.
func (p *Publisher) Subscribe(sub Subscriber) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subscribers[sub.NodeID] = &sub
	log.Printf("subscriber added: %s events=%v comm_filter=%v", sub.NodeID, sub.Events, sub.CommFilter)
}

// Unsubscribe removes a behavior agent from the subscriber list.
func (p *Publisher) Unsubscribe(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.subscribers, nodeID)
	log.Printf("subscriber removed: %s", nodeID)
}

// matchingSubscribers returns subscribers interested in this event.
func (p *Publisher) matchingSubscribers(eventType string, comm string) []*Subscriber {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var matches []*Subscriber
	for _, sub := range p.subscribers {
		// Check event type
		subscribed := false
		for _, e := range sub.Events {
			if e == eventType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			continue
		}

		// Check comm filter (empty = match all)
		if len(sub.CommFilter) > 0 {
			matched := false
			for _, c := range sub.CommFilter {
				if c == comm {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		matches = append(matches, sub)
	}
	return matches
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

// Publish classifies an event and pushes it only to matching subscribers.
func (p *Publisher) Publish(ctx context.Context, ev event.Event) classifier.EventCategory {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	category := p.classifier.Classify(ev)
	if category == classifier.CategorySilent {
		return category
	}

	// Extract comm for filtering
	comm := event.CommFromData(ev.Data)
	subs := p.matchingSubscribers(ev.Type, comm)
	if len(subs) == 0 {
		return category
	}

	payload := eventPayload{
		Type:      ev.Type,
		Resource:  ev.Resource,
		Data:      json.RawMessage(ev.Data),
		Timestamp: ev.Timestamp.Format(time.RFC3339Nano),
		Category:  category.String(),
	}
	data, _ := json.Marshal(payload)

	for _, sub := range subs {
		_, err := p.ag.Call(ctx, fmt.Sprintf("%s.receive_event", sub.NodeID), map[string]any{
			"event": string(data),
		})
		if err != nil {
			log.Printf("publish %s to %s: %v", ev.Type, sub.NodeID, err)
		}
	}

	return category
}

// Run reads events from the channel, classifies, and publishes to subscribers.
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
