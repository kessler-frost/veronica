package nats

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

	"github.com/nats-io/nats.go/jetstream"

	"github.com/fimbulwinter/veronica/internal/classifier"
	"github.com/fimbulwinter/veronica/internal/event"
)

type Publisher struct {
	js           jetstream.JetStream
	classifier   *classifier.Classifier
	executorPIDs sync.Map
}

type eventPayload struct {
	Type      string          `json:"type"`
	Resource  string          `json:"resource"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
	Category  string          `json:"category"`
}

func NewPublisher(js jetstream.JetStream, cls *classifier.Classifier) *Publisher {
	p := &Publisher{js: js, classifier: cls}
	cls.IsOurPID = p.IsOurPID
	return p
}

func (p *Publisher) IsOurPID(pid uint32) bool {
	_, ok := p.executorPIDs.Load(pid)
	if ok {
		return true
	}
	// Check if parent is tracked (catches children of bash -c "command")
	ppid := readPPID(pid)
	if ppid > 0 {
		_, ok = p.executorPIDs.Load(ppid)
		if ok {
			return true
		}
		// Check grandparent too (bash → sh → actual command)
		gppid := readPPID(ppid)
		if gppid > 0 {
			_, ok = p.executorPIDs.Load(gppid)
			return ok
		}
	}
	return false
}

// readPPID reads the parent PID from /proc/{pid}/stat.
func readPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Format: pid (comm) state ppid ...
	// comm can contain spaces/parens, so find the LAST ")" then parse fields after it
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

func (p *Publisher) TrackPID(pid uint32)   { p.executorPIDs.Store(pid, true) }
func (p *Publisher) UntrackPID(pid uint32) { p.executorPIDs.Delete(pid) }

func (p *Publisher) Publish(ctx context.Context, ev event.Event) classifier.EventCategory {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	category := p.classifier.Classify(ev)
	if category == classifier.CategorySilent {
		return category
	}
	subject := "events." + ev.Type
	payload := eventPayload{
		Type:      ev.Type,
		Resource:  ev.Resource,
		Data:      json.RawMessage(ev.Data),
		Timestamp: ev.Timestamp.Format(time.RFC3339Nano),
		Category:  category.String(),
	}
	data, _ := json.Marshal(payload)
	_, err := p.js.Publish(ctx, subject, data)
	if err != nil {
		log.Printf("publish to %s: %v", subject, err)
	}
	return category
}

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
