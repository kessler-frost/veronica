package nats

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

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
	return ok
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
