package nats

import (
	"context"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/fimbulwinter/veronica/internal/classifier"
	"github.com/fimbulwinter/veronica/internal/event"
)

func newTestPublisher(t *testing.T) (*Publisher, *Server) {
	t.Helper()
	srv, err := Start(Config{Port: 0, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(srv.Close)
	pub := NewPublisher(srv.JS(), classifier.New())
	return pub, srv
}

func streamMsgCount(t *testing.T, srv *Server) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := srv.JS().Stream(ctx, "EVENTS")
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	return info.State.Msgs
}

func TestPublisher_SilentEventDropped(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx := context.Background()

	// veronicad is self — classified silent
	ev := event.Event{
		Type:     "process_exec",
		Resource: "pid:1",
		Data:     `{"comm":"veronicad","pid":1}`,
	}
	cat := pub.Publish(ctx, ev)
	if cat != classifier.CategorySilent {
		t.Fatalf("expected silent, got %s", cat)
	}
	if count := streamMsgCount(t, srv); count != 0 {
		t.Fatalf("expected 0 messages in stream, got %d", count)
	}
}

func TestPublisher_PassEventPublished(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx := context.Background()

	// nginx exit → passes through to NATS
	ev := event.Event{
		Type:     "process_exit",
		Resource: "pid:99",
		Data:     `{"comm":"nginx","pid":99,"exit_code":1}`,
	}
	cat := pub.Publish(ctx, ev)
	if cat != classifier.CategoryPass {
		t.Fatalf("expected pass, got %s", cat)
	}
	if count := streamMsgCount(t, srv); count != 1 {
		t.Fatalf("expected 1 message in stream, got %d", count)
	}
}

func TestPublisher_PassEventCorrectSubject(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ev := event.Event{
		Type:     "process_exit",
		Resource: "pid:99",
		Data:     `{"comm":"nginx","pid":99,"exit_code":1}`,
	}
	pub.Publish(ctx, ev)

	// Create an ephemeral consumer filtered to the exact subject
	stream, _ := srv.JS().Stream(ctx, "EVENTS")
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		FilterSubject: "events.process_exit",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("fetch message: %v", err)
	}
	if msg.Subject() != "events.process_exit" {
		t.Fatalf("expected subject events.process_exit, got %s", msg.Subject())
	}
}

func TestPublisher_PayloadJSON(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	ev := event.Event{
		Type:      "process_exit",
		Resource:  "pid:99",
		Data:      `{"comm":"nginx","pid":99,"exit_code":1}`,
		Timestamp: ts,
	}
	pub.Publish(ctx, ev)

	stream, _ := srv.JS().Stream(ctx, "EVENTS")
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("fetch message: %v", err)
	}

	var payload eventPayload
	if err := json.Unmarshal(msg.Data(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if payload.Type != "process_exit" {
		t.Errorf("type: want process_exit, got %s", payload.Type)
	}
	if payload.Resource != "pid:99" {
		t.Errorf("resource: want pid:99, got %s", payload.Resource)
	}
	if payload.Category != "pass" {
		t.Errorf("category: want pass, got %s", payload.Category)
	}
	if payload.Timestamp != "2026-04-04T12:00:00Z" {
		t.Errorf("timestamp: want 2026-04-04T12:00:00Z, got %s", payload.Timestamp)
	}

	// Data must be an object, not a JSON string (no double-serialization)
	var dataObj map[string]any
	if err := json.Unmarshal(payload.Data, &dataObj); err != nil {
		t.Fatalf("data is not a JSON object: %v (raw: %s)", err, string(payload.Data))
	}
	if dataObj["comm"] != "nginx" {
		t.Errorf("data.comm: want nginx, got %v", dataObj["comm"])
	}
}

func TestPublisher_RunReadsFromChannel(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan event.Event, 3)
	// nginx exit × 2 (pass), systemd-resolved (silent — daemon prefix)
	events <- event.Event{Type: "process_exit", Resource: "pid:10", Data: `{"comm":"nginx","pid":10,"exit_code":1}`}
	events <- event.Event{Type: "process_exit", Resource: "pid:11", Data: `{"comm":"nginx","pid":11,"exit_code":2}`}
	events <- event.Event{Type: "process_exec", Resource: "pid:12", Data: `{"comm":"systemd-resolved","pid":12}`}

	go pub.Run(ctx, events)

	// Poll until both pass messages land or timeout
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if streamMsgCount(t, srv) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected 2 messages in stream, got %d", streamMsgCount(t, srv))
}

func TestPublisher_TrackedPIDIsSilent(t *testing.T) {
	pub, srv := newTestPublisher(t)
	ctx := context.Background()

	pub.TrackPID(555)
	ev := event.Event{
		Type:     "process_exec",
		Resource: "pid:555",
		Data:     `{"comm":"mkdir","pid":555,"filename":"/tmp/evil"}`,
	}
	cat := pub.Publish(ctx, ev)
	if cat != classifier.CategorySilent {
		t.Fatalf("expected silent for tracked PID, got %s", cat)
	}
	if count := streamMsgCount(t, srv); count != 0 {
		t.Fatalf("expected 0 messages for tracked PID, got %d", count)
	}

	pub.UntrackPID(555)
	// After untracking, event passes through
	cat = pub.Publish(ctx, ev)
	if cat != classifier.CategoryPass {
		t.Fatalf("expected pass after untrack, got %s", cat)
	}
	if count := streamMsgCount(t, srv); count != 1 {
		t.Fatalf("expected 1 message after untrack, got %d", count)
	}
}
