package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func TestCoordinator_UrgentEvent(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	var agentSpawned atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentSpawned.Store(true)
		resp := llm.Response{
			Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "handled"},
				FinishReason: "stop",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// chmod on sensitive path → urgent
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"chmod","cmdline":"chmod 777 /etc/shadow","filename":"/usr/bin/chmod"}`,
	})

	deadline := time.After(5 * time.Second)
	for !agentSpawned.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for urgent agent")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCoordinator_BatchEvent(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	var agentSpawned atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentSpawned.Store(true)
		resp := llm.Response{
			Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "batch handled"},
				FinishReason: "stop",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Regular mkdir → batch
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:42",
		Data:     `{"comm":"mkdir","cmdline":"mkdir /tmp/test","filename":"/usr/bin/mkdir"}`,
	})

	// Wait for batch flush (5s) + LLM call
	deadline := time.After(8 * time.Second)
	for !agentSpawned.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for batch agent")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCoordinator_Reports(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := llm.Response{Choices: []llm.Choice{{
			Message:      llm.Message{Role: "assistant", Content: "done"},
			FinishReason: "stop",
		}}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{MaxTurns: 10})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Urgent event → immediate report
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:99",
		Data:     `{"comm":"suspicious","filename":"/tmp/suspicious"}`,
	})

	select {
	case r := <-reports:
		if r.EventType != "spawned" {
			t.Fatalf("expected spawned report, got %q", r.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for report")
	}
}
