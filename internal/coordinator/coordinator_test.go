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

func TestCoordinator_HandleEvent(t *testing.T) {
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
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"nginx"}`,
	})

	// Wait for the goroutine to call the LLM
	deadline := time.After(3 * time.Second)
	for !agentSpawned.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for agent to be spawned")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCoordinator_ActionApproved(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response
		if callCount == 1 {
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c1", Type: "function",
						Function: llm.FunctionCall{
							Name:      "request_action",
							Arguments: `{"type":"shell_exec","resource":"pid:42","args":"{\"cmd\":\"echo ok\"}"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		} else {
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "action complete"},
				FinishReason: "stop",
			}}}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
		ActionExecutor: func(action Action) (string, error) {
			return "executed: " + action.Type, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	c.HandleEvent(Event{Type: "process_exec", Resource: "pid:42", Data: `{"comm":"nginx"}`})

	deadline := time.After(3 * time.Second)
	for callCount < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out, only got %d LLM calls", callCount)
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
	c := New(client, store, Config{
		SystemPrompt: "You manage systems.",
		MaxTurns:     10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	c.HandleEvent(Event{Type: "process_exec", Resource: "pid:99", Data: `{"comm":"sudo"}`})

	// Should receive at least a "spawned" report
	select {
	case r := <-reports:
		if r.EventType != "spawned" {
			t.Fatalf("expected spawned report, got %q", r.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for report")
	}
}
