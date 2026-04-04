package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func TestIntegration_FullEventLifecycle(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response

		switch callCount {
		case 1:
			// Agent reads a file first (read-only, no coordinator)
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c1", Type: "function",
						Function: llm.FunctionCall{
							Name:      "shell_read",
							Arguments: `{"cmd":"echo","args":["process info"]}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 2:
			// Agent requests an action (goes through coordinator)
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c2", Type: "function",
						Function: llm.FunctionCall{
							Name:      "request_action",
							Arguments: `{"command":"cgset -r memory.max=4G /sys/fs/cgroup/system.slice/4521","reason":"limit memory for high-CPU nginx"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 3:
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "Applied 4G memory limit to pid 4521"},
				FinishReason: "stop",
			}}}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	executedActions := make(chan Action, 1)
	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		SystemPrompt: "You manage Linux systems via eBPF.",
		MaxTurns:     10,
		ActionExecutor: func(a Action) (string, error) {
			executedActions <- a
			return "cgroup limit applied", nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Send an event
	c.HandleEvent(Event{
		Type:     "process_high_cpu",
		Resource: "pid:4521",
		Data:     `{"comm":"nginx","cpu_pct":95}`,
	})

	// Collect reports until we see "completed"
	var gotSpawned, gotActionReq, gotApproved, gotCompleted bool
	deadline := time.After(5 * time.Second)

	for !gotCompleted {
		select {
		case r := <-reports:
			switch r.EventType {
			case "spawned":
				gotSpawned = true
			case "action_requested":
				gotActionReq = true
			case "action_approved":
				gotApproved = true
			case "completed":
				gotCompleted = true
			}
		case <-deadline:
			t.Fatalf("timed out. spawned=%v action_req=%v approved=%v completed=%v",
				gotSpawned, gotActionReq, gotApproved, gotCompleted)
		}
	}

	if !gotSpawned || !gotActionReq || !gotApproved {
		t.Fatalf("missing reports. spawned=%v action_req=%v approved=%v",
			gotSpawned, gotActionReq, gotApproved)
	}

	// Verify the action was executed
	select {
	case a := <-executedActions:
		if a.Type != "shell_exec" {
			t.Fatalf("expected shell_exec, got %s", a.Type)
		}
	default:
		t.Fatal("no action was executed")
	}

	// Verify event was recorded in state
	events, _ := store.RecentEvents(10)
	if len(events) == 0 {
		t.Fatal("expected events in store")
	}
	if events[0].Type != "process_high_cpu" {
		t.Fatalf("expected process_high_cpu, got %s", events[0].Type)
	}
}
