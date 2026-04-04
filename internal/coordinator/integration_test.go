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

func TestIntegration_UrgentEventLifecycle(t *testing.T) {
	store, _ := state.Open(":memory:")
	defer store.Close()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response

		switch callCount {
		case 1:
			// Agent investigates
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "c1", Type: "function",
						Function: llm.FunctionCall{
							Name:      "request_action",
							Arguments: `{"command":"chmod 600 /etc/shadow","reason":"revert dangerous permissions"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		default:
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "Reverted /etc/shadow to 600"},
				FinishReason: "stop",
			}}}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	executedActions := make(chan Action, 1)
	client := llm.NewClient(server.URL, "test")
	c := New(client, store, Config{
		MaxTurns: 10,
		ActionExecutor: func(a Action) (string, error) {
			executedActions <- a
			return "permissions restored", nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	reports := c.Reports()
	c.Start(ctx)

	// Urgent: chmod on sensitive path
	c.HandleEvent(Event{
		Type:     "process_exec",
		Resource: "pid:4521",
		Data:     `{"comm":"chmod","cmdline":"chmod 777 /etc/shadow","filename":"/usr/bin/chmod"}`,
	})

	var gotSpawned, gotActionReq, gotApproved, gotCompleted bool
	deadline := time.After(10 * time.Second)

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
			t.Fatalf("timed out. spawned=%v req=%v approved=%v completed=%v",
				gotSpawned, gotActionReq, gotApproved, gotCompleted)
		}
	}

	if !gotSpawned || !gotActionReq || !gotApproved {
		t.Fatalf("missing reports. spawned=%v req=%v approved=%v",
			gotSpawned, gotActionReq, gotApproved)
	}

	select {
	case a := <-executedActions:
		if a.Type != "shell_exec" {
			t.Fatalf("expected shell_exec, got %s", a.Type)
		}
	default:
		t.Fatal("no action was executed")
	}
}
