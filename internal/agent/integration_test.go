package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/tool"
)

func TestIntegration_MultiToolConversation(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		var req llm.Request
		json.NewDecoder(r.Body).Decode(&req)

		var resp llm.Response

		switch callCount {
		case 1:
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "call_1", Type: "function",
						Function: llm.FunctionCall{Name: "list_procs", Arguments: `{}`},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 2:
			lastMsg := req.Messages[len(req.Messages)-1]
			if !strings.Contains(lastMsg.Content, "nginx") {
				t.Fatalf("expected tool result containing 'nginx', got %q", lastMsg.Content)
			}
			resp = llm.Response{Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID: "call_2", Type: "function",
						Function: llm.FunctionCall{Name: "read_proc", Arguments: `{"pid":42}`},
					}},
				},
				FinishReason: "tool_calls",
			}}}
		case 3:
			resp = llm.Response{Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "nginx (pid 42) is using 2.1GB memory"},
				FinishReason: "stop",
			}}}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	type EmptyArgs struct{}
	type ProcArgs struct {
		PID int `json:"pid" desc:"Process ID"`
	}

	client := llm.NewClient(server.URL, "test")
	reg := tool.NewRegistry()

	tool.Register(reg, "list_procs", "List running processes", func(ctx context.Context, args EmptyArgs) (any, error) {
		return []map[string]any{
			{"pid": 1, "name": "init"},
			{"pid": 42, "name": "nginx"},
		}, nil
	})

	tool.Register(reg, "read_proc", "Read process details", func(ctx context.Context, args ProcArgs) (any, error) {
		return map[string]any{
			"pid": args.PID, "name": "nginx", "rss_mb": 2100, "cpu_pct": 12.5,
		}, nil
	})

	result, err := Run(context.Background(), client, reg, Config{
		SystemPrompt: "You manage Linux systems.",
		MaxTurns:     10,
	}, "what is using the most memory?")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Turns != 3 {
		t.Fatalf("expected 3 turns, got %d", result.Turns)
	}
	if !strings.Contains(result.Response, "nginx") {
		t.Fatalf("expected response mentioning nginx, got %q", result.Response)
	}
	// system + user + assistant(tc) + tool + assistant(tc) + tool + assistant(final) = 7
	if len(result.History) != 7 {
		t.Fatalf("expected 7 messages in history, got %d", len(result.History))
	}
}
