package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/tool"
)

func TestRun_SimpleTextResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := llm.Response{
			Choices: []llm.Choice{{
				Message:      llm.Message{Role: "assistant", Content: "the hostname is web01"},
				FinishReason: "stop",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := llm.NewClient(server.URL, "test")
	reg := tool.NewRegistry()

	result, err := Run(context.Background(), client, reg, Config{
		SystemPrompt: "You are helpful.",
		MaxTurns:     10,
	}, "what is the hostname?")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Response != "the hostname is web01" {
		t.Fatalf("expected 'the hostname is web01', got %q", result.Response)
	}
	if result.Turns != 1 {
		t.Fatalf("expected 1 turn, got %d", result.Turns)
	}
}

func TestRun_ToolCallThenText(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp llm.Response

		if callCount == 1 {
			resp = llm.Response{
				Choices: []llm.Choice{{
					Message: llm.Message{
						Role: "assistant",
						ToolCalls: []llm.ToolCall{{
							ID:   "call_1",
							Type: "function",
							Function: llm.FunctionCall{
								Name:      "read_file",
								Arguments: `{"path":"/etc/hostname"}`,
							},
						}},
					},
					FinishReason: "tool_calls",
				}},
			}
		} else {
			resp = llm.Response{
				Choices: []llm.Choice{{
					Message:      llm.Message{Role: "assistant", Content: "hostname is web01"},
					FinishReason: "stop",
				}},
			}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	type ReadFileArgs struct {
		Path string `json:"path" desc:"File path"`
	}

	client := llm.NewClient(server.URL, "test")
	reg := tool.NewRegistry()
	tool.Register(reg, "read_file", "Read a file", func(ctx context.Context, args ReadFileArgs) (any, error) {
		return "web01", nil
	})

	result, err := Run(context.Background(), client, reg, Config{
		SystemPrompt: "You are helpful.",
		MaxTurns:     10,
	}, "what is the hostname?")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Response != "hostname is web01" {
		t.Fatalf("expected 'hostname is web01', got %q", result.Response)
	}
	if result.Turns != 2 {
		t.Fatalf("expected 2 turns, got %d", result.Turns)
	}
}

func TestRun_MaxTurnsExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := llm.Response{
			Choices: []llm.Choice{{
				Message: llm.Message{
					Role: "assistant",
					ToolCalls: []llm.ToolCall{{
						ID:   "call_1",
						Type: "function",
						Function: llm.FunctionCall{
							Name:      "noop",
							Arguments: `{}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	type NoopArgs struct{}

	client := llm.NewClient(server.URL, "test")
	reg := tool.NewRegistry()
	tool.Register(reg, "noop", "Do nothing", func(ctx context.Context, args NoopArgs) (any, error) {
		return "ok", nil
	})

	_, err := Run(context.Background(), client, reg, Config{
		SystemPrompt: "You are helpful.",
		MaxTurns:     3,
	}, "loop forever")

	if err == nil {
		t.Fatal("expected error for max turns exceeded")
	}
}
