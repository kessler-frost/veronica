package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientChat_TextResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("expected /v1/chat/completions, got %s", r.URL.Path)
		}

		var req Request
		json.NewDecoder(r.Body).Decode(&req)

		if req.Model != "test-model" {
			t.Fatalf("expected model test-model, got %s", req.Model)
		}
		if len(req.Messages) != 1 {
			t.Fatalf("expected 1 message, got %d", len(req.Messages))
		}

		resp := Response{
			ID: "test-id",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: "hello back"},
				FinishReason: "stop",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-model")
	msgs := []Message{{Role: "user", Content: "hello"}}

	resp, err := client.Chat(context.Background(), msgs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Choices[0].Message.Content != "hello back" {
		t.Fatalf("expected 'hello back', got %q", resp.Choices[0].Message.Content)
	}
}

func TestClientChat_ToolCallResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		json.NewDecoder(r.Body).Decode(&req)

		if len(req.Tools) != 1 {
			t.Fatalf("expected 1 tool, got %d", len(req.Tools))
		}
		if req.Tools[0].Function.Name != "read_file" {
			t.Fatalf("expected tool read_file, got %s", req.Tools[0].Function.Name)
		}

		resp := Response{
			ID: "test-id",
			Choices: []Choice{{
				Index: 0,
				Message: Message{
					Role: "assistant",
					ToolCalls: []ToolCall{{
						ID:   "call_1",
						Type: "function",
						Function: FunctionCall{
							Name:      "read_file",
							Arguments: `{"path":"/etc/hostname"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-model")
	msgs := []Message{{Role: "user", Content: "what is the hostname?"}}
	tools := []ToolDef{{
		Type: "function",
		Function: FunctionDef{
			Name:        "read_file",
			Description: "Read a file",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}},
		},
	}}

	resp, err := client.Chat(context.Background(), msgs, tools)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.Choices[0].Message.ToolCalls))
	}
	if resp.Choices[0].Message.ToolCalls[0].Function.Name != "read_file" {
		t.Fatalf("expected read_file, got %s", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	}
}
