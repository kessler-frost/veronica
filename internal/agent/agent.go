package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/tool"
)

// Run executes the agent loop: send messages to LLM, dispatch tool calls, repeat.
func Run(ctx context.Context, client *llm.Client, reg *tool.Registry, cfg Config, userMessage string) (*RunResult, error) {
	maxTurns := cfg.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 10
	}

	messages := []llm.Message{
		{Role: "system", Content: cfg.SystemPrompt},
		{Role: "user", Content: userMessage},
	}
	tools := reg.Definitions()

	for turn := range maxTurns {
		resp, err := client.Chat(ctx, messages, tools)
		if err != nil {
			return nil, fmt.Errorf("turn %d: %w", turn+1, err)
		}

		msg := resp.Choices[0].Message
		messages = append(messages, msg)

		if len(msg.ToolCalls) == 0 {
			return &RunResult{
				Response: msg.Content,
				Turns:    turn + 1,
				History:  messages,
			}, nil
		}

		for _, tc := range msg.ToolCalls {
			result, err := reg.Call(ctx, tc.Function.Name, tc.Function.Arguments)

			var content string
			if err != nil {
				content = fmt.Sprintf("error: %v", err)
			} else {
				b, _ := json.Marshal(result)
				content = string(b)
			}

			messages = append(messages, llm.Message{
				Role:       "tool",
				Content:    content,
				ToolCallID: tc.ID,
			})
		}
	}

	return nil, fmt.Errorf("max turns exceeded (%d)", maxTurns)
}
