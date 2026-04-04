package llm

// Message is a single message in a chat conversation.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall is a tool invocation requested by the LLM.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall is the function name + JSON arguments string.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDef defines a tool the LLM can call.
type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

// FunctionDef is the tool's name, description, and parameter schema.
type FunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// Request is a chat completion request.
type Request struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []ToolDef `json:"tools,omitempty"`
}

// Response is a chat completion response.
type Response struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
}

// Choice is a single completion choice.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}
