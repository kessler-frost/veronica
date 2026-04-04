package agent

import (
	"time"

	"github.com/fimbulwinter/veronica/internal/llm"
)

// Config configures an agent run.
type Config struct {
	SystemPrompt string
	Model        string
	MaxTurns     int           // default: 10
	TurnTimeout  time.Duration // per-LLM-call timeout; default 60s
}

// RunResult is the outcome of an agent run.
type RunResult struct {
	Response string        // final text from LLM
	Turns    int           // number of LLM round-trips taken
	History  []llm.Message // full conversation history
}
