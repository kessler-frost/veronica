package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func main() {
	llmURL := envOr("VERONICA_LLM_URL", "http://host.lima.internal:1234")
	llmModel := envOr("VERONICA_LLM_MODEL", "mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled")
	stateDB := envOr("VERONICA_STATE_DB", "/var/veronica/state.db")

	log.Printf("veronica starting")
	log.Printf("  llm: %s (model: %s)", llmURL, llmModel)
	log.Printf("  state: %s", stateDB)

	os.MkdirAll("/var/veronica", 0755)
	store, err := state.Open(stateDB)
	if err != nil {
		log.Fatalf("open state: %v", err)
	}
	defer store.Close()

	client := llm.NewClient(llmURL, llmModel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var coord *coordinator.Coordinator
	coord = coordinator.New(client, store, coordinator.Config{
		SystemPrompt: systemPrompt,
		MaxTurns:     10,
		ActionExecutor: func(a coordinator.Action) (string, error) {
			log.Printf("ACTION [%s]: %s", a.Resource, a.Args)

			cmd := exec.CommandContext(ctx, "bash", "-c", a.Args)
			out, err := cmd.CombinedOutput()
			output := strings.TrimSpace(string(out))

			if err != nil {
				// If command not found, try to install it
				if strings.Contains(output, "command not found") || strings.Contains(output, "No such file") {
					tool := extractToolName(output)
					if tool != "" {
						log.Printf("ACTION: tool %q not found, attempting install...", tool)
						installOut, installErr := installTool(ctx, tool)
						if installErr != nil {
							return output + "\ninstall attempt: " + installOut, err
						}
						// Retry original command
						retryOut, retryErr := exec.CommandContext(ctx, "bash", "-c", a.Args).CombinedOutput()
						if retryErr != nil {
							return strings.TrimSpace(string(retryOut)), retryErr
						}
						return strings.TrimSpace(string(retryOut)), nil
					}
				}
				return output, err
			}
			return output, nil
		},
	})

	coord.Start(ctx)

	go func() {
		for r := range coord.Reports() {
			log.Printf("[%s] %s: %s", r.AgentID, r.EventType, r.Detail)
		}
	}()

	events := make(chan coordinator.Event, 256)
	go func() {
		for e := range events {
			coord.HandleEvent(e)
		}
	}()

	ebpfMgr := vebpf.New(events)
	if err := ebpfMgr.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf: %v", err)
	}
	defer ebpfMgr.Close()
	log.Printf("ebpf probes attached")

	go func() {
		if err := ebpfMgr.ReadEvents(ctx); err != nil {
			log.Printf("ebpf reader stopped: %v", err)
		}
	}()

	log.Printf("veronica running. ctrl+c to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down...")
	cancel()
}

// extractToolName tries to find which tool is missing from an error message.
func extractToolName(errOutput string) string {
	// "bash: line 1: uv: command not found" → "uv"
	if idx := strings.Index(errOutput, ": command not found"); idx != -1 {
		before := errOutput[:idx]
		lastColon := strings.LastIndex(before, ": ")
		if lastColon != -1 {
			return strings.TrimSpace(before[lastColon+2:])
		}
	}
	return ""
}

// installTool attempts to install a missing tool.
func installTool(ctx context.Context, tool string) (string, error) {
	var installCmd string
	switch tool {
	case "uv", "uvx":
		installCmd = "curl -LsSf https://astral.sh/uv/install.sh | bash && ln -sf $HOME/.local/bin/uv /usr/local/bin/uv && ln -sf $HOME/.local/bin/uvx /usr/local/bin/uvx"
	case "bun", "bunx":
		installCmd = "curl -fsSL https://bun.sh/install | bash && ln -sf $HOME/.bun/bin/bun /usr/local/bin/bun"
	default:
		// Try dnf (Fedora)
		installCmd = "dnf install -y " + tool
	}

	log.Printf("ACTION: installing %s via: %s", tool, installCmd)
	out, err := exec.CommandContext(ctx, "bash", "-c", installCmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const systemPrompt = `You are Veronica, an autonomous intelligence layer embedded in a Linux operating system.
You observe kernel events via eBPF and manage the system.
You have read-only tools (read_file, shell_read) and can request actions via request_action.
When you receive an event, analyze it and decide what action to take.
Be concise in your reasoning. Focus on system health, security, and performance.`
