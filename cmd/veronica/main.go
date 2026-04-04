package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/llm"
	"github.com/fimbulwinter/veronica/internal/state"
)

func main() {
	llmURL := envOr("VERONICA_LLM_URL", "http://host.lima.internal:1234")
	llmModel := envOr("VERONICA_LLM_MODEL", "qwen3.5-35b")
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

	coord := coordinator.New(client, store, coordinator.Config{
		SystemPrompt: systemPrompt,
		MaxTurns:     10,
		ActionExecutor: func(a coordinator.Action) (string, error) {
			log.Printf("ACTION: %s on %s args=%s", a.Type, a.Resource, a.Args)
			return "executed (stub)", nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
