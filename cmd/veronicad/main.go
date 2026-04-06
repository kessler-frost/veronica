package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	vaf "github.com/fimbulwinter/veronica/internal/af"
	"github.com/fimbulwinter/veronica/internal/classifier"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/event"
)

func main() {
	afURL := envOr("AGENTFIELD_URL", "http://host.lima.internal:8090")
	listenAddr := envOr("VERONICA_LISTEN", ":8001")

	log.Printf("veronica starting")
	log.Printf("  agentfield: %s", afURL)
	log.Printf("  listen: %s", listenAddr)

	// Create Agentfield agent (daemon = service exposing functions)
	ag, err := agent.New(agent.Config{
		NodeID:        "veronicad",
		Version:       "0.2.0",
		AgentFieldURL: afURL,
		ListenAddress: listenAddr,
	})
	if err != nil {
		log.Fatalf("agentfield agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// eBPF
	events := make(chan event.Event, 256)
	ebpfMgr := vebpf.New(events)
	if err := ebpfMgr.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf: %v", err)
	}
	defer ebpfMgr.Close()
	log.Printf("ebpf probes attached")

	// Publisher: eBPF events → classify → push to subscribed behavior agents
	tracker := vaf.NewPIDTracker()
	cls := classifier.New()
	pub := vaf.NewPublisher(ag, cls, tracker)

	// Register all skills (functions) with Agentfield
	// Includes subscribe/unsubscribe so behavior agents can register for events
	vaf.RegisterSkills(ag, tracker, ebpfMgr.Maps(), pub)

	go pub.Run(ctx, events)

	go func() {
		if err := ebpfMgr.ReadEvents(ctx); err != nil {
			log.Printf("ebpf reader stopped: %v", err)
		}
	}()

	// Start Agentfield agent (registers with control plane + serves HTTP)
	go func() {
		if err := ag.Serve(ctx); err != nil {
			log.Printf("agentfield serve: %v", err)
		}
	}()

	log.Printf("veronica running. agentfield=%s. ctrl+c to stop.", afURL)

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
