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
	"github.com/fimbulwinter/veronica/internal/control"
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

	// Register the kernel control-plane functions (the 8 daemon↔warden contract
	// functions: resolve_app, observe, list_primitives, apply_policy,
	// set_policy_mode, list_policies, revert_policy, kill_switch).
	ctrl := control.NewHandlers(control.NewProcSource())
	registerControl(ag, ctrl)

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

// registerControl registers the eight kernel control-plane functions with
// Agentfield, following the same RegisterReasoner pattern as RegisterSkills.
func registerControl(ag *agent.Agent, c *control.Handlers) {
	ag.RegisterReasoner("resolve_app", c.ResolveApp,
		agent.WithDescription("Resolve an app name to its cgroup path and live PIDs"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("observe", c.Observe,
		agent.WithDescription("Return a windowed Activity snapshot of an app's kernel activity"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("list_primitives", c.ListPrimitives,
		agent.WithDescription("List the vetted eBPF-LSM enforcement primitives"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("apply_policy", c.ApplyPolicy,
		agent.WithDescription("Apply a primitive to an app in audit mode (audit-first, guard-listed)"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("set_policy_mode", c.SetPolicyMode,
		agent.WithDescription("Transition a policy between audit and enforce"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("list_policies", c.ListPolicies,
		agent.WithDescription("List all current policies"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("revert_policy", c.RevertPolicy,
		agent.WithDescription("Revert a single policy, detaching its enforcement"),
		agent.WithReasonerTags("skill"),
	)
	ag.RegisterReasoner("kill_switch", c.KillSwitch,
		agent.WithDescription("Revert every policy (fail-open kill switch)"),
		agent.WithReasonerTags("skill"),
	)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
