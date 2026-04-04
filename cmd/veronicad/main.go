package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/state"
	"github.com/fimbulwinter/veronica/internal/tool"
	"github.com/fimbulwinter/veronica/internal/ws"
)

func main() {
	wsAddr := envOr("VERONICA_WS_ADDR", ":9090")
	stateDB := envOr("VERONICA_STATE_DB", "/var/veronica/state.db")

	log.Printf("veronica starting")
	log.Printf("  ws: %s", wsAddr)
	log.Printf("  state: %s", stateDB)

	os.MkdirAll("/var/veronica", 0755)
	store, err := state.Open(stateDB)
	if err != nil {
		log.Fatalf("open state: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create coordinator first (need its action channel for toolkit)
	var coord *coordinator.Coordinator

	// Toolkit factory: creates a tool registry per session
	toolkitFn := func(sessionID string) *tool.Registry {
		return coordinator.NewToolkit(coord.ActionChannel(), sessionID, store)
	}

	// WebSocket server (implements coordinator.Router)
	wsSrv := ws.NewServer(wsAddr, toolkitFn)

	coord = coordinator.New(wsSrv, store, coordinator.Config{
		MaxTurns: 10,
		ActionExecutor: func(a coordinator.Action) (string, error) {
			log.Printf("ACTION [%s]: %s", a.Resource, a.Args)

			if isDangerous(a.Args) {
				log.Printf("ACTION DENIED (dangerous): %s", a.Args)
				return "DENIED: command matches dangerous pattern", fmt.Errorf("dangerous command blocked")
			}

			cmd := exec.CommandContext(ctx, "bash", "-c", a.Args)
			out, err := cmd.CombinedOutput()
			output := strings.TrimSpace(string(out))

			if err != nil {
				if strings.Contains(output, "command not found") || strings.Contains(output, "No such file") {
					toolName := extractToolName(output)
					if toolName != "" {
						log.Printf("ACTION: tool %q not found, attempting install...", toolName)
						installOut, installErr := installTool(ctx, toolName)
						if installErr != nil {
							return output + "\ninstall attempt: " + installOut, err
						}
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

	// Start WebSocket server
	go func() {
		if err := wsSrv.Start(ctx); err != nil {
			log.Printf("ws server stopped: %v", err)
		}
	}()

	// Start eBPF
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

	log.Printf("veronica running. ws=%s. ctrl+c to stop.", wsAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down...")
	cancel()
}

// isDangerous returns true for commands that should never be executed.
func isDangerous(cmd string) bool {
	dangerousPatterns := []string{
		"rm -rf /", "rm -rf /*", "mkfs",
		"dd if=/dev/zero", "dd if=/dev/urandom",
		":(){ :|:& };:", "> /dev/sda",
		"chmod -R 777 /", "chown -R",
		"shutdown", "reboot", "init 0", "halt", "poweroff",
	}
	lower := strings.ToLower(cmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// extractToolName tries to find which tool is missing from an error message.
func extractToolName(errOutput string) string {
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
func installTool(ctx context.Context, toolName string) (string, error) {
	var installCmd string
	switch toolName {
	case "uv", "uvx":
		installCmd = "curl -LsSf https://astral.sh/uv/install.sh | bash && ln -sf /root/.local/bin/uv /usr/local/bin/uv && ln -sf /root/.local/bin/uvx /usr/local/bin/uvx"
	case "bun", "bunx":
		installCmd = "curl -fsSL https://bun.sh/install | bash && ln -sf /root/.bun/bin/bun /usr/local/bin/bun"
	default:
		installCmd = "dnf install -y " + toolName
	}
	log.Printf("ACTION: installing %s via: %s", toolName, installCmd)
	out, err := exec.CommandContext(ctx, "bash", "-c", installCmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
