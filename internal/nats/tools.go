package nats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/nats-io/nats.go"
)

type ExecRequest struct {
	Command string `json:"command"`
	Reason  string `json:"reason,omitempty"`
}

type ToolResult struct {
	Ok    bool   `json:"ok"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// RegisterToolResponders sets up NATS request/reply handlers for all daemon tools.
// pub is used for PID tracking (so the classifier ignores commands we spawn).
func RegisterToolResponders(nc *nats.Conn, pub *Publisher) error {
	_, err := nc.Subscribe("tools.exec", func(msg *nats.Msg) {
		var req ExecRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL exec [%s]: %s", req.Reason, req.Command)

		if isDangerous(req.Command) {
			log.Printf("TOOL exec DENIED (dangerous): %s", req.Command)
			respond(msg, ToolResult{Ok: false, Error: "DENIED: command matches dangerous pattern"})
			return
		}

		ctx := context.Background()
		output, err := runTracked(ctx, req.Command, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: output})
	})
	return err
}

func runTracked(ctx context.Context, command string, pub *Publisher) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return err.Error(), err
	}
	if pub != nil {
		pid := uint32(cmd.Process.Pid)
		pub.TrackPID(pid)
		defer pub.UntrackPID(pid)
	}

	err := cmd.Wait()
	output := strings.TrimSpace(buf.String())

	if err != nil {
		if strings.Contains(output, "command not found") || strings.Contains(output, "No such file") {
			toolName := extractToolName(output)
			if toolName != "" {
				log.Printf("TOOL exec: %q not found, installing...", toolName)
				installOut, installErr := installTool(ctx, toolName)
				if installErr != nil {
					return output + "\ninstall attempt: " + installOut, err
				}
				return runTracked(ctx, command, pub)
			}
		}
		return output, err
	}
	return output, nil
}

func respond(msg *nats.Msg, result ToolResult) {
	data, _ := json.Marshal(result)
	if err := msg.Respond(data); err != nil {
		log.Printf("respond: %v", err)
	}
}

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
	log.Printf("TOOL exec: installing %s via: %s", toolName, installCmd)
	out, err := exec.CommandContext(ctx, "bash", "-c", installCmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
