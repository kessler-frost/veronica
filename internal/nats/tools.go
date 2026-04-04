package nats

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"

	json "github.com/goccy/go-json"

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

type EnforceRequest struct {
	Hook   string `json:"hook"`   // "file_open", "socket_connect", "xdp_drop"
	Target string `json:"target"` // path, IP, etc.
	Action string `json:"action"` // "deny" or "allow"
	Reason string `json:"reason"`
}

type TransformRequest struct {
	Interface string `json:"interface"`
	Match     string `json:"match"`
	Rewrite   string `json:"rewrite"`
	Reason    string `json:"reason"`
}

type ScheduleRequest struct {
	Target   string `json:"target"`   // PID or cgroup
	Priority string `json:"priority"` // "latency-sensitive", "batch", "normal"
	Reason   string `json:"reason"`
}

type MeasureRequest struct {
	Target   string `json:"target"`
	Metric   string `json:"metric"`   // "cache_misses", "cycles", "bandwidth"
	Duration string `json:"duration"` // "5s", "1m"
}

type MapReadRequest struct {
	Map string `json:"map"`
	Key string `json:"key,omitempty"` // empty = dump all
}

type MapWriteRequest struct {
	Map   string `json:"map"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type MapDeleteRequest struct {
	Map string `json:"map"`
	Key string `json:"key"`
}

type ProgramListRequest struct{} // no params

type ProgramLoadRequest struct {
	Name string `json:"name"`
}

type ProgramDetachRequest struct {
	Name string `json:"name"`
}

// RegisterToolResponders sets up NATS request/reply handlers for all daemon tools.
// pub is used for PID tracking (so the classifier ignores commands we spawn).
func RegisterToolResponders(nc *nats.Conn, pub *Publisher) error {
	subs := []struct {
		subject string
		handler nats.MsgHandler
	}{
		{"tools.exec", func(msg *nats.Msg) {
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
		}},
		{"tools.enforce", func(msg *nats.Msg) {
			var req EnforceRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL enforce [%s]: %s %s %s", req.Reason, req.Hook, req.Target, req.Action)
			// TODO: wire to eBPF manager LSM/kprobe/XDP map operations
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("enforce %s on %s via %s (pending eBPF wiring)", req.Action, req.Target, req.Hook)})
		}},
		{"tools.transform", func(msg *nats.Msg) {
			var req TransformRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL transform [%s]: iface=%s match=%s rewrite=%s", req.Reason, req.Interface, req.Match, req.Rewrite)
			// TODO: wire to eBPF manager TC/XDP rewrite map operations
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("transform on %s: %s -> %s (pending eBPF wiring)", req.Interface, req.Match, req.Rewrite)})
		}},
		{"tools.schedule", func(msg *nats.Msg) {
			var req ScheduleRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL schedule [%s]: target=%s priority=%s", req.Reason, req.Target, req.Priority)
			// TODO: wire to eBPF manager sched_ext map operations
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("schedule %s as %s (pending eBPF wiring)", req.Target, req.Priority)})
		}},
		{"tools.measure", func(msg *nats.Msg) {
			var req MeasureRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL measure [%s]: target=%s metric=%s duration=%s", req.Target, req.Target, req.Metric, req.Duration)
			// TODO: wire to eBPF manager perf_event map reads
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("measure %s on %s for %s (pending eBPF wiring)", req.Metric, req.Target, req.Duration)})
		}},
		{"tools.map.read", func(msg *nats.Msg) {
			var req MapReadRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL map.read: map=%s key=%q", req.Map, req.Key)
			// TODO: wire to eBPF manager map lookup/dump
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("map read %s key=%q (pending eBPF wiring)", req.Map, req.Key)})
		}},
		{"tools.map.write", func(msg *nats.Msg) {
			var req MapWriteRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL map.write: map=%s key=%q value=%q", req.Map, req.Key, req.Value)
			// TODO: wire to eBPF manager map update
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("map write %s[%s]=%s (pending eBPF wiring)", req.Map, req.Key, req.Value)})
		}},
		{"tools.map.delete", func(msg *nats.Msg) {
			var req MapDeleteRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL map.delete: map=%s key=%q", req.Map, req.Key)
			// TODO: wire to eBPF manager map delete
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("map delete %s[%s] (pending eBPF wiring)", req.Map, req.Key)})
		}},
		{"tools.program.list", func(msg *nats.Msg) {
			log.Printf("TOOL program.list")
			// TODO: wire to eBPF manager program inventory
			respond(msg, ToolResult{Ok: true, Data: "program list (pending eBPF wiring)"})
		}},
		{"tools.program.load", func(msg *nats.Msg) {
			var req ProgramLoadRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL program.load: name=%s", req.Name)
			// TODO: wire to eBPF manager dynamic program loading
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("program load %s (pending eBPF wiring)", req.Name)})
		}},
		{"tools.program.detach", func(msg *nats.Msg) {
			var req ProgramDetachRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
				return
			}
			log.Printf("TOOL program.detach: name=%s", req.Name)
			// TODO: wire to eBPF manager program detach/unload
			respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("program detach %s (pending eBPF wiring)", req.Name)})
		}},
	}

	for _, s := range subs {
		if _, err := nc.Subscribe(s.subject, s.handler); err != nil {
			return fmt.Errorf("subscribe %s: %w", s.subject, err)
		}
	}
	return nil
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
