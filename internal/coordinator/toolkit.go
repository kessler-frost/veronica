package coordinator

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/fimbulwinter/veronica/internal/tool"
)

var allowedCommands = map[string]bool{
	"cat": true, "ls": true, "ps": true, "stat": true, "df": true,
	"ip": true, "ss": true, "whoami": true, "hostname": true, "uname": true,
	"uptime": true, "free": true, "id": true, "echo": true, "head": true,
	"tail": true, "wc": true, "du": true, "mount": true, "lsblk": true,
	"top": true, "netstat": true, "lsof": true, "file": true, "which": true,
}

type readFileArgs struct {
	Path string `json:"path" desc:"Absolute path to the file to read"`
}

type shellReadArgs struct {
	Cmd  string   `json:"cmd" desc:"Command to run (must be in allowlist)"`
	Args []string `json:"args,omitempty" desc:"Command arguments"`
}

type requestActionArgs struct {
	Type     string `json:"type" desc:"Action type: shell_exec, write_file, kill, set_cgroup, write_map, etc."`
	Resource string `json:"resource" desc:"Resource identifier: pid:N, file:/path, ip:addr, etc."`
	Args     string `json:"args" desc:"JSON-encoded action-specific arguments"`
}

// NewToolkit creates a tool.Registry with read-only tools and request_action.
// The agentID identifies this agent in action requests.
// The actionCh is used to send action requests to the coordinator.
func NewToolkit(actionCh chan<- ActionRequest, agentID string) *tool.Registry {
	reg := tool.NewRegistry()

	tool.Register(reg, "read_file", "Read a file's contents", func(ctx context.Context, args readFileArgs) (any, error) {
		b, err := os.ReadFile(args.Path)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	})

	tool.Register(reg, "shell_read", "Run a read-only shell command (allowlisted commands only)", func(ctx context.Context, args shellReadArgs) (any, error) {
		if !allowedCommands[args.Cmd] {
			return nil, fmt.Errorf("command %q not in allowlist", args.Cmd)
		}
		out, err := exec.CommandContext(ctx, args.Cmd, args.Args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %w\noutput: %s", args.Cmd, err, string(out))
		}
		return string(out), nil
	})

	tool.Register(reg, "request_action", "Request the coordinator to execute a write/execute action", func(ctx context.Context, args requestActionArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: agentID,
			Action: Action{
				Type:     args.Type,
				Resource: args.Resource,
				Args:     args.Args,
			},
			Response: respCh,
		}

		select {
		case result := <-respCh:
			if result.Error != nil {
				return nil, result.Error
			}
			if result.Approved {
				return "approved: " + result.Output, nil
			}
			return "rejected: " + result.Output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	return reg
}

// AllowedCommands returns the set of allowed shell_read commands. Exported for testing.
func AllowedCommands() map[string]bool {
	result := make(map[string]bool, len(allowedCommands))
	for k, v := range allowedCommands {
		result[k] = v
	}
	return result
}
