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
	"sleep": true, "test": true, "find": true, "grep": true,
	"nginx": true, "python3": true, "node": true, "go": true,
	"journalctl": true, "systemctl": true, "docker": true,
	"dig": true, "nslookup": true, "curl": true, "wget": true,
}

type readFileArgs struct {
	Path string `json:"path" desc:"Absolute path to the file to read"`
}

type shellReadArgs struct {
	Cmd  string   `json:"cmd" desc:"Command to run (must be in allowlist)"`
	Args []string `json:"args,omitempty" desc:"Command arguments"`
}

type requestActionArgs struct {
	Command string `json:"command" desc:"Shell command to execute, e.g. 'cd /tmp/myapp && uv init && uv add fastapi'"`
	Reason  string `json:"reason" desc:"Brief explanation of why this action is needed"`
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

	tool.Register(reg, "request_action", "Request the coordinator to execute a shell command. Use this for any write/modify/install operation.", func(ctx context.Context, args requestActionArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: agentID,
			Action: Action{
				Type:     "shell_exec",
				Resource: args.Reason,
				Args:     args.Command,
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
