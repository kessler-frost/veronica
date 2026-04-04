package coordinator

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/fimbulwinter/veronica/internal/state"
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

type stateQueryArgs struct {
	Pattern string `json:"pattern" desc:"Key pattern to query (e.g. 'policy:*', 'event:*')"`
	Limit   int    `json:"limit,omitempty" desc:"Max results to return (default 50)"`
}

type stateWriteArgs struct {
	Key   string `json:"key" desc:"Key to write"`
	Value string `json:"value" desc:"JSON value to store"`
	TTL   int    `json:"ttl,omitempty" desc:"Time-to-live in seconds (0 = no expiry)"`
}

type mapReadArgs struct {
	Map string `json:"map" desc:"eBPF map name"`
	Key string `json:"key,omitempty" desc:"Specific key to read (omit to dump all)"`
}

type mapWriteArgs struct {
	Map   string `json:"map" desc:"eBPF map name"`
	Key   string `json:"key" desc:"Map key"`
	Value string `json:"value" desc:"Map value"`
}

type mapDeleteArgs struct {
	Map string `json:"map" desc:"eBPF map name"`
	Key string `json:"key" desc:"Key to delete"`
}

type programListArgs struct{}

type programLoadArgs struct {
	Name string `json:"name" desc:"Program name to load and attach"`
}

type programDetachArgs struct {
	Name string `json:"name" desc:"Program name to detach and unload"`
}

// NewToolkit creates a tool.Registry with read-only tools, state tools, and eBPF tool stubs.
// The sessionID identifies this agent in action requests.
// The actionCh is used to send action requests to the coordinator.
func NewToolkit(actionCh chan<- ActionRequest, sessionID string, store *state.Store) *tool.Registry {
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
			AgentID: sessionID,
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

	tool.Register(reg, "state_query", "Query buntdb state by key pattern", func(ctx context.Context, args stateQueryArgs) (any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 50
		}
		return store.QueryByPattern(args.Pattern, limit)
	})

	tool.Register(reg, "state_write", "Write a key-value pair to buntdb state", func(ctx context.Context, args stateWriteArgs) (any, error) {
		respCh := make(chan ActionResult, 1)
		actionCh <- ActionRequest{
			AgentID: sessionID,
			Action: Action{
				Type:     "state_write",
				Resource: "state:" + args.Key,
				Args:     fmt.Sprintf(`{"key":%q,"value":%q,"ttl":%d}`, args.Key, args.Value, args.TTL),
			},
			Response: respCh,
		}
		select {
		case result := <-respCh:
			if result.Error != nil {
				return nil, result.Error
			}
			return result.Output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	tool.Register(reg, "map_read", "Read an eBPF map entry or dump entire map", func(ctx context.Context, args mapReadArgs) (any, error) {
		return nil, fmt.Errorf("map_read not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "map_write", "Write a value to an eBPF map entry", func(ctx context.Context, args mapWriteArgs) (any, error) {
		return nil, fmt.Errorf("map_write not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "map_delete", "Delete an entry from an eBPF map", func(ctx context.Context, args mapDeleteArgs) (any, error) {
		return nil, fmt.Errorf("map_delete not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_list", "List loaded eBPF programs", func(ctx context.Context, args programListArgs) (any, error) {
		return nil, fmt.Errorf("program_list not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_load", "Load and attach an eBPF program", func(ctx context.Context, args programLoadArgs) (any, error) {
		return nil, fmt.Errorf("program_load not yet implemented — requires eBPF manager wiring")
	})

	tool.Register(reg, "program_detach", "Detach and unload an eBPF program", func(ctx context.Context, args programDetachArgs) (any, error) {
		return nil, fmt.Errorf("program_detach not yet implemented — requires eBPF manager wiring")
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
