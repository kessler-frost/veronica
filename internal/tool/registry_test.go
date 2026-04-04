package tool

import (
	"context"
	"testing"

	json "github.com/goccy/go-json"
)

func TestRegistry_RegisterAndCall(t *testing.T) {
	type ReadFileArgs struct {
		Path string `json:"path" desc:"File path"`
	}

	reg := NewRegistry()
	Register(reg, "read_file", "Read a file", func(ctx context.Context, args ReadFileArgs) (any, error) {
		return "contents of " + args.Path, nil
	})

	if len(reg.Definitions()) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(reg.Definitions()))
	}

	def := reg.Definitions()[0]
	if def.Function.Name != "read_file" {
		t.Fatalf("expected name read_file, got %s", def.Function.Name)
	}

	result, err := reg.Call(context.Background(), "read_file", `{"path":"/etc/hostname"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string result, got %T", result)
	}
	if s != "contents of /etc/hostname" {
		t.Fatalf("unexpected result: %s", s)
	}
}

func TestRegistry_CallUnknownTool(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Call(context.Background(), "nonexistent", `{}`)
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestRegistry_CallBadJSON(t *testing.T) {
	type Args struct {
		N int `json:"n" desc:"A number"`
	}

	reg := NewRegistry()
	Register(reg, "square", "Square a number", func(ctx context.Context, args Args) (any, error) {
		return args.N * args.N, nil
	})

	_, err := reg.Call(context.Background(), "square", `{invalid`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRegistry_DefinitionsProduceValidJSON(t *testing.T) {
	type Args struct {
		PID int `json:"pid" desc:"Process ID"`
	}

	reg := NewRegistry()
	Register(reg, "kill_proc", "Kill a process", func(ctx context.Context, args Args) (any, error) {
		return nil, nil
	})

	defs := reg.Definitions()
	b, err := json.Marshal(defs)
	if err != nil {
		t.Fatalf("definitions not JSON-serializable: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty JSON")
	}
}
