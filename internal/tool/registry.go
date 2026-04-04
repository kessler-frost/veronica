package tool

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fimbulwinter/veronica/internal/llm"
)

// entry holds a tool's definition and its untyped executor.
type entry struct {
	def     llm.ToolDef
	execute func(ctx context.Context, rawArgs string) (any, error)
}

// Registry holds registered tools and dispatches calls by name.
type Registry struct {
	tools map[string]entry
	order []string
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]entry),
	}
}

// Register adds a typed tool to the registry. Schema is generated from TArgs struct tags.
func Register[TArgs any](r *Registry, name string, description string, fn func(ctx context.Context, args TArgs) (any, error)) {
	schema := SchemaFromStruct[TArgs]()

	r.tools[name] = entry{
		def: llm.ToolDef{
			Type: "function",
			Function: llm.FunctionDef{
				Name:        name,
				Description: description,
				Parameters:  schema,
			},
		},
		execute: func(ctx context.Context, rawArgs string) (any, error) {
			var args TArgs
			if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
				return nil, fmt.Errorf("unmarshal args for %s: %w", name, err)
			}
			return fn(ctx, args)
		},
	}
	r.order = append(r.order, name)
}

// Definitions returns all registered tool definitions in registration order.
func (r *Registry) Definitions() []llm.ToolDef {
	defs := make([]llm.ToolDef, len(r.order))
	for i, name := range r.order {
		defs[i] = r.tools[name].def
	}
	return defs
}

// Call dispatches a tool call by name with raw JSON arguments.
func (r *Registry) Call(ctx context.Context, name string, rawArgs string) (any, error) {
	e, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	return e.execute(ctx, rawArgs)
}
