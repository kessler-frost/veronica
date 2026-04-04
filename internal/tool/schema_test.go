package tool

import (
	"encoding/json"
	"testing"
)

func TestSchemaFromStruct_SimpleFields(t *testing.T) {
	type Args struct {
		Path string `json:"path" desc:"File path to read"`
		Line int    `json:"line" desc:"Line number"`
	}

	schema := SchemaFromStruct[Args]()

	if schema["type"] != "object" {
		t.Fatalf("expected type object, got %v", schema["type"])
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected properties map, got %T", schema["properties"])
	}

	pathProp, ok := props["path"].(map[string]any)
	if !ok {
		t.Fatalf("expected path property, got %T", props["path"])
	}
	if pathProp["type"] != "string" {
		t.Fatalf("expected path type string, got %v", pathProp["type"])
	}
	if pathProp["description"] != "File path to read" {
		t.Fatalf("expected description 'File path to read', got %v", pathProp["description"])
	}

	lineProp, ok := props["line"].(map[string]any)
	if !ok {
		t.Fatalf("expected line property")
	}
	if lineProp["type"] != "integer" {
		t.Fatalf("expected line type integer, got %v", lineProp["type"])
	}

	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatalf("expected required []string, got %T", schema["required"])
	}
	if len(required) != 2 {
		t.Fatalf("expected 2 required fields, got %d", len(required))
	}
}

func TestSchemaFromStruct_OptionalField(t *testing.T) {
	type Args struct {
		Name    string `json:"name" desc:"The name"`
		Verbose bool   `json:"verbose,omitempty" desc:"Enable verbose output"`
	}

	schema := SchemaFromStruct[Args]()
	required := schema["required"].([]string)

	if len(required) != 1 || required[0] != "name" {
		t.Fatalf("expected only 'name' required, got %v", required)
	}
}

func TestSchemaFromStruct_ProducesValidJSON(t *testing.T) {
	type Args struct {
		PID    int    `json:"pid" desc:"Process ID"`
		Signal string `json:"signal" desc:"Signal name"`
	}

	schema := SchemaFromStruct[Args]()
	b, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("schema is not JSON-serializable: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty JSON output")
	}
}
