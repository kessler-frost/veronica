package control

import "fmt"

// stringSchema is the JSON-Schema fragment for a string-typed param.
func stringSchema() map[string]any { return map[string]any{"type": "string"} }

// stringArraySchema is the JSON-Schema fragment for an array-of-strings param.
func stringArraySchema() map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
}

// objectSchema builds an object schema with the given properties + required
// list, with additionalProperties:false so unexpected params are rejected.
func objectSchema(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             required,
		"additionalProperties": false,
	}
}

// catalog is the fixed, vetted v1 set of enforcement primitives. Each declares
// an id, a JSON-Schema for its params, and the LSM hook(s) it attaches.
var catalog = map[string]Primitive{
	"block-path-write": {
		ID:     "block-path-write",
		Desc:   "Deny writes under a path prefix",
		Params: objectSchema(map[string]any{"path_prefix": stringSchema()}, "path_prefix"),
		Hooks:  []string{"path_mkdir", "inode_create", "file_open"},
	},
	"block-mount": {
		ID:     "block-mount",
		Desc:   "Deny mount operations (sb_mount/move_mount); for blocking docker volume creation use block-path-write, since a local volume is a mkdir, not a mount",
		Params: objectSchema(map[string]any{"path_prefix": stringSchema()}),
		Hooks:  []string{"sb_mount", "move_mount"},
	},
	"block-egress": {
		ID:     "block-egress",
		Desc:   "Deny outbound connections to addresses outside the allow list",
		Params: objectSchema(map[string]any{"allow_cidrs": stringArraySchema()}, "allow_cidrs"),
		Hooks:  []string{"socket_connect"},
	},
	"block-exec": {
		ID:     "block-exec",
		Desc:   "Deny execution of named binaries",
		Params: objectSchema(map[string]any{"binaries": stringArraySchema()}, "binaries"),
		Hooks:  []string{"bprm_check_security"},
	},
	"drop-capability": {
		ID:     "drop-capability",
		Desc:   "Deny use of named Linux capabilities",
		Params: objectSchema(map[string]any{"caps": stringArraySchema()}, "caps"),
		Hooks:  []string{"capable", "security_capable"},
	},
}

// Catalog returns a copy of the vetted primitive catalog keyed by id.
func Catalog() map[string]Primitive {
	out := make(map[string]Primitive, len(catalog))
	for id, p := range catalog {
		out[id] = p
	}
	return out
}

// ValidateParams checks params against the primitive's JSON Schema. It returns
// an error for an unknown primitive id or schema-invalid params. The schema
// subset covers object/string/array-of-string with required + no extra props,
// which is all the v1 catalog needs.
func ValidateParams(primitiveID string, params map[string]any) error {
	p, ok := catalog[primitiveID]
	if !ok {
		return fmt.Errorf("unknown primitive %q", primitiveID)
	}
	if params == nil {
		params = map[string]any{}
	}
	return validateObject(p.Params, params)
}

// validateObject validates a value map against an object schema fragment.
func validateObject(schema map[string]any, params map[string]any) error {
	props, _ := schema["properties"].(map[string]any)

	for _, req := range requiredKeys(schema) {
		if _, present := params[req]; !present {
			return fmt.Errorf("missing required param %q", req)
		}
	}

	for key, val := range params {
		propSchema, known := props[key].(map[string]any)
		if !known {
			return fmt.Errorf("unexpected param %q", key)
		}
		if err := validateValue(propSchema, val); err != nil {
			return fmt.Errorf("param %q: %w", key, err)
		}
	}
	return nil
}

// requiredKeys extracts the "required" list from a schema fragment.
func requiredKeys(schema map[string]any) []string {
	raw, _ := schema["required"].([]string)
	return raw
}

// validateValue validates a single value against a string or array schema.
func validateValue(schema map[string]any, val any) error {
	switch schema["type"] {
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("want string, got %T", val)
		}
	case "array":
		items, ok := toSlice(val)
		if !ok {
			return fmt.Errorf("want array, got %T", val)
		}
		itemSchema, _ := schema["items"].(map[string]any)
		for i, item := range items {
			if err := validateValue(itemSchema, item); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
		}
	default:
		return fmt.Errorf("unsupported schema type %v", schema["type"])
	}
	return nil
}

// toSlice normalizes the array shapes JSON decoding can produce ([]any) plus
// the []string a Go caller may pass directly.
func toSlice(val any) ([]any, bool) {
	switch v := val.(type) {
	case []any:
		return v, true
	case []string:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out, true
	default:
		return nil, false
	}
}
