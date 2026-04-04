package tool

import (
	"reflect"
	"strings"
)

// SchemaFromStruct generates an OpenAI-compatible JSON schema from a Go struct's
// json tags and desc tags. Fields with `omitempty` in their json tag are optional.
func SchemaFromStruct[T any]() map[string]any {
	var zero T
	t := reflect.TypeOf(zero)

	properties := make(map[string]any)
	var required []string

	for i := range t.NumField() {
		field := t.Field(i)

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		parts := strings.Split(jsonTag, ",")
		name := parts[0]
		omitempty := len(parts) > 1 && parts[1] == "omitempty"

		prop := map[string]any{
			"type": goTypeToJSONType(field.Type.Kind()),
		}

		if desc := field.Tag.Get("desc"); desc != "" {
			prop["description"] = desc
		}

		properties[name] = prop

		if !omitempty {
			required = append(required, name)
		}
	}

	return map[string]any{
		"type":       "object",
		"properties": properties,
		"required":   required,
	}
}

func goTypeToJSONType(k reflect.Kind) string {
	switch k {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice:
		return "array"
	default:
		return "string"
	}
}
