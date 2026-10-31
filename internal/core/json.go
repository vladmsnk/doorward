package core

import "encoding/json"

// jsonText writes a value as JSON, so messages show "7500" for a number and
// "\"7500\"" for a string.
func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}

func jsonType(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case float64:
		return "a number"
	case bool:
		return "a boolean"
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	case nil:
		return "null"
	default:
		return "a value of an unknown type"
	}
}
