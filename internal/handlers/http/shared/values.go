package shared

import (
	"encoding/json"
	"maps"
	"strings"
)

// The helpers in this file replace the gokit helpers that gokit v0.5 removed
// from its public API. values_test.go pins their behavior.

// NormalizeKey trims and lower-cases value.
func NormalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// InterfaceBool reports whether data is the boolean true or the string "true"
// (any case, surrounding space ignored). Other values are encoded as JSON and
// compared the same way.
func InterfaceBool(data any) bool {
	if data == nil {
		return false
	}

	switch v := data.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		encoded, _ := json.Marshal(data)
		return strings.EqualFold(strings.Trim(string(encoded), `"`), "true")
	}
}

// MergeMetadata returns a new map of base overlaid with extra, or nil when
// both are empty.
func MergeMetadata(base, extra map[string]any) map[string]any {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}

	merged := make(map[string]any, len(base)+len(extra))
	maps.Copy(merged, base)
	maps.Copy(merged, extra)

	return merged
}
