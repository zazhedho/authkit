package shared

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// The helpers in this file replace the gokit string helpers the services used,
// so services need no framework package. text_test.go pins their output.

// NewID returns a UUID v7 string, falling back to v4 if v7 cannot be made.
// It is the default for the services' injected NewID.
func NewID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

// NormalizeKey trims and lower-cases value.
func NormalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// CleanText prepares user-supplied text for storage: it trims surrounding
// whitespace and does nothing else. The text is deliberately not
// HTML-processed. The previous StripHTML removed tags and then unescaped
// entities, so "&lt;script&gt;" came out as a live "<script>". Escaping is the
// job of whatever renders the stored value.
func CleanText(s string) string {
	return strings.TrimSpace(s)
}

// HumanizeKey turns snake_case and kebab-case keys into space separated words.
func HumanizeKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

// TitleHumanized is HumanizeKey with each word capitalised.
func TitleHumanized(value string) string {
	value = HumanizeKey(value)
	if value == "" {
		return value
	}

	words := strings.Fields(value)
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}
	return strings.Join(words, " ")
}

// JSONEncode marshals data, returning "" when it cannot be encoded.
func JSONEncode(data any) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonData)
}

// InterfaceString renders strings and byte slices as is and other values as
// JSON.
func InterfaceString(data any) string {
	if data == nil {
		return ""
	}
	switch v := data.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		bytes, _ := json.Marshal(data)
		return string(bytes)
	}
}

// NormalizeUUIDPointer returns the trimmed value when it is a UUID, else nil.
func NormalizeUUIDPointer(input string) *string {
	value := strings.TrimSpace(input)
	if value == "" {
		return nil
	}

	if _, err := uuid.Parse(value); err != nil {
		return nil
	}

	return &value
}

// normalizePayload round-trips input through JSON so structs become maps and
// slices; nil becomes an empty map and unencodable input is returned as is.
func normalizePayload(input any) any {
	if input == nil {
		return map[string]any{}
	}

	raw, err := json.Marshal(input)
	if err != nil {
		return input
	}

	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return input
	}

	return normalized
}

// isSensitiveKey reports whether a payload key names a secret.
func isSensitiveKey(key string) bool {
	k := NormalizeKey(key)
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "otp")
}

// RedactSensitivePayload normalises input and replaces the values of
// sensitive keys with "[REDACTED]".
func RedactSensitivePayload(input any) any {
	return redactSensitiveValue(normalizePayload(input))
}

// redactSensitiveValue redacts sensitive keys in an already normalised value.
func redactSensitiveValue(input any) any {
	switch v := input.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			if isSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactSensitiveValue(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, val := range v {
			out = append(out, redactSensitiveValue(val))
		}
		return out
	default:
		return v
	}
}

// TitleCase capitalises the first letter of each word and lower-cases the
// rest, using the English rules of golang.org/x/text/cases.
func TitleCase(s string) string {
	return cases.Title(language.English).String(s)
}
