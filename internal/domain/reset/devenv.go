package reset

import "strings"

// DevEnvValues are the normalized AppEnv values that enable the development
// password-reset fallback. The reset flow and the startup warning share them
// so they cannot drift.
var DevEnvValues = []string{"development", "local", "test"}

// IsDevEnv reports whether appEnv, normalized, is one of DevEnvValues.
func IsDevEnv(appEnv string) bool {
	n := strings.ToLower(strings.TrimSpace(appEnv))
	for _, v := range DevEnvValues {
		if n == v {
			return true
		}
	}
	return false
}
