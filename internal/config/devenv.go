// Package devenv defines which AppEnv values count as development, shared by the
// reset fallback and the New warning so they cannot drift.
package config

import "github.com/zazhedho/gokit"

// Values are the normalized AppEnv values that enable the development
// password-reset fallback.
var Values = []string{"development", "local", "test"}

// IsDev reports whether appEnv, normalized, is one of Values.
func IsDev(appEnv string) bool {
	n := gokit.NormalizeKey(appEnv)
	for _, v := range Values {
		if n == v {
			return true
		}
	}
	return false
}
