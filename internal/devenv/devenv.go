// Package devenv holds the one definition of which AppEnv values count as a
// development environment, shared by the password-reset fallback in the user
// handler and the startup warning in authkit.New, so the two cannot drift.
package devenv

import "github.com/zazhedho/gokit/utils"

// Values are the normalized AppEnv values that enable the development
// password-reset fallback.
var Values = []string{"development", "local", "test"}

// IsDev reports whether appEnv, normalized, is one of Values.
func IsDev(appEnv string) bool {
	n := utils.NormalizeKey(appEnv)
	for _, v := range Values {
		if n == v {
			return true
		}
	}
	return false
}
