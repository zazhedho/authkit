// Package migrations embeds the authkit SQL migrations (000001 to 000004).
package migrations

import "embed"

// FS holds the *.sql migration files at its root.
//
//go:embed *.sql
var FS embed.FS
