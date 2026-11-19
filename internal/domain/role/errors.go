package role

import "errors"

var (
	// ErrNotFound is returned for the not found case.
	ErrNotFound = errors.New("role not found")
	// ErrDuplicate is returned for the duplicate case.
	ErrDuplicate = errors.New("role already exists")
)

// ErrInUse is returned when a role still has users, so it cannot be deleted.
var ErrInUse = errors.New("role is still assigned to users")
