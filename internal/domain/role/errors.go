package role

import "errors"

var (
	ErrNotFound  = errors.New("role not found")
	ErrDuplicate = errors.New("role already exists")
)

// ErrInUse is returned when a role still has users, so it cannot be deleted.
var ErrInUse = errors.New("role is still assigned to users")
