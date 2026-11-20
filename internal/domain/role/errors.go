package role

import "errors"

var (
	ErrNotFound  = errors.New("role not found")
	ErrDuplicate = errors.New("role already exists")
)

// ErrInUse is returned when a role still has users, so it cannot be deleted.
var ErrInUse = errors.New("role is still assigned to users")

// ErrSystemRole is returned when a built-in role is edited or deleted.
var ErrSystemRole = errors.New("system roles cannot be changed")

// ErrInvalidPermission is returned when a permission id does not exist.
var ErrInvalidPermission = errors.New("invalid permission id")
