package permission

import "errors"

var (
	ErrNotFound  = errors.New("permission not found")
	ErrDuplicate = errors.New("permission already exists")
	// ErrInUse is returned when a permission is granted to a role and an edit
	// would change what it grants.
	ErrInUse = errors.New("permission is granted to a role")
)
