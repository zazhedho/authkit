package permission

import "errors"

var (
	// ErrNotFound is returned for the not found case.
	ErrNotFound = errors.New("permission not found")
	// ErrDuplicate is returned for the duplicate case.
	ErrDuplicate = errors.New("permission already exists")
)
