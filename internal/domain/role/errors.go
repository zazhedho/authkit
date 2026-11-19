package role

import "errors"

var (
	// ErrNotFound is returned for the not found case.
	ErrNotFound = errors.New("role not found")
	// ErrDuplicate is returned for the duplicate case.
	ErrDuplicate = errors.New("role already exists")
)
