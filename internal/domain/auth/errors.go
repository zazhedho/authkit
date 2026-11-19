package auth

import "errors"

var (
	// ErrNotFound is returned for the not found case.
	ErrNotFound = errors.New("blacklisted token not found")
	// ErrDuplicate is returned for the duplicate case.
	ErrDuplicate = errors.New("token already blacklisted")
)
