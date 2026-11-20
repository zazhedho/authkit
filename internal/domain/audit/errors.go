package audit

import "errors"

var ErrNotFound = errors.New("audit trail not found")

// Store refuses an event without these fields.
var (
	ErrActionRequired   = errors.New("action is required")
	ErrResourceRequired = errors.New("resource is required")
	ErrStatusRequired   = errors.New("status is required")
)
