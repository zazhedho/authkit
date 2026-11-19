package audit

import "errors"

// ErrNotFound is returned for the not found case.
var ErrNotFound = errors.New("audit trail not found")
