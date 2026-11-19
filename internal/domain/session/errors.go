package session

import "errors"

// ErrNotFound is returned for the not found case.
var ErrNotFound = errors.New("session not found")
