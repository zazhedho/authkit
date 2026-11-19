package session

import "errors"

// ErrNotFound is returned for the not found case.
var ErrNotFound = errors.New("session not found")

// ErrRefreshReused is returned when an already-rotated refresh token is
// presented again; the session is revoked at the same time.
var ErrRefreshReused = errors.New("refresh token was already used")
