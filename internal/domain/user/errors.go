package user

import "errors"

// Repositories translate storage misses and unique violations into these, and
// keep the original error in the chain so errors.Is still matches it.
var (
	ErrNotFound  = errors.New("user not found")
	ErrDuplicate = errors.New("user already exists")
)

// Google sign-in and registration policy failures.
var (
	ErrGoogleNotConfigured        = errors.New("google login is not configured")
	ErrGoogleTokenInvalid         = errors.New("invalid google token")
	ErrGoogleEmailMissing         = errors.New("google account email is not available")
	ErrPublicRegistrationDisabled = errors.New("public registration is currently disabled")
)
