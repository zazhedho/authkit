package reset

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotFound means no reset token is stored for the hash.
var ErrNotFound = errors.New("reset token not found")

var (
	// ErrInvalid is returned for the invalid case.
	ErrInvalid = errors.New("reset token invalid or expired")
	// ErrNotConfigured is returned for the not configured case.
	ErrNotConfigured = errors.New("password reset service not configured")
	// ErrDeliveryFailed is returned for the delivery failed case.
	ErrDeliveryFailed = errors.New("password reset delivery failed")
)

// ThrottleError reports a send refused by a cooldown or rate limit.
type ThrottleError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *ThrottleError) Error() string {
	if e == nil {
		return "reset throttled"
	}
	return fmt.Sprintf("reset throttled: %s", e.Reason)
}
