package otp

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotFound means no OTP is stored for the address.
var ErrNotFound = errors.New("otp not found")

var (
	// ErrInvalid is returned for the invalid case.
	ErrInvalid = errors.New("otp invalid or expired")
	// ErrTooManyAttempt is returned for the too many attempt case.
	ErrTooManyAttempt = errors.New("otp too many attempts")
	// ErrNotConfigured is returned for the not configured case.
	ErrNotConfigured = errors.New("otp service not configured")
	// ErrDeliveryFailed is returned for the delivery failed case.
	ErrDeliveryFailed = errors.New("otp delivery failed")
)

// ThrottleError reports a send refused by a cooldown or rate limit.
type ThrottleError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *ThrottleError) Error() string {
	if e == nil {
		return "otp throttled"
	}
	return fmt.Sprintf("otp throttled: %s", e.Reason)
}
