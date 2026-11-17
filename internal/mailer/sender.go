package mailer

import "time"

// Sender delivers registration OTP emails. ttl is how long the code stays
// valid; implementations should state it in the message.
type Sender interface {
	SendOTP(to, code, appName string, ttl time.Duration) error
}
