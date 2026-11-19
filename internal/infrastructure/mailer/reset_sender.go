package mailer

import "time"

// PasswordResetSender is the password reset sender.
type PasswordResetSender interface {
	SendPasswordReset(to, token, appName, resetURL string, ttl time.Duration) error
}
