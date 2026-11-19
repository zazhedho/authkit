package config

import "time"

// PasswordResetConfig is the password reset config.
type PasswordResetConfig struct {
	TTL         time.Duration
	Cooldown    time.Duration
	RateWindow  time.Duration
	RateLimit   int
	Secret      string
	URLTemplate string
}
