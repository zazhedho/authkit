package config

import "time"

// OTPConfig is the OTP config.
type OTPConfig struct {
	TTL         time.Duration
	MaxAttempts int
	RateLimit   int
	RateWindow  time.Duration
	Cooldown    time.Duration
	Secret      string
}
