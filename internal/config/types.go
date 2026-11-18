package config

import "time"

// LoginLimit configures the login attempt limiter.
type LoginLimit struct {
	Limit         int
	Window        time.Duration
	BlockDuration time.Duration
}

// RateLimit configures a per-IP request rate limit.
type RateLimit struct {
	Limit  int
	Window time.Duration
}

// FlagKeys are the runtime app-config keys the user handler consults.
type FlagKeys struct {
	PublicRegistration string
	RegisterOTP        string
	PasswordResetEmail string
}
