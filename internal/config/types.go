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

const (
	DefaultFlagPublicRegistration = "auth.public_registration_enabled"
	DefaultFlagRegisterOTP        = "auth.register_otp_enabled"
	DefaultFlagPasswordResetEmail = "auth.password_reset_email_enabled"
)

// DefaultFlagKeys returns the built-in app-config keys.
func DefaultFlagKeys() FlagKeys {
	return FlagKeys{
		PublicRegistration: DefaultFlagPublicRegistration,
		RegisterOTP:        DefaultFlagRegisterOTP,
		PasswordResetEmail: DefaultFlagPasswordResetEmail,
	}
}

// UserHandler carries the explicit settings the user handler needs at request
// time.
type UserHandler struct {
	AppEnv, EmailAppName  string
	AccessTTL, RefreshTTL time.Duration
	OTPCooldown           time.Duration
	// ResetCooldown is the resend cooldown reported by the forgot-password
	// email flow.
	ResetCooldown time.Duration
	Flags         FlagKeys
}
