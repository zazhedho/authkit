// Package config holds the authkit configuration: the Config type, defaults,
// validation, environment parsing and secret redaction. It is the only package
// that reads the environment.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
)

// OTPMailer sends registration OTP emails.
type OTPMailer interface {
	mailer.Sender
}

// ResetMailer sends password reset emails.
type ResetMailer interface {
	mailer.PasswordResetSender
}

// Mailer sends both registration OTP and password reset emails.
type Mailer interface {
	OTPMailer
	ResetMailer
}

// OTPConfig configures registration OTP generation, limits and lifetime.
type OTPConfig struct {
	TTL         time.Duration
	MaxAttempts int
	RateLimit   int
	RateWindow  time.Duration
	Cooldown    time.Duration
	Secret      string
}

// PasswordResetConfig configures the password reset flow.
type PasswordResetConfig struct {
	TTL         time.Duration
	Cooldown    time.Duration
	RateWindow  time.Duration
	RateLimit   int
	Secret      string
	URLTemplate string
}

// LoginLimit configures login attempt limiting.
type LoginLimit struct {
	Limit         int
	Window        time.Duration
	BlockDuration time.Duration
}

// RateLimit configures a request rate limit (count per window).
type RateLimit struct {
	Limit  int
	Window time.Duration
}

// FlagKeys names the app-config keys that act as feature flags.
type FlagKeys struct {
	PublicRegistration string
	RegisterOTP        string
	PasswordResetEmail string
}

// Config is the explicit configuration. DB, AppName and JWTKey are required;
// other zero values take defaults. OTP.Secret and Reset.Secret have no default
// and are required when both Redis and Mailer are set.
type Config struct {
	DB    *gorm.DB              // required
	Redis redis.UniversalClient // optional; a nil *redis.Client counts as unset
	// Mailer sends both OTP and reset emails. OTPMailer and ResetMailer, when
	// set, take precedence for their own flow, so the two can use different
	// senders or only one can be enabled.
	Mailer      Mailer      // optional
	OTPMailer   OTPMailer   // optional
	ResetMailer ResetMailer // optional

	AppName, AppEnv                 string        // AppName is required
	JWTKey                          string        // required, at least 32 characters
	AccessTokenTTL, RefreshTokenTTL time.Duration // default 15m and 168h
	// SessionMaxLifetime caps a session from login, however often it is
	// refreshed. Default 30 days; needs Redis.
	SessionMaxLifetime time.Duration
	// FailClosedLimiters makes the rate limiters reject requests when Redis
	// fails instead of letting them through (the default).
	FailClosedLimiters bool
	// PhoneLogin lets users sign in with their phone number. Off by default:
	// phone numbers are not verified.
	PhoneLogin         bool
	DefaultRole        string // default "viewer"
	GoogleClientIDs    []string
	EmailAppName       string        // default: AppName
	PermissionCacheTTL time.Duration // default 300s
	Login              LoginLimit
	Register           RateLimit
	// AuthRate is the per-IP limit on the unauthenticated auth routes that have
	// no limiter of their own: google login, refresh, forgot and reset password,
	// and the authenticated change-password. Default 30 per minute.
	AuthRate RateLimit
	OTP      OTPConfig
	Reset    PasswordResetConfig
	Flags    FlagKeys
}

// String reports whether each secret is set but never prints one, so logging a
// Config with %v cannot leak credentials.
func (c Config) String() string {
	set := func(v string) string {
		if strings.TrimSpace(v) == "" {
			return "unset"
		}
		return "set"
	}
	return fmt.Sprintf("authkit.Config{AppName:%q AppEnv:%q JWTKey:%s OTP.Secret:%s Reset.Secret:%s Redis:%t Mailer:%t}",
		c.AppName, c.AppEnv, set(c.JWTKey), set(c.OTP.Secret), set(c.Reset.Secret), c.Redis != nil, OTPSender(c) != nil || ResetSender(c) != nil)
}

// GoString implements fmt.GoStringer with the same redaction as String, so %#v
// is safe too.
func (c Config) GoString() string { return c.String() }

// OTPSender is the sender the OTP flow uses: OTPMailer, else Mailer.
func OTPSender(c Config) OTPMailer {
	if c.OTPMailer != nil {
		return c.OTPMailer
	}
	if c.Mailer != nil {
		return c.Mailer
	}
	return nil
}

// ResetSender is the sender the reset flow uses: ResetMailer, else Mailer.
func ResetSender(c Config) ResetMailer {
	if c.ResetMailer != nil {
		return c.ResetMailer
	}
	if c.Mailer != nil {
		return c.Mailer
	}
	return nil
}
