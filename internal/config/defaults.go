package config

import (
	"reflect"
	"strings"
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

const (
	defaultAccessTTL          = 15 * time.Minute
	defaultSessionMaxLifetime = 30 * 24 * time.Hour
	defaultRefreshTTL         = 168 * time.Hour
	defaultPermissionCacheTTL = 300 * time.Second
	defaultLoginLimit         = 5
	defaultLoginWindow        = 60 * time.Second
	defaultLoginBlock         = 300 * time.Second
	defaultRegisterLimit      = 5
	defaultRegisterWindow     = 60 * time.Second
	defaultAuthRateLimit      = 30
	defaultAuthRateWindow     = 60 * time.Second
	defaultOTPTTL             = 300 * time.Second
	defaultOTPCooldown        = 60 * time.Second
	defaultOTPRateLimit       = 5
	defaultOTPMaxAttempts     = 5
	defaultResetTTL           = 900 * time.Second
	defaultResetCooldown      = 60 * time.Second
	defaultResetRateLimit     = 5

	defaultFlagPublicRegistration = "auth.public_registration_enabled"
	defaultFlagRegisterOTP        = "auth.register_otp_enabled"
	defaultFlagPasswordResetEmail = "auth.password_reset_email_enabled"
)

// WithDefaults returns c with every unset (zero or non-positive) value replaced
// by its default. It never invents a secret.
func WithDefaults(c Config) Config {
	c.Redis = untypedNil(c.Redis)
	c.Mailer = untypedNil(c.Mailer)
	c.OTPMailer = untypedNil(c.OTPMailer)
	c.ResetMailer = untypedNil(c.ResetMailer)
	defaultPositive(&c.AccessTokenTTL, defaultAccessTTL)
	defaultPositive(&c.RefreshTokenTTL, defaultRefreshTTL)
	defaultPositive(&c.SessionMaxLifetime, defaultSessionMaxLifetime)
	defaultText(&c.DefaultRole, domainuser.RoleViewer)
	defaultText(&c.EmailAppName, c.AppName)
	defaultPositive(&c.PermissionCacheTTL, defaultPermissionCacheTTL)

	defaultPositive(&c.Login.Limit, defaultLoginLimit)
	defaultPositive(&c.Login.Window, defaultLoginWindow)
	defaultPositive(&c.Login.BlockDuration, defaultLoginBlock)
	defaultPositive(&c.Register.Limit, defaultRegisterLimit)
	defaultPositive(&c.Register.Window, defaultRegisterWindow)
	defaultPositive(&c.AuthRate.Limit, defaultAuthRateLimit)
	defaultPositive(&c.AuthRate.Window, defaultAuthRateWindow)

	defaultPositive(&c.OTP.TTL, defaultOTPTTL)
	defaultPositive(&c.OTP.Cooldown, defaultOTPCooldown)
	defaultPositive(&c.OTP.RateLimit, defaultOTPRateLimit)
	defaultPositive(&c.OTP.RateWindow, c.OTP.TTL)
	defaultPositive(&c.OTP.MaxAttempts, defaultOTPMaxAttempts)

	defaultPositive(&c.Reset.TTL, defaultResetTTL)
	defaultPositive(&c.Reset.Cooldown, defaultResetCooldown)
	defaultPositive(&c.Reset.RateLimit, defaultResetRateLimit)
	defaultPositive(&c.Reset.RateWindow, c.Reset.TTL)

	defaultText(&c.Flags.PublicRegistration, defaultFlagPublicRegistration)
	defaultText(&c.Flags.RegisterOTP, defaultFlagRegisterOTP)
	defaultText(&c.Flags.PasswordResetEmail, defaultFlagPasswordResetEmail)
	return c
}

// defaultPositive sets *v to def when it is zero or negative.
func defaultPositive[T ~int | ~int64](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// defaultText sets *v to def when it is empty or only whitespace.
func defaultText(v *string, def string) {
	if strings.TrimSpace(*v) == "" {
		*v = def
	}
}

// untypedNil turns a nil pointer stored in an interface (a nil *redis.Client
// passed as Config.Redis, a nil mailer) into a nil interface, so "disabled" has
// one spelling and nothing downstream calls a method on a nil value.
func untypedNil[T any](v T) T {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
		var zero T
		return zero
	}
	return v
}

func Warnings(c Config) []string {
	var out []string
	if c.Redis == nil {
		out = append(out, "authkit: Redis is not configured: login rate limiting, register rate limiting, "+
			"sessions, OTP and email password reset are inactive")
	}
	return out
}
