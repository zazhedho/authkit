package config

import (
	"reflect"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

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
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = defaultAccessTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = defaultRefreshTTL
	}
	if c.SessionMaxLifetime <= 0 {
		c.SessionMaxLifetime = defaultSessionMaxLifetime
	}
	if strings.TrimSpace(c.DefaultRole) == "" {
		c.DefaultRole = domainuser.RoleViewer
	}
	if strings.TrimSpace(c.EmailAppName) == "" {
		c.EmailAppName = c.AppName
	}
	if c.PermissionCacheTTL <= 0 {
		c.PermissionCacheTTL = defaultPermissionCacheTTL
	}

	if c.Login.Limit <= 0 {
		c.Login.Limit = defaultLoginLimit
	}
	if c.Login.Window <= 0 {
		c.Login.Window = defaultLoginWindow
	}
	if c.Login.BlockDuration <= 0 {
		c.Login.BlockDuration = defaultLoginBlock
	}
	if c.Register.Limit <= 0 {
		c.Register.Limit = defaultRegisterLimit
	}
	if c.Register.Window <= 0 {
		c.Register.Window = defaultRegisterWindow
	}
	if c.AuthRate.Limit <= 0 {
		c.AuthRate.Limit = defaultAuthRateLimit
	}
	if c.AuthRate.Window <= 0 {
		c.AuthRate.Window = defaultAuthRateWindow
	}

	if c.OTP.TTL <= 0 {
		c.OTP.TTL = defaultOTPTTL
	}
	if c.OTP.Cooldown <= 0 {
		c.OTP.Cooldown = defaultOTPCooldown
	}
	if c.OTP.RateLimit <= 0 {
		c.OTP.RateLimit = defaultOTPRateLimit
	}
	if c.OTP.RateWindow <= 0 {
		c.OTP.RateWindow = c.OTP.TTL
	}
	if c.OTP.MaxAttempts <= 0 {
		c.OTP.MaxAttempts = defaultOTPMaxAttempts
	}

	if c.Reset.TTL <= 0 {
		c.Reset.TTL = defaultResetTTL
	}
	if c.Reset.Cooldown <= 0 {
		c.Reset.Cooldown = defaultResetCooldown
	}
	if c.Reset.RateLimit <= 0 {
		c.Reset.RateLimit = defaultResetRateLimit
	}
	if c.Reset.RateWindow <= 0 {
		c.Reset.RateWindow = c.Reset.TTL
	}

	if strings.TrimSpace(c.Flags.PublicRegistration) == "" {
		c.Flags.PublicRegistration = defaultFlagPublicRegistration
	}
	if strings.TrimSpace(c.Flags.RegisterOTP) == "" {
		c.Flags.RegisterOTP = defaultFlagRegisterOTP
	}
	if strings.TrimSpace(c.Flags.PasswordResetEmail) == "" {
		c.Flags.PasswordResetEmail = defaultFlagPasswordResetEmail
	}
	return c
}

// untypedNil turns a nil pointer stored in the interface (a nil *redis.Client
// passed as Config.Redis) into a nil interface, so "Redis is disabled" has one
// spelling and nothing downstream calls a method on a nil client.
func untypedNil(c redis.UniversalClient) redis.UniversalClient {
	if v := reflect.ValueOf(c); v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	return c
}
