// Package authkit assembles the users, auth and RBAC modules from explicit
// configuration. Request-time code never reads the environment: ConfigFromEnv
// (config_env.go) is the only place that does, and it is optional.
package authkit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit/authutil"
	"github.com/zazhedho/authkit/mailer"
	"github.com/zazhedho/authkit/settings"
	"gorm.io/gorm"
)

// Mailer sends both registration OTP and password reset emails.
type Mailer interface {
	mailer.Sender
	mailer.PasswordResetSender
}

// Config is the full explicit configuration. DB, AppName and JWTKey are
// required. Zero values of everything else fall back to the defaults applied
// by withDefaults. OTP.Secret and Reset.Secret have no default: they are
// required whenever both Redis and Mailer are set.
type Config struct {
	DB     *gorm.DB      // required
	Redis  *redis.Client // optional
	Mailer Mailer        // optional

	AppName, AppEnv                 string // AppName is required
	JWTKey                          string // required, at least 32 characters
	AccessTokenTTL, RefreshTokenTTL time.Duration
	DefaultRole                     string // default "viewer"
	GoogleClientIDs                 []string
	EmailAppName                    string        // default: AppName
	PermissionCacheTTL              time.Duration // default 300s
	Login                           settings.LoginLimit
	Register                        settings.RateLimit
	OTP                             settings.OTPConfig
	Reset                           settings.PasswordResetConfig
	Flags                           settings.FlagKeys
}

// String implements fmt.Stringer. It reports whether each secret is set but
// never prints one, and leaves out DB, Redis and Mailer internals, so a config
// that is logged or printed with %v or %+v cannot leak credentials.
func (c Config) String() string {
	set := func(v string) string {
		if strings.TrimSpace(v) == "" {
			return "unset"
		}
		return "set"
	}
	return fmt.Sprintf("authkit.Config{AppName:%q AppEnv:%q JWTKey:%s OTP.Secret:%s Reset.Secret:%s Redis:%t Mailer:%t}",
		c.AppName, c.AppEnv, set(c.JWTKey), set(c.OTP.Secret), set(c.Reset.Secret), c.Redis != nil, c.Mailer != nil)
}

// GoString implements fmt.GoStringer with the same redaction as String, so %#v
// is safe too.
func (c Config) GoString() string { return c.String() }

const (
	defaultPermissionCacheTTL = 300 * time.Second
	defaultLoginLimit         = 5
	defaultLoginWindow        = 60 * time.Second
	defaultLoginBlock         = 300 * time.Second
	defaultRegisterLimit      = 5
	defaultRegisterWindow     = 60 * time.Second
	defaultOTPTTL             = 300 * time.Second
	defaultOTPCooldown        = 60 * time.Second
	defaultOTPRateLimit       = 5
	defaultOTPMaxAttempts     = 5
	defaultResetTTL           = authutil.DefaultResetTTL
	defaultResetCooldown      = 60 * time.Second
	defaultResetRateLimit     = 5
)

// withDefaults returns c with every unset (zero or non-positive) value replaced
// by the default the environment-based code used before. It never invents a
// secret.
func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = authutil.DefaultAccessTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = authutil.DefaultRefreshTTL
	}
	if strings.TrimSpace(c.DefaultRole) == "" {
		c.DefaultRole = authutil.RoleViewer
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

	defaults := settings.DefaultFlagKeys()
	if strings.TrimSpace(c.Flags.PublicRegistration) == "" {
		c.Flags.PublicRegistration = defaults.PublicRegistration
	}
	if strings.TrimSpace(c.Flags.RegisterOTP) == "" {
		c.Flags.RegisterOTP = defaults.RegisterOTP
	}
	if strings.TrimSpace(c.Flags.PasswordResetEmail) == "" {
		c.Flags.PasswordResetEmail = defaults.PasswordResetEmail
	}
	return c
}

// Validate expects defaults to be applied already, as New does before calling
// it. It checks that DB and AppName are set, that JWTKey is a valid signing key
// (at least 32 characters), that DefaultRole is not a privileged role, and that
// OTP.Secret and Reset.Secret are set when both Redis and Mailer are. Those
// secrets are only required then, because the OTP and password reset services
// are inert (never sign or verify anything) otherwise.
func (c Config) Validate() error {
	if c.DB == nil {
		return errors.New("authkit: DB is required")
	}
	if strings.TrimSpace(c.AppName) == "" {
		return errors.New("authkit: AppName is required")
	}
	if _, err := authutil.NewTokens(authutil.TokenConfig{Key: c.JWTKey, AppName: c.AppName}); err != nil {
		return fmt.Errorf("authkit: JWTKey: %w", err)
	}
	switch role := strings.ToLower(strings.TrimSpace(c.DefaultRole)); role {
	case authutil.RoleSuperAdmin, authutil.RoleAdmin:
		return fmt.Errorf("authkit: DefaultRole must not be a privileged role (%q): public registrations would receive it", role)
	}
	if c.Redis != nil && c.Mailer != nil {
		if strings.TrimSpace(c.OTP.Secret) == "" {
			return errors.New("authkit: OTP.Secret is required when Redis and Mailer are set")
		}
		if strings.TrimSpace(c.Reset.Secret) == "" {
			return errors.New("authkit: Reset.Secret is required when Redis and Mailer are set")
		}
	}
	return nil
}
