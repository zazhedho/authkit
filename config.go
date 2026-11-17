package authkit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit/internal/authutil"
	"github.com/zazhedho/authkit/internal/settings"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"
)

// OTPConfig configures registration OTP generation, limits and lifetime.
type OTPConfig = settings.OTPConfig

// PasswordResetConfig configures the password reset flow.
type PasswordResetConfig = settings.PasswordResetConfig

// LoginLimit configures login attempt limiting.
type LoginLimit = settings.LoginLimit

// RateLimit configures a request rate limit (count per window).
type RateLimit = settings.RateLimit

// FlagKeys names the app-config keys that act as feature flags.
type FlagKeys = settings.FlagKeys

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
	Login                           LoginLimit
	Register                        RateLimit
	OTP                             OTPConfig
	Reset                           PasswordResetConfig
	Flags                           FlagKeys
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

// ConfigFromEnv builds a Config from the legacy environment variables and
// applies the same defaults the old code used. It leaves DB, Redis and Mailer
// unset, and the OTP and reset secrets stay empty unless OTP_SECRET and
// RESET_SECRET are set: there are no built-in secrets.
//
// This file is the only place in the module (besides internal/mailer/brevo_env.go
// and cmd/) that reads the environment; it is meant to be called once at startup.
func ConfigFromEnv() Config {
	// Duration-style variables (OTP_TTL, ...) win over their _SECONDS forms;
	// rate windows default to the TTL.
	otpTTL := durationEnv("OTP_TTL", time.Duration(gokit.GetEnv("OTP_TTL_SECONDS", 0))*time.Second)
	resetTTL := durationEnv("RESET_TTL", time.Duration(gokit.GetEnv("RESET_TTL_SECONDS", 0))*time.Second)

	resetURL := gokit.GetEnv("RESET_URL_TEMPLATE", "")
	if resetURL == "" {
		resetURL = gokit.GetEnv("RESET_URL", "")
	}

	cfg := Config{
		AppName:         gokit.GetEnv("APP_NAME", ""),
		AppEnv:          gokit.GetEnv("APP_ENV", ""),
		JWTKey:          gokit.GetEnv("JWT_KEY", ""),
		AccessTokenTTL:  time.Duration(gokit.GetEnv("JWT_EXP", 0)) * time.Hour,
		RefreshTokenTTL: time.Duration(gokit.GetEnv("REFRESH_TOKEN_EXP_HOURS", 0)) * time.Hour,
		GoogleClientIDs: googleClientIDsFromEnv(),
		EmailAppName:    gokit.GetEnv("AUTH_EMAIL_APP_NAME", ""),
		PermissionCacheTTL: durationEnv("PERMISSION_CACHE_TTL",
			time.Duration(gokit.GetEnv("PERMISSION_CACHE_TTL_SECONDS", 0))*time.Second),
	}
	cfg.Login.Limit = gokit.GetEnv("LOGIN_ATTEMPT_LIMIT", 0)
	cfg.Login.Window = time.Duration(gokit.GetEnv("LOGIN_ATTEMPT_WINDOW_SECONDS", 0)) * time.Second
	cfg.Login.BlockDuration = time.Duration(gokit.GetEnv("LOGIN_BLOCK_DURATION_SECONDS", 0)) * time.Second
	cfg.Register.Limit = gokit.GetEnv("REGISTER_RATE_LIMIT", 0)
	cfg.Register.Window = time.Duration(gokit.GetEnv("REGISTER_RATE_WINDOW_SECONDS", 0)) * time.Second

	cfg.OTP.Secret = gokit.GetEnv("OTP_SECRET", "")
	cfg.OTP.TTL = otpTTL
	cfg.OTP.Cooldown = durationEnv("OTP_COOLDOWN", time.Duration(gokit.GetEnv("OTP_COOLDOWN_SECONDS", 0))*time.Second)
	cfg.OTP.RateLimit = gokit.GetEnv("OTP_RATE_LIMIT", 0)
	cfg.OTP.MaxAttempts = gokit.GetEnv("OTP_MAX_ATTEMPTS", 0)
	cfg.OTP.RateWindow = durationEnv("OTP_RATE_WINDOW", time.Duration(gokit.GetEnv("OTP_RATE_WINDOW_SECONDS", 0))*time.Second)

	cfg.Reset.Secret = gokit.GetEnv("RESET_SECRET", "")
	cfg.Reset.TTL = resetTTL
	cfg.Reset.Cooldown = durationEnv("RESET_COOLDOWN", time.Duration(gokit.GetEnv("RESET_COOLDOWN_SECONDS", 0))*time.Second)
	cfg.Reset.RateLimit = gokit.GetEnv("RESET_RATE_LIMIT", 0)
	cfg.Reset.RateWindow = durationEnv("RESET_RATE_WINDOW", time.Duration(gokit.GetEnv("RESET_RATE_WINDOW_SECONDS", 0))*time.Second)
	cfg.Reset.URLTemplate = resetURL

	cfg.Flags.PublicRegistration = gokit.GetEnv("CONFIG_PUBLIC_REGISTRATION", "")
	cfg.Flags.RegisterOTP = gokit.GetEnv("CONFIG_REGISTER_OTP", "")
	cfg.Flags.PasswordResetEmail = gokit.GetEnv("CONFIG_PASSWORD_RESET_EMAIL", "")

	return cfg.withDefaults()
}

// durationEnv returns the duration-style variable when it holds a positive
// value, otherwise fallback (the _SECONDS form).
func durationEnv(key string, fallback time.Duration) time.Duration {
	return gokit.DurationFromEnv([]string{key}, fallback)
}

// googleClientIDsFromEnv merges GOOGLE_CLIENT_IDS (comma separated) and
// GOOGLE_CLIENT_ID, trimmed, without blanks or duplicates.
func googleClientIDsFromEnv() []string {
	var ids []string
	seen := map[string]struct{}{}
	add := func(raw string) {
		value := strings.TrimSpace(raw)
		if value == "" {
			return
		}
		if _, dup := seen[value]; dup {
			return
		}
		seen[value] = struct{}{}
		ids = append(ids, value)
	}
	for item := range strings.SplitSeq(gokit.GetEnv("GOOGLE_CLIENT_IDS", ""), ",") {
		add(item)
	}
	add(gokit.GetEnv("GOOGLE_CLIENT_ID", ""))
	return ids
}
