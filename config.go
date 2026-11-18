package authkit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit/internal/config"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"
)

// OTPConfig configures registration OTP generation, limits and lifetime.
type OTPConfig = config.OTPConfig

// PasswordResetConfig configures the password reset flow.
type PasswordResetConfig = config.PasswordResetConfig

// LoginLimit configures login attempt limiting.
type LoginLimit = config.LoginLimit

// RateLimit configures a request rate limit (count per window).
type RateLimit = config.RateLimit

// FlagKeys names the app-config keys that act as feature flags.
type FlagKeys = config.FlagKeys

// Config is the explicit configuration. DB, AppName and JWTKey are required;
// other zero values take defaults. OTP.Secret and Reset.Secret have no default
// and are required when both Redis and Mailer are set.
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
		c.AppName, c.AppEnv, set(c.JWTKey), set(c.OTP.Secret), set(c.Reset.Secret), c.Redis != nil, c.Mailer != nil)
}

// GoString implements fmt.GoStringer with the same redaction as String, so %#v
// is safe too.
func (c Config) GoString() string { return c.String() }

// devEnvValues are the normalized AppEnv values that enable the development
// password-reset fallback. The startup warning and the user handler's
// DevEnv setting both derive from them.
var devEnvValues = []string{"development", "local", "test"}

func isDevEnv(appEnv string) bool {
	n := strings.ToLower(strings.TrimSpace(appEnv))
	for _, v := range devEnvValues {
		if n == v {
			return true
		}
	}
	return false
}

const (
	defaultAccessTTL          = 24 * time.Hour
	defaultRefreshTTL         = 168 * time.Hour
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
	defaultResetTTL           = 900 * time.Second
	defaultResetCooldown      = 60 * time.Second
	defaultResetRateLimit     = 5

	defaultFlagPublicRegistration = "auth.public_registration_enabled"
	defaultFlagRegisterOTP        = "auth.register_otp_enabled"
	defaultFlagPasswordResetEmail = "auth.password_reset_email_enabled"
)

// withDefaults returns c with every unset (zero or non-positive) value replaced
// by its default. It never invents a secret.
func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = defaultAccessTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = defaultRefreshTTL
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

// Validate expects defaults applied (as New does). OTP.Secret and Reset.Secret
// are required only when both Redis and Mailer are set; otherwise those services are inert.
func (c Config) Validate() error {
	if c.DB == nil {
		return errors.New("authkit: DB is required")
	}
	if strings.TrimSpace(c.AppName) == "" {
		return errors.New("authkit: AppName is required")
	}
	if _, err := token.NewTokens(token.TokenConfig{Key: c.JWTKey, AppName: c.AppName}); err != nil {
		return fmt.Errorf("authkit: JWTKey: %w", err)
	}
	switch role := strings.ToLower(strings.TrimSpace(c.DefaultRole)); role {
	case domainuser.RoleSuperAdmin, domainuser.RoleAdmin:
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

// ConfigFromEnv builds a Config from environment variables; names and defaults:
// see README, Configuration. DB, Redis and Mailer stay unset and there are no
// built-in secrets. Call it once at startup.
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
