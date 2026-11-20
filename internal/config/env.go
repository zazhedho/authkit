package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// FromEnv names every unparsable authkit variable in its error (defaults still
// apply) and never the host's. Names and defaults: see README, Configuration.
// DB, Redis and the mailers stay unset.
func FromEnv() (Config, error) {
	env := &envReader{}
	cfg := fromEnv(env)
	if err := env.err(); err != nil {
		return cfg, fmt.Errorf("authkit: environment: %w", err)
	}
	return cfg, nil
}

func fromEnv(env *envReader) Config {
	// Duration-style variables (OTP_TTL, ...) win over their _SECONDS forms;
	// rate windows default to the TTL.
	otpTTL := env.duration("OTP_TTL", env.seconds("OTP_TTL_SECONDS"))
	resetTTL := env.duration("RESET_TTL", env.seconds("RESET_TTL_SECONDS"))

	resetURL := env.str("RESET_URL_TEMPLATE")
	if resetURL == "" {
		resetURL = env.str("RESET_URL")
	}

	cfg := Config{
		AppName:            env.str("APP_NAME"),
		AppEnv:             env.str("APP_ENV"),
		JWTKey:             env.str("JWT_KEY"),
		AccessTokenTTL:     accessTTLFromEnv(env),
		RefreshTokenTTL:    time.Duration(env.integer("REFRESH_TOKEN_EXP_HOURS")) * time.Hour,
		SessionMaxLifetime: time.Duration(env.integer("SESSION_MAX_LIFETIME_HOURS")) * time.Hour,
		FailClosedLimiters: env.boolean("LIMITER_FAIL_CLOSED"),
		PhoneLogin:         env.boolean("LOGIN_WITH_PHONE"),
		GoogleClientIDs:    googleClientIDsFromEnv(env),
		EmailAppName:       env.str("AUTH_EMAIL_APP_NAME"),
		PermissionCacheTTL: env.duration("PERMISSION_CACHE_TTL", env.seconds("PERMISSION_CACHE_TTL_SECONDS")),
	}
	cfg.Login.Limit = env.integer("LOGIN_ATTEMPT_LIMIT")
	cfg.Login.Window = env.seconds("LOGIN_ATTEMPT_WINDOW_SECONDS")
	cfg.Login.BlockDuration = env.seconds("LOGIN_BLOCK_DURATION_SECONDS")
	cfg.Register.Limit = env.integer("REGISTER_RATE_LIMIT")
	cfg.Register.Window = env.seconds("REGISTER_RATE_WINDOW_SECONDS")
	cfg.AuthRate.Limit = env.integer("AUTH_RATE_LIMIT")
	cfg.AuthRate.Window = env.seconds("AUTH_RATE_WINDOW_SECONDS")

	cfg.OTP.Secret = env.str("OTP_SECRET")
	cfg.OTP.TTL = otpTTL
	cfg.OTP.Cooldown = env.duration("OTP_COOLDOWN", env.seconds("OTP_COOLDOWN_SECONDS"))
	cfg.OTP.RateLimit = env.integer("OTP_RATE_LIMIT")
	cfg.OTP.MaxAttempts = env.integer("OTP_MAX_ATTEMPTS")
	cfg.OTP.RateWindow = env.duration("OTP_RATE_WINDOW", env.seconds("OTP_RATE_WINDOW_SECONDS"))

	cfg.Reset.Secret = env.str("RESET_SECRET")
	cfg.Reset.TTL = resetTTL
	cfg.Reset.Cooldown = env.duration("RESET_COOLDOWN", env.seconds("RESET_COOLDOWN_SECONDS"))
	cfg.Reset.RateLimit = env.integer("RESET_RATE_LIMIT")
	cfg.Reset.RateWindow = env.duration("RESET_RATE_WINDOW", env.seconds("RESET_RATE_WINDOW_SECONDS"))
	cfg.Reset.URLTemplate = resetURL

	cfg.Flags.PublicRegistration = env.str("CONFIG_PUBLIC_REGISTRATION")
	cfg.Flags.RegisterOTP = env.str("CONFIG_REGISTER_OTP")
	cfg.Flags.PasswordResetEmail = env.str("CONFIG_PASSWORD_RESET_EMAIL")

	return WithDefaults(cfg)
}

// envReader reads authkit's own variables and records the ones it cannot parse,
// so a bad value of the host's is never reported as ours.
type envReader struct{ errs []error }

func (e *envReader) err() error { return errors.Join(e.errs...) }

func (e *envReader) str(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func (e *envReader) integer(key string) int {
	raw := e.str(key)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s must be a valid integer", key))
		return 0
	}
	return n
}

func (e *envReader) boolean(key string) bool {
	raw := e.str(key)
	if raw == "" {
		return false
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s must be a valid boolean", key))
	}
	return b
}

// seconds reads a whole number of seconds.
func (e *envReader) seconds(key string) time.Duration {
	n := e.integer(key)
	if n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// duration reads a duration such as 30s, 5m or 1h, or bare seconds. A missing,
// non-positive or unparsable value gives fallback.
func (e *envReader) duration(key string, fallback time.Duration) time.Duration {
	raw := e.str(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		secs, convErr := strconv.Atoi(raw)
		if convErr != nil {
			e.errs = append(e.errs, fmt.Errorf("%s must be a duration such as 60, 30s, 1m or 1h", key))
			return fallback
		}
		d = time.Duration(secs) * time.Second
	}
	if d <= 0 {
		return fallback
	}
	return d
}

// accessTTLFromEnv reads JWT_EXP_MINUTES, then the older JWT_EXP in hours.
func accessTTLFromEnv(env *envReader) time.Duration {
	if minutes := env.integer("JWT_EXP_MINUTES"); minutes > 0 {
		return time.Duration(minutes) * time.Minute
	}
	return time.Duration(env.integer("JWT_EXP")) * time.Hour
}

// googleClientIDsFromEnv merges GOOGLE_CLIENT_IDS (comma separated) and
// GOOGLE_CLIENT_ID, trimmed, without blanks or duplicates.
func googleClientIDsFromEnv(env *envReader) []string {
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
	for item := range strings.SplitSeq(env.str("GOOGLE_CLIENT_IDS"), ",") {
		add(item)
	}
	add(env.str("GOOGLE_CLIENT_ID"))
	return ids
}
