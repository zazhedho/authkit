package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
)

// FromEnvStrict is FromEnv that also reports every variable that
// was set to a value it could not parse (a typo such as JWT_EXP_MINUTES=15m
// otherwise falls back to the default without a word). It returns the config
// built so far together with the error. Prefer it at startup.
func FromEnvStrict() (Config, error) {
	cfg := FromEnv()
	if err := gokit.EnvErrors(); err != nil {
		return cfg, fmt.Errorf("authkit: environment: %w", err)
	}
	return cfg, nil
}

// FromEnv builds a Config from environment variables; names and defaults:
// see README, Configuration. DB, Redis and Mailer stay unset and there are no
// built-in secrets. Call it once at startup.
func FromEnv() Config {
	// Duration-style variables (OTP_TTL, ...) win over their _SECONDS forms;
	// rate windows default to the TTL.
	otpTTL := durationEnv("OTP_TTL", time.Duration(gokit.GetEnv("OTP_TTL_SECONDS", 0))*time.Second)
	resetTTL := durationEnv("RESET_TTL", time.Duration(gokit.GetEnv("RESET_TTL_SECONDS", 0))*time.Second)

	resetURL := gokit.GetEnv("RESET_URL_TEMPLATE", "")
	if resetURL == "" {
		resetURL = gokit.GetEnv("RESET_URL", "")
	}

	cfg := Config{
		AppName:            gokit.GetEnv("APP_NAME", ""),
		AppEnv:             gokit.GetEnv("APP_ENV", ""),
		JWTKey:             gokit.GetEnv("JWT_KEY", ""),
		AccessTokenTTL:     accessTTLFromEnv(),
		RefreshTokenTTL:    time.Duration(gokit.GetEnv("REFRESH_TOKEN_EXP_HOURS", 0)) * time.Hour,
		SessionMaxLifetime: time.Duration(gokit.GetEnv("SESSION_MAX_LIFETIME_HOURS", 0)) * time.Hour,
		FailClosedLimiters: gokit.GetEnv("LIMITER_FAIL_CLOSED", false),
		PhoneLogin:         gokit.GetEnv("LOGIN_WITH_PHONE", false),
		GoogleClientIDs:    googleClientIDsFromEnv(),
		EmailAppName:       gokit.GetEnv("AUTH_EMAIL_APP_NAME", ""),
		PermissionCacheTTL: durationEnv("PERMISSION_CACHE_TTL",
			time.Duration(gokit.GetEnv("PERMISSION_CACHE_TTL_SECONDS", 0))*time.Second),
	}
	cfg.Login.Limit = gokit.GetEnv("LOGIN_ATTEMPT_LIMIT", 0)
	cfg.Login.Window = time.Duration(gokit.GetEnv("LOGIN_ATTEMPT_WINDOW_SECONDS", 0)) * time.Second
	cfg.Login.BlockDuration = time.Duration(gokit.GetEnv("LOGIN_BLOCK_DURATION_SECONDS", 0)) * time.Second
	cfg.Register.Limit = gokit.GetEnv("REGISTER_RATE_LIMIT", 0)
	cfg.Register.Window = time.Duration(gokit.GetEnv("REGISTER_RATE_WINDOW_SECONDS", 0)) * time.Second
	cfg.AuthRate.Limit = gokit.GetEnv("AUTH_RATE_LIMIT", 0)
	cfg.AuthRate.Window = time.Duration(gokit.GetEnv("AUTH_RATE_WINDOW_SECONDS", 0)) * time.Second

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

	return WithDefaults(cfg)
}

// accessTTLFromEnv reads JWT_EXP_MINUTES, then the older JWT_EXP in hours.
func accessTTLFromEnv() time.Duration {
	if minutes := gokit.GetEnv("JWT_EXP_MINUTES", 0); minutes > 0 {
		return time.Duration(minutes) * time.Minute
	}
	return time.Duration(gokit.GetEnv("JWT_EXP", 0)) * time.Hour
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
