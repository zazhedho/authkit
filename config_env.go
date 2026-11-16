package authkit

import (
	"strings"
	"time"

	"github.com/zazhedho/gokit/utils"
)

// ConfigFromEnv builds a Config from the legacy environment variables and
// applies the same defaults the old code used. It leaves DB, Redis and Mailer
// unset, and the OTP and reset secrets stay empty unless OTP_SECRET and
// RESET_SECRET are set: there are no built-in secrets.
//
// This file is the only place in the module (besides mailer/brevo_env.go and
// cmd/) that reads the environment; it is meant to be called once at startup.
func ConfigFromEnv() Config {
	// Duration-style variables (OTP_TTL, ...) win over their _SECONDS forms;
	// rate windows default to the TTL.
	otpTTL := durationEnv("OTP_TTL", time.Duration(utils.GetEnv("OTP_TTL_SECONDS", 0))*time.Second)
	resetTTL := durationEnv("RESET_TTL", time.Duration(utils.GetEnv("RESET_TTL_SECONDS", 0))*time.Second)

	resetURL := utils.GetEnv("RESET_URL_TEMPLATE", "")
	if resetURL == "" {
		resetURL = utils.GetEnv("RESET_URL", "")
	}

	cfg := Config{
		AppName:         utils.GetEnv("APP_NAME", ""),
		AppEnv:          utils.GetEnv("APP_ENV", ""),
		JWTKey:          utils.GetEnv("JWT_KEY", ""),
		AccessTokenTTL:  time.Duration(utils.GetEnv("JWT_EXP", 0)) * time.Hour,
		RefreshTokenTTL: time.Duration(utils.GetEnv("REFRESH_TOKEN_EXP_HOURS", 0)) * time.Hour,
		GoogleClientIDs: googleClientIDsFromEnv(),
		EmailAppName:    utils.GetEnv("AUTH_EMAIL_APP_NAME", ""),
		PermissionCacheTTL: durationEnv("PERMISSION_CACHE_TTL",
			time.Duration(utils.GetEnv("PERMISSION_CACHE_TTL_SECONDS", 0))*time.Second),
	}
	cfg.Login.Limit = utils.GetEnv("LOGIN_ATTEMPT_LIMIT", 0)
	cfg.Login.Window = time.Duration(utils.GetEnv("LOGIN_ATTEMPT_WINDOW_SECONDS", 0)) * time.Second
	cfg.Login.BlockDuration = time.Duration(utils.GetEnv("LOGIN_BLOCK_DURATION_SECONDS", 0)) * time.Second
	cfg.Register.Limit = utils.GetEnv("REGISTER_RATE_LIMIT", 0)
	cfg.Register.Window = time.Duration(utils.GetEnv("REGISTER_RATE_WINDOW_SECONDS", 0)) * time.Second

	cfg.OTP.Secret = utils.GetEnv("OTP_SECRET", "")
	cfg.OTP.TTL = otpTTL
	cfg.OTP.Cooldown = durationEnv("OTP_COOLDOWN", time.Duration(utils.GetEnv("OTP_COOLDOWN_SECONDS", 0))*time.Second)
	cfg.OTP.RateLimit = utils.GetEnv("OTP_RATE_LIMIT", 0)
	cfg.OTP.MaxAttempts = utils.GetEnv("OTP_MAX_ATTEMPTS", 0)
	cfg.OTP.RateWindow = durationEnv("OTP_RATE_WINDOW", time.Duration(utils.GetEnv("OTP_RATE_WINDOW_SECONDS", 0))*time.Second)

	cfg.Reset.Secret = utils.GetEnv("RESET_SECRET", "")
	cfg.Reset.TTL = resetTTL
	cfg.Reset.Cooldown = durationEnv("RESET_COOLDOWN", time.Duration(utils.GetEnv("RESET_COOLDOWN_SECONDS", 0))*time.Second)
	cfg.Reset.RateLimit = utils.GetEnv("RESET_RATE_LIMIT", 0)
	cfg.Reset.RateWindow = durationEnv("RESET_RATE_WINDOW", time.Duration(utils.GetEnv("RESET_RATE_WINDOW_SECONDS", 0))*time.Second)
	cfg.Reset.URLTemplate = resetURL

	cfg.Flags.PublicRegistration = utils.GetEnv("CONFIG_PUBLIC_REGISTRATION", "")
	cfg.Flags.RegisterOTP = utils.GetEnv("CONFIG_REGISTER_OTP", "")
	cfg.Flags.PasswordResetEmail = utils.GetEnv("CONFIG_PASSWORD_RESET_EMAIL", "")

	return cfg.withDefaults()
}

// durationEnv returns the duration-style variable when it holds a positive
// value, otherwise fallback (the _SECONDS form).
func durationEnv(key string, fallback time.Duration) time.Duration {
	return utils.DurationFromEnv([]string{key}, fallback)
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
	for item := range strings.SplitSeq(utils.GetEnv("GOOGLE_CLIENT_IDS", ""), ",") {
		add(item)
	}
	add(utils.GetEnv("GOOGLE_CLIENT_ID", ""))
	return ids
}
