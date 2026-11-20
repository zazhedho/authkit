package authkit

import (
	"github.com/zazhedho/authkit/internal/config"
)

// Config is the explicit configuration. DB, AppName and JWTKey are required;
// other zero values take defaults. See the README, Configuration.
type Config = config.Config

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

// ConfigFromEnv builds a Config from environment variables; names and defaults:
// see README, Configuration. DB, Redis and Mailer stay unset and there are no
// built-in secrets. Call it once at startup.
func ConfigFromEnv() Config { return config.FromEnv() }

// ConfigFromEnvStrict is ConfigFromEnv that also reports every variable that
// was set to a value it could not parse. It returns the config built so far
// together with the error. Prefer it at startup.
func ConfigFromEnvStrict() (Config, error) { return config.FromEnvStrict() }
