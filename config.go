package authkit

import (
	"github.com/zazhedho/authkit/internal/config"
)

// Config is the explicit configuration; DB, AppName and JWTKey are required.
// A typed nil Redis or mailer counts as unset.
type Config = config.Config

type OTPConfig = config.OTPConfig

type PasswordResetConfig = config.PasswordResetConfig

type LoginLimit = config.LoginLimit

type RateLimit = config.RateLimit

// FlagKeys are keys of rows in app_configs, not on/off values.
type FlagKeys = config.FlagKeys

// ConfigFromEnv fills a Config from the environment. The error names the
// authkit variables that could not be parsed, never the host's; refuse to start
// on it. DB, Redis and the mailers are never read from the environment.
func ConfigFromEnv() (Config, error) { return config.FromEnv() }
