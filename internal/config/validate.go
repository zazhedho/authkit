package config

import (
	"errors"
	"fmt"
	"strings"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
)

// minSecretLength is the shortest OTP.Secret or Reset.Secret Validate accepts.
const minSecretLength = 32

// Validate expects defaults applied (as New does). OTP.Secret and Reset.Secret
// are required only when both Redis and Mailer are set; otherwise those services are inert.
func (c Config) Validate() error {
	if c.DB == nil {
		return errors.New("authkit: DB is required")
	}
	if strings.TrimSpace(c.AppName) == "" {
		return errors.New("authkit: AppName is required")
	}
	if _, err := token.NewTokens(token.Config{Key: c.JWTKey, AppName: c.AppName}); err != nil {
		return fmt.Errorf("authkit: JWTKey: %w", err)
	}
	switch role := strings.ToLower(strings.TrimSpace(c.DefaultRole)); role {
	case domainuser.RoleSuperAdmin, domainuser.RoleAdmin:
		return fmt.Errorf("authkit: DefaultRole must not be a privileged role (%q): public registrations would receive it", role)
	}
	if c.Redis != nil && OTPSender(c) != nil && strings.TrimSpace(c.OTP.Secret) == "" {
		return errors.New("authkit: OTP.Secret is required when Redis and a Mailer are set")
	}
	if c.Redis != nil && ResetSender(c) != nil && strings.TrimSpace(c.Reset.Secret) == "" {
		return errors.New("authkit: Reset.Secret is required when Redis and a Mailer are set")
	}
	// A secret that is set must be long enough to key an HMAC, even when the
	// features that use it are off today.
	if secret := strings.TrimSpace(c.OTP.Secret); secret != "" && len(secret) < minSecretLength {
		return fmt.Errorf("authkit: OTP.Secret must be at least %d characters", minSecretLength)
	}
	if secret := strings.TrimSpace(c.Reset.Secret); secret != "" && len(secret) < minSecretLength {
		return fmt.Errorf("authkit: Reset.Secret must be at least %d characters", minSecretLength)
	}
	return nil
}
