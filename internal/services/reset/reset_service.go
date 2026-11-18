package reset

import (
	"context"
	"errors"
	"fmt"
	"github.com/zazhedho/authkit/internal/config"
	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
	"github.com/zazhedho/gokit"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrResetInvalid        = errors.New("reset token invalid or expired")
	ErrResetNotConfigured  = errors.New("password reset service not configured")
	ErrResetDeliveryFailed = errors.New("password reset delivery failed")
)

type ThrottleError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *ThrottleError) Error() string {
	if e == nil {
		return "reset throttled"
	}
	return fmt.Sprintf("reset throttled: %s", e.Reason)
}

type Service struct {
	Repo   Repository
	Sender mailer.PasswordResetSender
	Config config.PasswordResetConfig
}

func NewService(repo Repository, sender mailer.PasswordResetSender, cfg config.PasswordResetConfig) *Service {
	return &Service{Repo: repo, Sender: sender, Config: cfg}
}

// // missingSecret reports an empty or blank secret; every entry point then treats
// // the service as unconfigured rather than hash with an empty key.
func (s *Service) missingSecret() bool {
	return strings.TrimSpace(s.Config.Secret) == ""
}

func (s *Service) RequestReset(ctx context.Context, email, appName string) error {
	if s == nil || s.Repo == nil || s.Sender == nil || s.missingSecret() {
		return ErrResetNotConfigured
	}

	normalizedEmail := gokit.SanitizeEmail(email)
	if normalizedEmail == "" {
		return ErrResetInvalid
	}

	cooldownTTL, err := s.Repo.GetCooldownTTL(ctx, normalizedEmail)
	if err != nil {
		return fmt.Errorf("check cooldown: %w", err)
	}
	if cooldownTTL > 0 {
		return &ThrottleError{Reason: "cooldown", RetryAfter: cooldownTTL}
	}

	if s.Config.RateLimit > 0 && s.Config.RateWindow > 0 {
		count, retryAfter, err := s.Repo.IncrementSendCount(ctx, normalizedEmail, s.Config.RateWindow)
		if err != nil {
			return fmt.Errorf("rate limit: %w", err)
		}
		if count > s.Config.RateLimit {
			return &ThrottleError{Reason: "rate_limit", RetryAfter: retryAfter}
		}
	}

	token, err := generateResetToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	hash := hashToken(token, s.Config.Secret)
	if err := s.Repo.SetToken(ctx, hash, normalizedEmail, s.Config.TTL); err != nil {
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		return fmt.Errorf("store token: %w", err)
	}
	if err := s.Repo.SetCooldown(ctx, normalizedEmail, s.Config.Cooldown); err != nil {
		_ = s.Repo.DeleteToken(ctx, hash)
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		return fmt.Errorf("set cooldown: %w", err)
	}

	resetURL := buildResetURL(s.Config.URLTemplate, token)
	if err := s.Sender.SendPasswordReset(normalizedEmail, token, appName, resetURL, s.Config.TTL); err != nil {
		_ = s.Repo.DeleteToken(ctx, hash)
		_ = s.Repo.ClearCooldown(ctx, normalizedEmail)
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		return ErrResetDeliveryFailed
	}

	return nil
}

func (s *Service) VerifyReset(ctx context.Context, token string) (string, error) {
	if s == nil || s.Repo == nil || s.missingSecret() {
		return "", ErrResetNotConfigured
	}

	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return "", ErrResetInvalid
	}

	hash := hashToken(cleanToken, s.Config.Secret)
	email, err := s.Repo.GetEmailByToken(ctx, hash)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrResetInvalid
		}
		return "", fmt.Errorf("get token: %w", err)
	}

	_ = s.Repo.DeleteToken(ctx, hash)
	_ = s.Repo.ClearCooldown(ctx, email)
	_ = s.Repo.ClearSendCount(ctx, email)
	return email, nil
}
