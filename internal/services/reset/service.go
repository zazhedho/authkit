package reset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// Config holds the reset timing and limits; Secret keys the stored token
// hashes and URLTemplate shapes the emailed link.
type Config struct {
	TTL         time.Duration
	Cooldown    time.Duration
	RateWindow  time.Duration
	RateLimit   int
	Secret      string
	URLTemplate string
}

type Service struct {
	Repo   Repository
	Sender Mailer
	Config Config
}

func NewService(repo Repository, sender Mailer, cfg Config) *Service {
	return &Service{Repo: repo, Sender: sender, Config: cfg}
}

// missingSecret reports an empty or blank secret; every entry point then treats
// the service as unconfigured rather than hash with an empty key.
func (s *Service) missingSecret() bool {
	return strings.TrimSpace(s.Config.Secret) == ""
}

func (s *Service) RequestReset(ctx context.Context, email, appName string) error {
	if s == nil || s.Repo == nil || s.Sender == nil || s.missingSecret() {
		return domainreset.ErrNotConfigured
	}

	normalizedEmail := domainuser.SanitizeEmail(email)
	if normalizedEmail == "" {
		return domainreset.ErrInvalid
	}

	cooldownTTL, err := s.Repo.GetCooldownTTL(ctx, normalizedEmail)
	if err != nil {
		return fmt.Errorf("check cooldown: %w", err)
	}
	if cooldownTTL > 0 {
		return &domainreset.ThrottleError{Reason: "cooldown", RetryAfter: cooldownTTL}
	}

	if s.Config.RateLimit > 0 && s.Config.RateWindow > 0 {
		count, retryAfter, err := s.Repo.IncrementSendCount(ctx, normalizedEmail, s.Config.RateWindow)
		if err != nil {
			return fmt.Errorf("rate limit: %w", err)
		}
		if count > s.Config.RateLimit {
			return &domainreset.ThrottleError{Reason: "rate_limit", RetryAfter: retryAfter}
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
		return domainreset.ErrDeliveryFailed
	}

	return nil
}

func (s *Service) VerifyReset(ctx context.Context, token string) (string, error) {
	if s == nil || s.Repo == nil || s.missingSecret() {
		return "", domainreset.ErrNotConfigured
	}

	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return "", domainreset.ErrInvalid
	}

	hash := hashToken(cleanToken, s.Config.Secret)
	email, err := s.Repo.ConsumeToken(ctx, hash)
	if err != nil {
		if errors.Is(err, domainreset.ErrNotFound) {
			return "", domainreset.ErrInvalid
		}
		return "", fmt.Errorf("get token: %w", err)
	}

	_ = s.Repo.ClearCooldown(ctx, email)
	_ = s.Repo.ClearSendCount(ctx, email)
	return email, nil
}
