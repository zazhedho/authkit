package otp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zazhedho/logus"

	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// Config holds the OTP timing and limits; Secret keys the stored code hashes.
type Config struct {
	TTL         time.Duration
	MaxAttempts int
	RateLimit   int
	RateWindow  time.Duration
	Cooldown    time.Duration
	Secret      string
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
// the service as unconfigured rather than sign with an empty key.
func (s *Service) missingSecret() bool {
	return strings.TrimSpace(s.Config.Secret) == ""
}

func (s *Service) SendRegisterOTP(ctx context.Context, email, appName string) error {
	if s == nil || s.Repo == nil || s.Sender == nil || s.missingSecret() {
		return domainotp.ErrNotConfigured
	}

	normalizedEmail := domainuser.SanitizeEmail(email)
	if normalizedEmail == "" {
		return domainotp.ErrInvalid
	}

	cooldownTTL, err := s.Repo.GetCooldownTTL(ctx, normalizedEmail)
	if err != nil {
		return fmt.Errorf("check cooldown: %w", err)
	}
	if cooldownTTL > 0 {
		return &domainotp.ThrottleError{Reason: "cooldown", RetryAfter: cooldownTTL}
	}

	if s.Config.RateLimit > 0 && s.Config.RateWindow > 0 {
		count, retryAfter, err := s.Repo.IncrementSendCount(ctx, normalizedEmail, s.Config.RateWindow)
		if err != nil {
			return fmt.Errorf("rate limit: %w", err)
		}
		if count > s.Config.RateLimit {
			return &domainotp.ThrottleError{Reason: "rate_limit", RetryAfter: retryAfter}
		}
	}

	code, err := generateOTP()
	if err != nil {
		return fmt.Errorf("generate otp: %w", err)
	}

	hashed := hashOTP(normalizedEmail, code, s.Config.Secret)
	if err := s.Repo.SetOTP(ctx, normalizedEmail, hashed, s.Config.TTL); err != nil {
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		return fmt.Errorf("store otp: %w", err)
	}
	// The attempt counter is not reset by a resend: guesses against the
	// address add up across codes until the counter's window ends.
	if err := s.Repo.SetCooldown(ctx, normalizedEmail, s.Config.Cooldown); err != nil {
		_ = s.Repo.DeleteOTP(ctx, normalizedEmail)
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		return fmt.Errorf("set cooldown: %w", err)
	}

	if err := s.Sender.SendOTP(normalizedEmail, code, appName, s.Config.TTL); err != nil {
		_ = s.Repo.DeleteOTP(ctx, normalizedEmail)
		_ = s.Repo.ClearCooldown(ctx, normalizedEmail)
		_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
		logus.Log(logus.LevelError, "OTP delivery error:", err)
		return domainotp.ErrDeliveryFailed
	}

	return nil
}

func (s *Service) VerifyRegisterOTP(ctx context.Context, email, code string) error {
	if s == nil || s.Repo == nil || s.missingSecret() {
		return domainotp.ErrNotConfigured
	}

	normalizedEmail := domainuser.SanitizeEmail(email)
	cleanCode := strings.TrimSpace(code)
	if normalizedEmail == "" || cleanCode == "" {
		return domainotp.ErrInvalid
	}

	hashed, err := s.Repo.GetOTP(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, domainotp.ErrNotFound) {
			return domainotp.ErrInvalid
		}
		return fmt.Errorf("get otp: %w", err)
	}

	attempts, err := s.Repo.IncrementAttempts(ctx, normalizedEmail, s.Config.TTL)
	if err != nil {
		return fmt.Errorf("increment attempts: %w", err)
	}

	// Past the limit the counter stays until its window ends, so asking for a
	// fresh code does not hand out fresh guesses.
	if s.Config.MaxAttempts > 0 && attempts > s.Config.MaxAttempts {
		_ = s.Repo.DeleteOTP(ctx, normalizedEmail)
		return domainotp.ErrTooManyAttempt
	}

	if !verifyOTP(normalizedEmail, cleanCode, hashed, s.Config.Secret) {
		if s.Config.MaxAttempts > 0 && attempts >= s.Config.MaxAttempts {
			_ = s.Repo.DeleteOTP(ctx, normalizedEmail)
			return domainotp.ErrTooManyAttempt
		}
		return domainotp.ErrInvalid
	}

	_ = s.Repo.DeleteOTP(ctx, normalizedEmail)
	_ = s.Repo.ResetAttempts(ctx, normalizedEmail)
	_ = s.Repo.ClearCooldown(ctx, normalizedEmail)
	_ = s.Repo.ClearSendCount(ctx, normalizedEmail)
	return nil
}
