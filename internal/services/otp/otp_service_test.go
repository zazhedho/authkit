package otp

import (
	"context"
	"errors"
	"github.com/zazhedho/authkit/internal/config"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type otpRepoTestDouble struct {
	otp                 map[string]string
	attempts            map[string]int
	cooldownTTL         time.Duration
	sendCount           int
	sendRetryAfter      time.Duration
	deletedEmail        string
	resetEmail          string
	clearedCooldown     string
	clearedSend         string
	getCooldownErr      error
	incrementSendErr    error
	setOTPErr           error
	getOTPErr           error
	incrementAttemptErr error
	setCooldownErr      error
}

func newOTPRepoTestDouble() *otpRepoTestDouble {
	return &otpRepoTestDouble{
		otp:      map[string]string{},
		attempts: map[string]int{},
	}
}

func (m *otpRepoTestDouble) SetOTP(ctx context.Context, email, hashed string, ttl time.Duration) error {
	if m.setOTPErr != nil {
		return m.setOTPErr
	}
	m.otp[email] = hashed
	return nil
}
func (m *otpRepoTestDouble) GetOTP(ctx context.Context, email string) (string, error) {
	if m.getOTPErr != nil {
		return "", m.getOTPErr
	}
	hashed, ok := m.otp[email]
	if !ok {
		return "", redis.Nil
	}
	return hashed, nil
}
func (m *otpRepoTestDouble) DeleteOTP(ctx context.Context, email string) error {
	m.deletedEmail = email
	delete(m.otp, email)
	return nil
}
func (m *otpRepoTestDouble) IncrementAttempts(ctx context.Context, email string, ttl time.Duration) (int, error) {
	if m.incrementAttemptErr != nil {
		return 0, m.incrementAttemptErr
	}
	m.attempts[email]++
	return m.attempts[email], nil
}
func (m *otpRepoTestDouble) ResetAttempts(ctx context.Context, email string) error {
	m.resetEmail = email
	delete(m.attempts, email)
	return nil
}
func (m *otpRepoTestDouble) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return m.setCooldownErr
}
func (m *otpRepoTestDouble) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	if m.getCooldownErr != nil {
		return 0, m.getCooldownErr
	}
	return m.cooldownTTL, nil
}
func (m *otpRepoTestDouble) ClearCooldown(ctx context.Context, email string) error {
	m.clearedCooldown = email
	return nil
}
func (m *otpRepoTestDouble) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	if m.incrementSendErr != nil {
		return 0, 0, m.incrementSendErr
	}
	m.sendCount++
	return m.sendCount, m.sendRetryAfter, nil
}
func (m *otpRepoTestDouble) ClearSendCount(ctx context.Context, email string) error {
	m.clearedSend = email
	return nil
}

type otpSenderTestDouble struct {
	to      string
	code    string
	appName string
	ttl     time.Duration
	err     error
}

func (m *otpSenderTestDouble) SendOTP(to, code, appName string, ttl time.Duration) error {
	m.ttl = ttl
	m.to = to
	m.code = code
	m.appName = appName
	return m.err
}

func otpTestConfig() config.OTPConfig {
	return config.OTPConfig{
		TTL:         5 * time.Minute,
		MaxAttempts: 2,
		RateLimit:   2,
		RateWindow:  time.Minute,
		Cooldown:    time.Minute,
		Secret:      "secret",
	}
}

func TestSendRegisterOTPStoresHashedOTPAndSendsNormalizedEmail(t *testing.T) {
	repo := newOTPRepoTestDouble()
	sender := &otpSenderTestDouble{}
	svc := NewService(repo, sender, otpTestConfig())

	if err := svc.SendRegisterOTP(context.Background(), " Jane.Doe@Example.COM ", "Starter"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if sender.to != "jane.doe@example.com" || sender.appName != "Starter" {
		t.Fatalf("unexpected sender call: %+v", sender)
	}
	if sender.ttl != 5*time.Minute {
		t.Fatalf("sender got ttl %v, want the configured 5m", sender.ttl)
	}
	if len(sender.code) != 6 {
		t.Fatalf("expected six digit code, got %q", sender.code)
	}
	if repo.otp["jane.doe@example.com"] == "" || repo.otp["jane.doe@example.com"] == sender.code {
		t.Fatalf("expected hashed otp to be stored, got %q", repo.otp["jane.doe@example.com"])
	}
}

func TestSendRegisterOTPReturnsThrottleOnCooldown(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.cooldownTTL = 30 * time.Second
	svc := NewService(repo, &otpSenderTestDouble{}, otpTestConfig())

	err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	throttle, ok := errors.AsType[*ThrottleError](err)
	if !ok {
		t.Fatalf("expected throttle error, got %v", err)
	}
	if throttle.Reason != "cooldown" || throttle.RetryAfter != 30*time.Second {
		t.Fatalf("unexpected throttle error: %+v", throttle)
	}
}

func TestSendRegisterOTPCleansUpWhenDeliveryFails(t *testing.T) {
	repo := newOTPRepoTestDouble()
	svc := NewService(repo, &otpSenderTestDouble{err: errors.New("smtp down")}, otpTestConfig())

	err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	if !errors.Is(err, ErrOTPDeliveryFailed) {
		t.Fatalf("expected delivery failed error, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" || repo.clearedCooldown != "jane@example.com" || repo.clearedSend != "jane@example.com" {
		t.Fatalf("expected cleanup for failed delivery, got %+v", repo)
	}
}

func TestVerifyRegisterOTPSucceedsAndClearsState(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.otp["jane@example.com"] = hashOTP("123456", "secret")
	svc := NewService(repo, nil, otpTestConfig())

	if err := svc.VerifyRegisterOTP(context.Background(), " Jane@Example.COM ", " 123456 "); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" || repo.resetEmail != "jane@example.com" || repo.clearedSend != "jane@example.com" {
		t.Fatalf("expected otp state cleared, got %+v", repo)
	}
}

func TestVerifyRegisterOTPDeletesAfterTooManyAttempts(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.otp["jane@example.com"] = hashOTP("123456", "secret")
	repo.attempts["jane@example.com"] = 2
	svc := NewService(repo, nil, otpTestConfig())

	err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "000000")
	if !errors.Is(err, ErrOTPTooManyAttempt) {
		t.Fatalf("expected too many attempts, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" {
		t.Fatalf("expected otp deleted, got %+v", repo)
	}
}

func TestOTPServiceNotConfigured(t *testing.T) {
	err := NewService(nil, nil, otpTestConfig()).SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	if !errors.Is(err, ErrOTPNotConfigured) {
		t.Fatalf("expected not configured error, got %v", err)
	}
}

func TestSendRegisterOTPRejectsInvalidEmail(t *testing.T) {
	svc := NewService(newOTPRepoTestDouble(), &otpSenderTestDouble{}, otpTestConfig())
	err := svc.SendRegisterOTP(context.Background(), "   ", "Starter")
	if !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("expected invalid otp error, got %v", err)
	}
}

func TestSendRegisterOTPRepositoryErrors(t *testing.T) {
	tests := map[string]*otpRepoTestDouble{
		"cooldown":     {getCooldownErr: errors.New("redis down")},
		"rate limit":   {incrementSendErr: errors.New("redis down")},
		"store otp":    {setOTPErr: errors.New("redis down")},
		"set cooldown": {setCooldownErr: errors.New("redis down")},
	}

	for name, repo := range tests {
		t.Run(name, func(t *testing.T) {
			if repo.otp == nil {
				repo.otp = map[string]string{}
			}
			if repo.attempts == nil {
				repo.attempts = map[string]int{}
			}
			svc := NewService(repo, &otpSenderTestDouble{}, otpTestConfig())
			if err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter"); err == nil {
				t.Fatal("expected repository error")
			}
		})
	}
}

func TestSendRegisterOTPReturnsThrottleOnRateLimit(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.sendCount = 2
	repo.sendRetryAfter = 20 * time.Second
	svc := NewService(repo, &otpSenderTestDouble{}, otpTestConfig())

	err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	throttle, ok := errors.AsType[*ThrottleError](err)
	if !ok {
		t.Fatalf("expected throttle error, got %v", err)
	}
	if throttle.Reason != "rate_limit" || throttle.RetryAfter != 20*time.Second {
		t.Fatalf("unexpected throttle error: %+v", throttle)
	}
}

func TestVerifyRegisterOTPErrorBranches(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		err := NewService(nil, nil, otpTestConfig()).VerifyRegisterOTP(context.Background(), "jane@example.com", "123456")
		if !errors.Is(err, ErrOTPNotConfigured) {
			t.Fatalf("expected not configured, got %v", err)
		}
	})
	t.Run("invalid input", func(t *testing.T) {
		svc := NewService(newOTPRepoTestDouble(), nil, otpTestConfig())
		if err := svc.VerifyRegisterOTP(context.Background(), "", ""); !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("expected invalid otp, got %v", err)
		}
	})
	t.Run("missing otp", func(t *testing.T) {
		svc := NewService(newOTPRepoTestDouble(), nil, otpTestConfig())
		if err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "123456"); !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("expected invalid otp, got %v", err)
		}
	})
	t.Run("get otp error", func(t *testing.T) {
		repo := newOTPRepoTestDouble()
		repo.getOTPErr = errors.New("redis down")
		svc := NewService(repo, nil, otpTestConfig())
		if err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "123456"); err == nil {
			t.Fatal("expected get otp error")
		}
	})
	t.Run("increment attempts error", func(t *testing.T) {
		repo := newOTPRepoTestDouble()
		repo.otp["jane@example.com"] = hashOTP("123456", "secret")
		repo.incrementAttemptErr = errors.New("redis down")
		svc := NewService(repo, nil, otpTestConfig())
		if err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "123456"); err == nil {
			t.Fatal("expected increment attempts error")
		}
	})
	t.Run("wrong code before max attempts", func(t *testing.T) {
		repo := newOTPRepoTestDouble()
		repo.otp["jane@example.com"] = hashOTP("123456", "secret")
		svc := NewService(repo, nil, otpTestConfig())
		if err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "000000"); !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("expected invalid otp, got %v", err)
		}
	})
}

func TestThrottleErrorString(t *testing.T) {
	var nilErr *ThrottleError
	if got := nilErr.Error(); got != "otp throttled" {
		t.Fatalf("expected nil throttle message, got %q", got)
	}

	err := &ThrottleError{Reason: "cooldown"}
	if got := err.Error(); got != "otp throttled: cooldown" {
		t.Fatalf("expected cooldown throttle message, got %q", got)
	}
}

// untouchableOTPRepo panics on any repository call, so a test fails loudly if
// the service reaches the repo.
type untouchableOTPRepo struct{ Repository }

func callWithoutRepoAccess(t *testing.T, call func() error) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("service touched the repository with an empty secret: %v", r)
		}
	}()
	return call()
}

func TestOTPServiceRefusesEmptySecretBeforeTouchingRepo(t *testing.T) {
	for _, secret := range []string{"", "   "} {
		cfg := otpTestConfig()
		cfg.Secret = secret
		svc := NewService(untouchableOTPRepo{}, &otpSenderTestDouble{}, cfg)

		err := callWithoutRepoAccess(t, func() error {
			return svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
		})
		if !errors.Is(err, ErrOTPNotConfigured) {
			t.Fatalf("SendRegisterOTP with secret %q: expected not configured, got %v", secret, err)
		}

		err = callWithoutRepoAccess(t, func() error {
			return svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "123456")
		})
		if !errors.Is(err, ErrOTPNotConfigured) {
			t.Fatalf("VerifyRegisterOTP with secret %q: expected not configured, got %v", secret, err)
		}
	}
}
