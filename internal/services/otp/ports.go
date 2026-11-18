package otp

import (
	"context"
	"time"
)

// Repository is the Redis-backed state the service needs.
type Repository interface {
	SetOTP(ctx context.Context, email, hashed string, ttl time.Duration) error
	GetOTP(ctx context.Context, email string) (string, error)
	DeleteOTP(ctx context.Context, email string) error
	IncrementAttempts(ctx context.Context, email string, ttl time.Duration) (int, error)
	ResetAttempts(ctx context.Context, email string) error
	SetCooldown(ctx context.Context, email string, ttl time.Duration) error
	GetCooldownTTL(ctx context.Context, email string) (time.Duration, error)
	ClearCooldown(ctx context.Context, email string) error
	IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error)
	ClearSendCount(ctx context.Context, email string) error
}

// Mailer delivers the registration code. ttl is how long the code stays valid.
type Mailer interface {
	SendOTP(to, code, appName string, ttl time.Duration) error
}
