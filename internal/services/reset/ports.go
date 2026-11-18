package reset

import (
	"context"
	"time"
)

type Repository interface {
	SetToken(ctx context.Context, hash, email string, ttl time.Duration) error
	GetEmailByToken(ctx context.Context, hash string) (string, error)
	DeleteToken(ctx context.Context, hash string) error
	SetCooldown(ctx context.Context, email string, ttl time.Duration) error
	GetCooldownTTL(ctx context.Context, email string) (time.Duration, error)
	ClearCooldown(ctx context.Context, email string) error
	IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error)
	ClearSendCount(ctx context.Context, email string) error
}

// Mailer delivers the password reset link. ttl is how long the token stays valid.
type Mailer interface {
	SendPasswordReset(to, token, appName, resetURL string, ttl time.Duration) error
}
