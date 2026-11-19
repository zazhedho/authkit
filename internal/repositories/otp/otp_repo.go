package otp

import (
	"context"
	"fmt"
	"time"

	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

type Repository struct {
	Redis *redis.Client
}

func NewRepository(redisClient *redis.Client) *Repository {
	return &Repository{Redis: redisClient}
}

const (
	otpRegisterKeyPrefix = "otp:register:"
	otpAttemptKeyPrefix  = "otp:attempt:"
	otpCooldownKeyPrefix = "otp:cooldown:"
	otpRateKeyPrefix     = "otp:rate:"
)

func (r *Repository) SetOTP(ctx context.Context, email, hashed string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email), hashed, ttl).Err()
}

func (r *Repository) GetOTP(ctx context.Context, email string) (string, error) {
	value, err := r.Redis.Get(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email)).Result()
	return value, repositoryshared.Redis(err, domainotp.ErrNotFound)
}

func (r *Repository) DeleteOTP(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email)).Err()
}

func (r *Repository) IncrementAttempts(ctx context.Context, email string, ttl time.Duration) (int, error) {
	count, _, err := repositoryshared.IncrementWithTTL(ctx, r.Redis, fmt.Sprintf("%s%s", otpAttemptKeyPrefix, email), ttl)
	return count, err
}

func (r *Repository) ResetAttempts(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpAttemptKeyPrefix, email)).Err()
}

func (r *Repository) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email), "1", ttl).Err()
}

func (r *Repository) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	return r.Redis.TTL(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email)).Result()
}

func (r *Repository) ClearCooldown(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email)).Err()
}

func (r *Repository) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	return repositoryshared.IncrementWithTTL(ctx, r.Redis, fmt.Sprintf("%s%s", otpRateKeyPrefix, email), ttl)
}

func (r *Repository) ClearSendCount(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpRateKeyPrefix, email)).Err()
}
