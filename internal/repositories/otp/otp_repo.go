package otp

import (
	"context"
	"fmt"
	"time"

	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

// Repository stores otp data.
type Repository struct {
	Redis *redis.Client
}

// NewRepository creates the otp repository on Redis.
func NewRepository(redisClient *redis.Client) *Repository {
	return &Repository{Redis: redisClient}
}

const (
	otpRegisterKeyPrefix = "otp:register:"
	otpAttemptKeyPrefix  = "otp:attempt:"
	otpCooldownKeyPrefix = "otp:cooldown:"
	otpRateKeyPrefix     = "otp:rate:"
)

// SetOTP sets the OTP.
func (r *Repository) SetOTP(ctx context.Context, email, hashed string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email), hashed, ttl).Err()
}

// GetOTP returns the OTP.
func (r *Repository) GetOTP(ctx context.Context, email string) (string, error) {
	value, err := r.Redis.Get(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email)).Result()
	return value, repositoryshared.Redis(err, domainotp.ErrNotFound)
}

// DeleteOTP deletes the OTP.
func (r *Repository) DeleteOTP(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpRegisterKeyPrefix, email)).Err()
}

// IncrementAttempts increments the attempts.
func (r *Repository) IncrementAttempts(ctx context.Context, email string, ttl time.Duration) (int, error) {
	key := fmt.Sprintf("%s%s", otpAttemptKeyPrefix, email)
	count, err := r.Redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if count == 1 && ttl > 0 {
		_ = r.Redis.Expire(ctx, key, ttl).Err()
	}
	return int(count), nil
}

// ResetAttempts resets the attempts.
func (r *Repository) ResetAttempts(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpAttemptKeyPrefix, email)).Err()
}

// SetCooldown sets the cooldown.
func (r *Repository) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email), "1", ttl).Err()
}

// GetCooldownTTL returns the cooldown TTL.
func (r *Repository) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	return r.Redis.TTL(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email)).Result()
}

// ClearCooldown clears the cooldown.
func (r *Repository) ClearCooldown(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpCooldownKeyPrefix, email)).Err()
}

// IncrementSendCount increments the send count.
func (r *Repository) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	return repositoryshared.IncrementWithTTL(ctx, r.Redis, fmt.Sprintf("%s%s", otpRateKeyPrefix, email), ttl)
}

// ClearSendCount clears the send count.
func (r *Repository) ClearSendCount(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", otpRateKeyPrefix, email)).Err()
}
