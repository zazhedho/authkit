package reset

import (
	"context"
	"fmt"
	"time"

	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

// Repository stores reset data.
type Repository struct {
	Redis *redis.Client
}

// NewRepository creates the reset repository on Redis.
func NewRepository(redisClient *redis.Client) *Repository {
	return &Repository{Redis: redisClient}
}

const (
	resetTokenKeyPrefix    = "reset:token:"
	resetCooldownKeyPrefix = "reset:cooldown:"
	resetRateKeyPrefix     = "reset:rate:"
)

// SetToken sets the token.
func (r *Repository) SetToken(ctx context.Context, hash, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash), email, ttl).Err()
}

// GetEmailByToken returns the email by token.
func (r *Repository) GetEmailByToken(ctx context.Context, hash string) (string, error) {
	value, err := r.Redis.Get(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash)).Result()
	return value, repositoryshared.Redis(err, domainreset.ErrNotFound)
}

// DeleteToken deletes the token.
func (r *Repository) DeleteToken(ctx context.Context, hash string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash)).Err()
}

// SetCooldown sets the cooldown.
func (r *Repository) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email), "1", ttl).Err()
}

// GetCooldownTTL returns the cooldown TTL.
func (r *Repository) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	return r.Redis.TTL(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email)).Result()
}

// ClearCooldown clears the cooldown.
func (r *Repository) ClearCooldown(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email)).Err()
}

// IncrementSendCount increments the send count.
func (r *Repository) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	return repositoryshared.IncrementWithTTL(ctx, r.Redis, fmt.Sprintf("%s%s", resetRateKeyPrefix, email), ttl)
}

// ClearSendCount clears the send count.
func (r *Repository) ClearSendCount(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetRateKeyPrefix, email)).Err()
}
