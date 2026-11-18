package reset

import (
	"context"
	"fmt"
	"time"

	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	reposhared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

type Repository struct {
	Redis *redis.Client
}

func NewRepository(redisClient *redis.Client) *Repository {
	return &Repository{Redis: redisClient}
}

const (
	resetTokenKeyPrefix    = "reset:token:"
	resetCooldownKeyPrefix = "reset:cooldown:"
	resetRateKeyPrefix     = "reset:rate:"
)

func (r *Repository) SetToken(ctx context.Context, hash, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash), email, ttl).Err()
}

func (r *Repository) GetEmailByToken(ctx context.Context, hash string) (string, error) {
	value, err := r.Redis.Get(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash)).Result()
	return value, reposhared.Redis(err, domainreset.ErrNotFound)
}

func (r *Repository) DeleteToken(ctx context.Context, hash string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash)).Err()
}

func (r *Repository) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return r.Redis.Set(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email), "1", ttl).Err()
}

func (r *Repository) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	return r.Redis.TTL(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email)).Result()
}

func (r *Repository) ClearCooldown(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetCooldownKeyPrefix, email)).Err()
}

func (r *Repository) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	key := fmt.Sprintf("%s%s", resetRateKeyPrefix, email)
	count, err := r.Redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, 0, err
	}
	if count == 1 && ttl > 0 {
		_ = r.Redis.Expire(ctx, key, ttl).Err()
	}
	retryAfter, _ := r.Redis.TTL(ctx, key).Result()
	return int(count), retryAfter, nil
}

func (r *Repository) ClearSendCount(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetRateKeyPrefix, email)).Err()
}
