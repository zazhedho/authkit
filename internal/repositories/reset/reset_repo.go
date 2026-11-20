package reset

import (
	"context"
	"fmt"
	"time"

	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

type Repository struct {
	Redis redis.UniversalClient
}

func NewRepository(redisClient redis.UniversalClient) *Repository {
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

// ConsumeToken reads and deletes the token in one step (GETDEL), so two requests
// presenting the same token cannot both succeed.
func (r *Repository) ConsumeToken(ctx context.Context, hash string) (string, error) {
	value, err := r.Redis.GetDel(ctx, fmt.Sprintf("%s%s", resetTokenKeyPrefix, hash)).Result()
	return value, repositoryshared.Redis(err, domainreset.ErrNotFound)
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
	return repositoryshared.IncrementWithTTL(ctx, r.Redis, fmt.Sprintf("%s%s", resetRateKeyPrefix, email), ttl)
}

func (r *Repository) ClearSendCount(ctx context.Context, email string) error {
	return r.Redis.Del(ctx, fmt.Sprintf("%s%s", resetRateKeyPrefix, email)).Err()
}
