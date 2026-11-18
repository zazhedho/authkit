package shared

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// IncrementWithTTL bumps a rate counter. The first increment starts the ttl
// window; the returned duration is what is left of it.
func IncrementWithTTL(ctx context.Context, client *redis.Client, key string, ttl time.Duration) (int, time.Duration, error) {
	count, err := client.Incr(ctx, key).Result()
	if err != nil {
		return 0, 0, err
	}
	if count == 1 && ttl > 0 {
		_ = client.Expire(ctx, key, ttl).Err()
	}
	retryAfter, _ := client.TTL(ctx, key).Result()
	return int(count), retryAfter, nil
}
