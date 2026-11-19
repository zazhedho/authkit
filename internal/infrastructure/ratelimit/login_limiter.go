package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// LoginLimiter throttles login attempts per key; IsBlocked and RegisterFailure
// report whether and for how long it is blocked, Reset clears it.
type LoginLimiter interface {
	IsBlocked(ctx context.Context, key string) (bool, time.Duration, error)
	RegisterFailure(ctx context.Context, key string) (bool, time.Duration, error)
	Reset(ctx context.Context, key string) error
}

type redisLoginLimiter struct {
	client        *redis.Client
	limit         int
	window        time.Duration
	blockDuration time.Duration
}

// NewRedisLoginLimiter returns a Redis-backed LoginLimiter, or nil when client
// is nil or limit, window or blockDuration is not positive.
func NewRedisLoginLimiter(client *redis.Client, limit int, window, blockDuration time.Duration) LoginLimiter {
	if client == nil || limit <= 0 || window <= 0 || blockDuration <= 0 {
		return nil
	}

	return &redisLoginLimiter{
		client:        client,
		limit:         limit,
		window:        window,
		blockDuration: blockDuration,
	}
}

func (l *redisLoginLimiter) attemptKey(key string) string {
	return fmt.Sprintf("login_attempts:%s", key)
}

func (l *redisLoginLimiter) blockKey(key string) string {
	return fmt.Sprintf("login_block:%s", key)
}

func (l *redisLoginLimiter) IsBlocked(ctx context.Context, key string) (bool, time.Duration, error) {
	if l == nil || l.client == nil {
		return false, 0, nil
	}

	ttl, err := l.client.TTL(ctx, l.blockKey(key)).Result()
	if err != nil {
		return false, 0, err
	}

	if ttl <= 0 {
		return false, 0, nil
	}

	return true, ttl, nil
}

// failureScript counts a failure, starts the window on the first one and blocks
// the key at the limit, all in one step.
var failureScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if count >= tonumber(ARGV[3]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[2])
  redis.call('DEL', KEYS[1])
  return {1, tonumber(ARGV[2])}
end
return {0, redis.call('PTTL', KEYS[1])}
`)

func (l *redisLoginLimiter) RegisterFailure(ctx context.Context, key string) (bool, time.Duration, error) {
	if l == nil || l.client == nil {
		return false, 0, nil
	}
	res, err := failureScript.Run(ctx, l.client, []string{l.attemptKey(key), l.blockKey(key)},
		l.window.Milliseconds(), l.blockDuration.Milliseconds(), l.limit).Int64Slice()
	if err != nil {
		return false, 0, err
	}
	if len(res) != 2 {
		return false, 0, fmt.Errorf("login limiter: unexpected reply %v", res)
	}
	ttl := time.Duration(res[1]) * time.Millisecond
	if ttl < 0 {
		ttl = 0
	}
	return res[0] == 1, ttl, nil
}

func (l *redisLoginLimiter) Reset(ctx context.Context, key string) error {
	if l == nil || l.client == nil {
		return nil
	}

	if err := l.client.Del(ctx, l.attemptKey(key)).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if err := l.client.Del(ctx, l.blockKey(key)).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	return nil
}
