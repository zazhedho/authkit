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
	client        redis.UniversalClient
	limit         int
	window        time.Duration
	blockDuration time.Duration
	// backoff delays past the limit exponentially instead of blocking at it.
	backoff bool
}

// NewRedisLoginLimiter returns a Redis-backed LoginLimiter, or nil when client
// is nil or limit, window or blockDuration is not positive.
func NewRedisLoginLimiter(client redis.UniversalClient, limit int, window, blockDuration time.Duration) LoginLimiter {
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

// NewRedisBackoffLimiter returns a LoginLimiter that never blocks within limit
// failures per window and then delays each further failure by twice the last
// (1s, 2s, 4s, ...) up to maxDelay. A few requests cannot lock a key out, so it
// suits a key an attacker can name, such as a victim's identifier. It returns
// nil under the same conditions as NewRedisLoginLimiter.
func NewRedisBackoffLimiter(client redis.UniversalClient, limit int, window, maxDelay time.Duration) LoginLimiter {
	l, ok := NewRedisLoginLimiter(client, limit, window, maxDelay).(*redisLoginLimiter)
	if !ok {
		return nil
	}
	l.backoff = true
	return l
}

// The {key} hash tag keeps both keys of the Lua script in one Redis Cluster slot.
func (l *redisLoginLimiter) attemptKey(key string) string {
	return fmt.Sprintf("login_attempts:{%s}", key)
}

func (l *redisLoginLimiter) blockKey(key string) string {
	return fmt.Sprintf("login_block:{%s}", key)
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

// backoffScript counts a failure and, past the limit, blocks the key for
// 1s << (count-limit-1), capped at ARGV[2]; the counter is kept so the delay
// keeps growing until the window ends.
var backoffScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local over = count - tonumber(ARGV[3])
if over > 0 then
  if over > 20 then over = 20 end
  local delay = 1000 * (2 ^ (over - 1))
  if delay > tonumber(ARGV[2]) then delay = tonumber(ARGV[2]) end
  redis.call('SET', KEYS[2], '1', 'PX', math.floor(delay))
  return {1, math.floor(delay)}
end
return {0, redis.call('PTTL', KEYS[1])}
`)

func (l *redisLoginLimiter) RegisterFailure(ctx context.Context, key string) (bool, time.Duration, error) {
	if l == nil || l.client == nil {
		return false, 0, nil
	}
	script := failureScript
	if l.backoff {
		script = backoffScript
	}
	res, err := script.Run(ctx, l.client, []string{l.attemptKey(key), l.blockKey(key)},
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
