package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newLimiterRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func TestNewRedisLoginLimiterReturnsNilForInvalidConfig(t *testing.T) {
	if got := NewRedisLoginLimiter(nil, 5, time.Minute, time.Minute); got != nil {
		t.Fatalf("expected nil limiter for nil client, got %#v", got)
	}
	if got := NewRedisLoginLimiter(nil, 0, time.Minute, time.Minute); got != nil {
		t.Fatalf("expected nil limiter for zero limit, got %#v", got)
	}
}

func TestRedisLoginLimiterKeyBuilders(t *testing.T) {
	limiter := &redisLoginLimiter{}
	if got := limiter.attemptKey("jane@example.com"); got != "login_attempts:jane@example.com" {
		t.Fatalf("unexpected attempt key: %q", got)
	}
	if got := limiter.blockKey("jane@example.com"); got != "login_block:jane@example.com" {
		t.Fatalf("unexpected block key: %q", got)
	}
}

func TestRedisLoginLimiterBlocksAtTheLimitAndResets(t *testing.T) {
	mr, client := newLimiterRedis(t)
	limiter := NewRedisLoginLimiter(client, 3, time.Minute, 5*time.Minute)
	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		blocked, ttl, err := limiter.RegisterFailure(ctx, "client-1")
		if err != nil || blocked || ttl <= 0 || ttl > time.Minute {
			t.Fatalf("failure %d: blocked=%v ttl=%v err=%v", i, blocked, ttl, err)
		}
	}
	// The window was started together with the first count.
	if got := mr.TTL("login_attempts:client-1"); got <= 0 || got > time.Minute {
		t.Fatalf("attempt TTL = %v", got)
	}
	blocked, ttl, err := limiter.RegisterFailure(ctx, "client-1")
	if err != nil || !blocked || ttl != 5*time.Minute {
		t.Fatalf("limit failure: blocked=%v ttl=%v err=%v", blocked, ttl, err)
	}
	if mr.Exists("login_attempts:client-1") {
		t.Fatal("the attempt counter must be cleared once blocked")
	}
	if isBlocked, ttl, err := limiter.IsBlocked(ctx, "client-1"); err != nil || !isBlocked || ttl <= 0 {
		t.Fatalf("IsBlocked: %v %v %v", isBlocked, ttl, err)
	}
	if err := limiter.Reset(ctx, "client-1"); err != nil {
		t.Fatal(err)
	}
	if isBlocked, _, err := limiter.IsBlocked(ctx, "client-1"); err != nil || isBlocked {
		t.Fatalf("after reset: blocked=%v err=%v", isBlocked, err)
	}
}

func TestRedisLoginLimiterWindowExpires(t *testing.T) {
	mr, client := newLimiterRedis(t)
	limiter := NewRedisLoginLimiter(client, 3, time.Minute, 5*time.Minute)
	ctx := context.Background()
	_, _, _ = limiter.RegisterFailure(ctx, "k")
	_, _, _ = limiter.RegisterFailure(ctx, "k")
	mr.FastForward(2 * time.Minute)
	if blocked, _, err := limiter.RegisterFailure(ctx, "k"); err != nil || blocked {
		t.Fatalf("a failure after the window must start a new count: blocked=%v err=%v", blocked, err)
	}
}

func TestRedisLoginLimiterNilReceiverAndRedisErrors(t *testing.T) {
	ctx := context.Background()
	var nilLimiter *redisLoginLimiter
	if blocked, ttl, err := nilLimiter.IsBlocked(ctx, "client-1"); err != nil || blocked || ttl != 0 {
		t.Fatalf("nil is blocked: blocked=%v ttl=%v err=%v", blocked, ttl, err)
	}
	if blocked, ttl, err := nilLimiter.RegisterFailure(ctx, "client-1"); err != nil || blocked || ttl != 0 {
		t.Fatalf("nil register failure: blocked=%v ttl=%v err=%v", blocked, ttl, err)
	}
	if err := nilLimiter.Reset(ctx, "client-1"); err != nil {
		t.Fatalf("nil reset: %v", err)
	}

	mr, client := newLimiterRedis(t)
	limiter := NewRedisLoginLimiter(client, 2, time.Minute, 5*time.Minute)
	mr.Close()
	if _, _, err := limiter.IsBlocked(ctx, "c"); err == nil {
		t.Error("IsBlocked: expected an error with Redis down")
	}
	if _, _, err := limiter.RegisterFailure(ctx, "c"); err == nil {
		t.Error("RegisterFailure: expected an error with Redis down")
	}
	if err := limiter.Reset(ctx, "c"); err == nil {
		t.Error("Reset: expected an error with Redis down")
	}
}
