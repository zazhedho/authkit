package ratelimit

import (
	"context"
	"strings"
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
	if got := limiter.attemptKey("jane@example.com"); got != "login_attempts:{jane@example.com}" {
		t.Fatalf("unexpected attempt key: %q", got)
	}
	if got := limiter.blockKey("jane@example.com"); got != "login_block:{jane@example.com}" {
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
	if got := mr.TTL("login_attempts:{client-1}"); got <= 0 || got > time.Minute {
		t.Fatalf("attempt TTL = %v", got)
	}
	blocked, ttl, err := limiter.RegisterFailure(ctx, "client-1")
	if err != nil || !blocked || ttl != 5*time.Minute {
		t.Fatalf("limit failure: blocked=%v ttl=%v err=%v", blocked, ttl, err)
	}
	if mr.Exists("login_attempts:{client-1}") {
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

// hashTag is the part of a key Redis Cluster hashes: the first non-empty {...}.
func hashTag(key string) string {
	open := strings.IndexByte(key, '{')
	if open < 0 {
		return key
	}
	end := strings.IndexByte(key[open+1:], '}')
	if end <= 0 {
		return key
	}
	return key[open+1 : open+1+end]
}

func TestLimiterKeysShareAClusterSlot(t *testing.T) {
	for _, l := range []*redisLoginLimiter{{}, {backoff: true}} {
		for _, key := range []string{"1.2.3.4:jane@example.com", "identifier:jane@example.com", "change_password:u1"} {
			if hashTag(l.attemptKey(key)) != hashTag(l.blockKey(key)) || hashTag(l.attemptKey(key)) == l.attemptKey(key) {
				t.Fatalf("keys for %q would land in different slots: %q %q", key, l.attemptKey(key), l.blockKey(key))
			}
		}
	}
}

func TestBackoffLimiterDoesNotLockOutAfterTheLimit(t *testing.T) {
	_, client := newLimiterRedis(t)
	limiter := NewRedisBackoffLimiter(client, 5, time.Minute, 5*time.Minute)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		blocked, _, err := limiter.RegisterFailure(ctx, "victim")
		if err != nil || blocked {
			t.Fatalf("failure %d within the limit must not block: blocked=%v err=%v", i, blocked, err)
		}
	}
	if isBlocked, _, _ := limiter.IsBlocked(ctx, "victim"); isBlocked {
		t.Fatal("five failures must not lock an identifier out")
	}
}

func TestBackoffLimiterDelaysGrowExponentiallyUpToTheCap(t *testing.T) {
	mr, client := newLimiterRedis(t)
	limiter := NewRedisBackoffLimiter(client, 2, time.Hour, 10*time.Second)
	ctx := context.Background()
	var delays []time.Duration
	for range 8 {
		_, _, _ = limiter.RegisterFailure(ctx, "k")
		if i := len(delays); i < 2 {
			delays = append(delays, 0)
			continue
		}
		blocked, ttl, err := limiter.IsBlocked(ctx, "k")
		if err != nil || !blocked {
			t.Fatalf("failure past the limit must delay: blocked=%v err=%v", blocked, err)
		}
		delays = append(delays, ttl.Round(time.Second))
		mr.FastForward(ttl + time.Millisecond) // wait the delay out, keep the counter
	}
	want := []time.Duration{0, 0, 1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("delays = %v, want %v", delays, want)
		}
	}
}
