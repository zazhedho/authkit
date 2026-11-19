package otp

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestCountersStartTheirWindowAtomically(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewRepository(client)
	ctx := context.Background()
	email := "jane@example.com"

	if n, err := repo.IncrementAttempts(ctx, email, time.Minute); err != nil || n != 1 {
		t.Fatalf("attempts: n=%d err=%v", n, err)
	}
	if got := mr.TTL(otpAttemptKeyPrefix + email); got != time.Minute {
		t.Fatalf("attempt TTL = %v, want 1m", got)
	}
	if n, _ := repo.IncrementAttempts(ctx, email, time.Minute); n != 2 {
		t.Fatalf("second attempt count = %d", n)
	}
	count, retryAfter, err := repo.IncrementSendCount(ctx, email, time.Minute)
	if err != nil || count != 1 || retryAfter <= 0 {
		t.Fatalf("send count: count=%d retry=%v err=%v", count, retryAfter, err)
	}
}
