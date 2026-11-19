package reset

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSendCountStartsItsWindowAtomically(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewRepository(client)
	email := "jane@example.com"

	count, retryAfter, err := repo.IncrementSendCount(context.Background(), email, time.Minute)
	if err != nil || count != 1 || retryAfter != time.Minute {
		t.Fatalf("count=%d retry=%v err=%v", count, retryAfter, err)
	}
	if got := mr.TTL(resetRateKeyPrefix + email); got != time.Minute {
		t.Fatalf("TTL = %v, want 1m", got)
	}
}

func TestConsumeTokenIsSingleUse(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewRepository(client)
	ctx := context.Background()
	if err := repo.SetToken(ctx, "h", "jane@example.com", time.Minute); err != nil {
		t.Fatal(err)
	}
	if email, err := repo.ConsumeToken(ctx, "h"); err != nil || email != "jane@example.com" {
		t.Fatalf("first use: %q %v", email, err)
	}
	if _, err := repo.ConsumeToken(ctx, "h"); err == nil {
		t.Fatal("a token must work once")
	}
}
