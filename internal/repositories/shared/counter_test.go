package shared

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newCounterRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func TestIncrementWithTTLStartsTheWindowOnTheFirstHit(t *testing.T) {
	mr, client := newCounterRedis(t)
	count, retryAfter, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute)
	if err != nil || count != 1 || retryAfter != time.Minute {
		t.Fatalf("count=%d retryAfter=%v err=%v", count, retryAfter, err)
	}
	if got := mr.TTL("rate:a"); got != time.Minute {
		t.Fatalf("TTL = %v, want 1m set together with the increment", got)
	}
}

func TestIncrementWithTTLKeepsTheWindowOnLaterHits(t *testing.T) {
	mr, client := newCounterRedis(t)
	ctx := context.Background()
	_, _, _ = IncrementWithTTL(ctx, client, "rate:a", time.Minute)
	mr.FastForward(20 * time.Second)
	count, retryAfter, err := IncrementWithTTL(ctx, client, "rate:a", time.Minute)
	if err != nil || count != 2 || retryAfter != 40*time.Second {
		t.Fatalf("count=%d retryAfter=%v err=%v", count, retryAfter, err)
	}
}

func TestIncrementWithTTLGivesAnExpiryToACounterThatLostIt(t *testing.T) {
	mr, client := newCounterRedis(t)
	if err := client.Set(context.Background(), "rate:a", 4, 0).Err(); err != nil {
		t.Fatal(err)
	}
	count, _, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute)
	if err != nil || count != 5 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if mr.TTL("rate:a") != time.Minute {
		t.Fatalf("a counter without expiry was left immortal: %v", mr.TTL("rate:a"))
	}
}

func TestIncrementWithTTLWithoutAWindowSetsNoExpiry(t *testing.T) {
	mr, client := newCounterRedis(t)
	if _, _, err := IncrementWithTTL(context.Background(), client, "rate:a", 0); err != nil {
		t.Fatal(err)
	}
	if mr.TTL("rate:a") != 0 {
		t.Fatal("no expiry expected")
	}
}

func TestIncrementWithTTLReturnsRedisErrors(t *testing.T) {
	mr, client := newCounterRedis(t)
	mr.Close()
	if _, _, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute); err == nil {
		t.Fatal("expected an error with Redis down")
	}
}
