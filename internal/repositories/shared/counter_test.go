package shared

import (
	"context"
	"errors"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"
)

func TestIncrementWithTTLStartsTheWindowOnTheFirstHit(t *testing.T) {
	client, mock := redismock.NewClientMock()
	mock.ExpectIncr("rate:a").SetVal(1)
	mock.ExpectExpire("rate:a", time.Minute).SetVal(true)
	mock.ExpectTTL("rate:a").SetVal(50 * time.Second)

	count, retryAfter, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute)
	if err != nil || count != 1 || retryAfter != 50*time.Second {
		t.Fatalf("unexpected result count=%d retryAfter=%v err=%v", count, retryAfter, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementWithTTLKeepsTheWindowOnLaterHits(t *testing.T) {
	client, mock := redismock.NewClientMock()
	mock.ExpectIncr("rate:a").SetVal(3)
	mock.ExpectTTL("rate:a").SetVal(10 * time.Second)

	count, retryAfter, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute)
	if err != nil || count != 3 || retryAfter != 10*time.Second {
		t.Fatalf("unexpected result count=%d retryAfter=%v err=%v", count, retryAfter, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementWithTTLSkipsExpireWithoutATTL(t *testing.T) {
	client, mock := redismock.NewClientMock()
	mock.ExpectIncr("rate:a").SetVal(1)
	mock.ExpectTTL("rate:a").SetVal(-1)

	if _, _, err := IncrementWithTTL(context.Background(), client, "rate:a", 0); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementWithTTLReturnsTheIncrementError(t *testing.T) {
	client, mock := redismock.NewClientMock()
	boom := errors.New("redis down")
	mock.ExpectIncr("rate:a").SetErr(boom)

	count, retryAfter, err := IncrementWithTTL(context.Background(), client, "rate:a", time.Minute)
	if !errors.Is(err, boom) || count != 0 || retryAfter != 0 {
		t.Fatalf("unexpected result count=%d retryAfter=%v err=%v", count, retryAfter, err)
	}
}
