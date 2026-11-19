package shared

import (
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"
)

var (
	errMissing = errors.New("missing")
	errDup     = errors.New("dup")
)

func TestGormTranslatesAndKeepsBothErrors(t *testing.T) {
	got := Gorm(gorm.ErrRecordNotFound, errMissing, errDup)
	if !errors.Is(got, errMissing) || !errors.Is(got, gorm.ErrRecordNotFound) {
		t.Fatalf("expected domain and gorm errors in chain, got %v", got)
	}
	if got.Error() != gorm.ErrRecordNotFound.Error() {
		t.Fatalf("expected original text, got %q", got.Error())
	}

	got = Gorm(gorm.ErrDuplicatedKey, errMissing, errDup)
	if !errors.Is(got, errDup) || !errors.Is(got, gorm.ErrDuplicatedKey) || errors.Is(got, errMissing) {
		t.Fatalf("unexpected duplicate chain: %v", got)
	}
}

func TestGormPassesThroughOtherErrors(t *testing.T) {
	other := errors.New("boom")
	if Gorm(nil, errMissing, errDup) != nil {
		t.Fatal("nil must stay nil")
	}
	if !errors.Is(Gorm(other, errMissing, errDup), other) || errors.Is(Gorm(other, errMissing, errDup), errMissing) {
		t.Fatal("unrelated errors must be returned unchanged")
	}
	if got := Gorm(gorm.ErrRecordNotFound, nil, nil); !errors.Is(got, gorm.ErrRecordNotFound) || errors.Is(got, errMissing) {
		t.Fatalf("nil domain error must leave the driver error, got %v", got)
	}
}

func TestRedisTranslatesNil(t *testing.T) {
	got := Redis(redis.Nil, errMissing)
	if !errors.Is(got, errMissing) || !errors.Is(got, redis.Nil) {
		t.Fatalf("expected both errors in chain, got %v", got)
	}
	other := errors.New("boom")
	if !errors.Is(Redis(other, errMissing), other) || Redis(nil, errMissing) != nil {
		t.Fatal("other errors and nil must pass through")
	}
}

func TestRedisMsgKeepsCallerMessage(t *testing.T) {
	got := RedisMsg(redis.Nil, errMissing, "thing not found")
	if got.Error() != "thing not found" || !errors.Is(got, errMissing) || !errors.Is(got, redis.Nil) {
		t.Fatalf("unexpected error %v", got)
	}
	other := errors.New("boom")
	if !errors.Is(RedisMsg(other, errMissing, "x"), other) {
		t.Fatal("other errors must pass through")
	}
}

func TestGormMapsGokitNotFoundFromWrites(t *testing.T) {
	got := Gorm(gokit.ErrNotFound, errMissing, errDup)
	if !errors.Is(got, errMissing) || !errors.Is(got, gokit.ErrNotFound) {
		t.Fatalf("a write that matched no row must map to the domain error, got %v", got)
	}
}
