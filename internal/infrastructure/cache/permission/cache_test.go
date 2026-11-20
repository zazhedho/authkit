package permission

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func TestKey(t *testing.T) {
	if got := Key("user-1"); got != "permission:v2:user:user-1" {
		t.Fatalf("Key() = %q", got)
	}
}

func TestGetUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectGet("permission:v2:user:user-1").SetVal(`["users:list","users:create"]`)

	got, ok := GetUserPermissionKeys(ctx, client, "user-1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 2 || got[0] != "users:list" || got[1] != "users:create" {
		t.Fatalf("unexpected permission keys: %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetUserPermissionKeysMissOnNilClient(t *testing.T) {
	got, ok := GetUserPermissionKeys(context.Background(), nil, "user-1")
	if ok {
		t.Fatalf("expected cache miss, got %#v", got)
	}
}

func TestGetUserPermissionKeysMissOnInvalidJSON(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectGet("permission:v2:user:user-1").SetVal(`{`)

	got, ok := GetUserPermissionKeys(ctx, client, "user-1")
	if ok {
		t.Fatalf("expected cache miss, got %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectSet("permission:v2:user:user-1", `["users:list"]`, 2*time.Minute).SetVal("OK")

	SetUserPermissionKeys(ctx, client, "user-1", []string{"users:list"}, 2*time.Minute)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectDel("permission:v2:user:user-1", "authstate:v2:user:user-1", "permission:v2:user:user-2", "authstate:v2:user:user-2").SetVal(2)

	DeleteUserPermissionKeys(ctx, client, "user-1", "", " user-2 ")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAllUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectScan(0, "permission:v2:user:*", 100).SetVal([]string{"permission:v2:user:user-1"}, 0)
	mock.ExpectDel("permission:v2:user:user-1").SetVal(1)

	DeleteAllUserPermissionKeys(ctx, client)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetUserPermissionKeysSkipsCachingWithoutPositiveTTL(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	// No Set is expected: a zero TTL would make redis keep the key forever.
	SetUserPermissionKeys(ctx, client, "user-1", []string{"users:list"}, 0)
	SetUserPermissionKeys(ctx, client, "user-1", []string{"users:list"}, -time.Second)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCacheWrapsRedisHelpersAndIsNilSafe(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()
	cache := New(client)

	mock.ExpectSet("permission:v2:user:user-1", `["users:list"]`, time.Minute).SetVal("OK")
	cache.Set(ctx, "user-1", []string{"users:list"}, time.Minute)
	mock.ExpectGet("permission:v2:user:user-1").SetVal(`["users:list"]`)
	if got, ok := cache.Get(ctx, "user-1"); !ok || len(got) != 1 || got[0] != "users:list" {
		t.Fatalf("expected cache hit, got %#v ok=%v", got, ok)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	for _, empty := range []*Cache{nil, New(nil)} {
		empty.Set(ctx, "user-1", []string{"x"}, time.Minute)
		if got, ok := empty.Get(ctx, "user-1"); ok {
			t.Fatalf("expected miss without a client, got %#v", got)
		}
	}
}

func TestAuthStateRoundTripAndNilSafety(t *testing.T) {
	client, mock := redismock.NewClientMock()
	cache := New(client)
	cutoff := time.Now().Truncate(time.Second)
	raw, _ := json.Marshal(authState{Role: "viewer", TokensValidAfter: &cutoff})
	mock.ExpectSet("authstate:v2:user:u1", raw, time.Minute).SetVal("OK")
	cache.SetAuthState(context.Background(), "u1", domainuser.AuthState{Role: "viewer", TokensValidAfter: &cutoff}, time.Minute)
	mock.ExpectGet("authstate:v2:user:u1").SetVal(string(raw))
	got, ok := cache.GetAuthState(context.Background(), "u1")
	if !ok || got.Role != "viewer" || got.TokensValidAfter == nil || !got.TokensValidAfter.Equal(cutoff) {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := (*Cache)(nil).GetAuthState(context.Background(), "u1"); ok {
		t.Fatal("a nil cache never hits")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
