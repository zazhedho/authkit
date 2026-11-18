package permission

import (
	"context"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"
)

func TestKey(t *testing.T) {
	if got := Key("user-1"); got != "permission:user:user-1" {
		t.Fatalf("Key() = %q", got)
	}
}

func TestGetUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectGet("permission:user:user-1").SetVal(`["users:list","users:create"]`)

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

	mock.ExpectGet("permission:user:user-1").SetVal(`{`)

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

	mock.ExpectSet("permission:user:user-1", `["users:list"]`, 2*time.Minute).SetVal("OK")

	SetUserPermissionKeys(ctx, client, "user-1", []string{"users:list"}, 2*time.Minute)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectDel("permission:user:user-1", "permission:user:user-2").SetVal(2)

	DeleteUserPermissionKeys(ctx, client, "user-1", "", " user-2 ")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAllUserPermissionKeys(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectScan(0, "permission:user:*", 100).SetVal([]string{"permission:user:user-1"}, 0)
	mock.ExpectDel("permission:user:user-1").SetVal(1)

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
