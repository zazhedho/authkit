package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"

	"github.com/alicebob/miniredis/v2"
	redismock "github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

func newMiniRepo(t *testing.T) (*Repository, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRepository(client), mr
}

func newSession(id, access, refresh string) *domainsession.Session {
	now := time.Now()
	return &domainsession.Session{
		SessionID: id, UserID: "user-1", Username: "Jane", Email: "jane@example.com", Role: "viewer",
		AccessToken: access, RefreshToken: refresh, LoginAt: now, LastActivity: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestSessionLifecycle(t *testing.T) {
	repo, _ := newMiniRepo(t)
	ctx := context.Background()
	if err := repo.Create(ctx, newSession("s1", "access-1", "refresh-1")); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.GetByToken(ctx, "access-1"); err != nil || got.SessionID != "s1" {
		t.Fatalf("by access: %+v %v", got, err)
	}
	if got, err := repo.GetByRefreshToken(ctx, "refresh-1"); err != nil || got.SessionID != "s1" {
		t.Fatalf("by refresh: %+v %v", got, err)
	}
	if live, err := repo.HasAccessTokenSession(ctx, "access-1"); err != nil || !live {
		t.Fatalf("live=%v err=%v", live, err)
	}
	if err := repo.RotateTokens(ctx, "s1", "access-2", "refresh-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if live, _ := repo.HasAccessTokenSession(ctx, "access-1"); live {
		t.Fatal("the old access token must stop belonging to a session after rotation")
	}
	if live, _ := repo.HasAccessTokenSession(ctx, "access-2"); !live {
		t.Fatal("the new access token must belong to the session")
	}
	if err := repo.Delete(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if live, _ := repo.HasAccessTokenSession(ctx, "access-2"); live {
		t.Fatal("a deleted session must not validate its access token")
	}
	if _, err := repo.GetBySessionID(ctx, "s1"); !errors.Is(err, domainsession.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestRedisHoldsNoRawTokens(t *testing.T) {
	repo, mr := newMiniRepo(t)
	if err := repo.Create(context.Background(), newSession("s1", "raw-access-token", "raw-refresh-token")); err != nil {
		t.Fatal(err)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "raw-access-token") || strings.Contains(key, "raw-refresh-token") {
			t.Fatalf("raw token in key %q", key)
		}
		if v, err := mr.Get(key); err == nil && (strings.Contains(v, "raw-access-token") || strings.Contains(v, "raw-refresh-token")) {
			t.Fatalf("raw token in value of %q", key)
		}
	}
	if !mr.Exists("access_token_session:" + HashToken("raw-access-token")) {
		t.Fatal("expected the access index to be keyed by the token hash")
	}
}

func TestReusingARotatedRefreshTokenRevokesTheSession(t *testing.T) {
	repo, _ := newMiniRepo(t)
	ctx := context.Background()
	if err := repo.Create(ctx, newSession("s1", "access-1", "refresh-1")); err != nil {
		t.Fatal(err)
	}
	if err := repo.RotateTokens(ctx, "s1", "access-2", "refresh-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByRefreshToken(ctx, "refresh-1"); !errors.Is(err, domainsession.ErrRefreshReused) {
		t.Fatalf("got %v, want ErrRefreshReused", err)
	}
	if live, _ := repo.HasAccessTokenSession(ctx, "access-2"); live {
		t.Fatal("reuse detection must revoke the whole session")
	}
}

func TestConcurrentRotationOfOneRefreshTokenHasOneWinner(t *testing.T) {
	repo, _ := newMiniRepo(t)
	ctx := context.Background()
	if err := repo.Create(ctx, newSession("s1", "access-1", "refresh-1")); err != nil {
		t.Fatal(err)
	}
	if err := repo.RotateTokens(ctx, "s1", "access-2", "refresh-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A second rotation that read the session before the first finished.
	stale := newSession("s1", "access-1", "refresh-1")
	stale.AccessTokenHash, stale.RefreshTokenHash = HashToken("access-1"), HashToken("refresh-1")
	if ok, err := repo.Redis.SetNX(ctx, refreshUsedKey+stale.RefreshTokenHash, "s1", time.Hour).Result(); err != nil || ok {
		t.Fatalf("the old refresh token must already be claimed (ok=%v err=%v)", ok, err)
	}
}

func TestDeleteByUserIDReportsFailures(t *testing.T) {
	repo, mr := newMiniRepo(t)
	ctx := context.Background()
	if err := repo.Create(ctx, newSession("s1", "a1", "r1")); err != nil {
		t.Fatal(err)
	}
	mr.SetError("boom")
	if err := repo.DeleteByUserID(ctx, "user-1"); err == nil {
		t.Fatal("DeleteByUserID must return the Redis failure")
	}
}

func TestSessionRepositoryRejectsExpiredSessionOnCreateAndDeleteByUser(t *testing.T) {
	client, mock := redismock.NewClientMock()
	repo := NewRepository(client)
	ctx := context.Background()
	if err := repo.Create(ctx, &domainsession.Session{SessionID: "expired", ExpiresAt: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatal("expected expired session create error")
	}
	mock.ExpectSMembers("user_sessions:missing-user").SetVal([]string{})
	if err := repo.DeleteByUserID(ctx, "missing-user"); err != nil {
		t.Fatalf("delete by user should tolerate missing set, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestSessionRepositoryGetBySessionIDPropagatesRedisError(t *testing.T) {
	client, mock := redismock.NewClientMock()
	repo := NewRepository(client)
	mock.ExpectGet("session:session-1").SetErr(redis.TxFailedErr)

	if _, err := repo.GetBySessionID(context.Background(), "session-1"); err == nil {
		t.Fatal("expected redis error")
	}
}
