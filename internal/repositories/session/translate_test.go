package session

import (
	"context"
	"errors"
	"testing"

	redismock "github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
)

func TestMissingSessionKeysAreDomainNotFoundWithOriginalText(t *testing.T) {
	client, mock := redismock.NewClientMock()
	repo := NewRepository(client)
	ctx := context.Background()

	mock.ExpectGet(sessionKeyPrefix + "s1").RedisNil()
	mock.ExpectGet(accessTokenSessionKey + "t1").RedisNil()
	mock.ExpectGet(refreshTokenSessionKey + "r1").RedisNil()

	_, err1 := repo.GetBySessionID(ctx, "s1")
	_, err2 := repo.GetByToken(ctx, "t1")
	_, err3 := repo.GetByRefreshToken(ctx, "r1")

	for err, text := range map[error]string{
		err1: "session not found",
		err2: "session not found for token",
		err3: "session not found for refresh token",
	} {
		if !errors.Is(err, domainsession.ErrNotFound) || !errors.Is(err, redis.Nil) {
			t.Fatalf("expected domain not found and redis.Nil in the chain, got %v", err)
		}
		if err.Error() != text {
			t.Fatalf("expected message %q, got %q", text, err.Error())
		}
	}
}
