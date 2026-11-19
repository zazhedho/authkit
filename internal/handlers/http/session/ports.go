package session

import (
	"context"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
)

type Service interface {
	GetUserSessions(ctx context.Context, userID string, currentSessionID string) ([]*domainsession.Info, error)
	DestroySession(ctx context.Context, sessionID string) error
	DestroyOtherSessions(ctx context.Context, userID string, currentSessionID string) error
	GetSessionByToken(ctx context.Context, token string) (*domainsession.Session, error)
	GetSessionBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error)
}
