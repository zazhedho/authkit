package session

import (
	"context"
	"time"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
)

// Repository is the Redis-backed session store the service needs.
type Repository interface {
	Create(ctx context.Context, session *domainsession.Session) error
	GetBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error)
	GetByUserID(ctx context.Context, userID string) ([]*domainsession.Session, error)
	GetByToken(ctx context.Context, token string) (*domainsession.Session, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error)
	RotateTokens(ctx context.Context, sessionID string, accessToken string, refreshToken string, expiresAt time.Time) error
	Delete(ctx context.Context, sessionID string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
