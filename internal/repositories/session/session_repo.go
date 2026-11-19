package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zazhedho/logus"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

// Repository stores session data.
type Repository struct {
	Redis *redis.Client
}

// NewRepository creates the session repository on Redis.
func NewRepository(redisClient *redis.Client) *Repository {
	return &Repository{
		Redis: redisClient,
	}
}

const (
	sessionKeyPrefix       = "session:"
	userSessionsKey        = "user_sessions:"
	accessTokenSessionKey  = "access_token_session:"
	refreshTokenSessionKey = "refresh_token_session:"
)

// Create creates the record.
func (r *Repository) Create(ctx context.Context, session *domainsession.Session) error {
	sessionKey := fmt.Sprintf("%s%s", sessionKeyPrefix, session.SessionID)
	userSessionKey := fmt.Sprintf("%s%s", userSessionsKey, session.UserID)
	accessTokenKey := fmt.Sprintf("%s%s", accessTokenSessionKey, session.AccessToken)
	refreshTokenKey := fmt.Sprintf("%s%s", refreshTokenSessionKey, session.RefreshToken)

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session already expired")
	}

	pipe := r.Redis.Pipeline()
	pipe.Set(ctx, sessionKey, sessionData, ttl)
	pipe.SAdd(ctx, userSessionKey, session.SessionID)
	pipe.Expire(ctx, userSessionKey, ttl)
	pipe.Set(ctx, accessTokenKey, session.SessionID, ttl)
	pipe.Set(ctx, refreshTokenKey, session.SessionID, ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	logus.Logf(logus.LevelDebug, "Session created: %s for user: %s", session.SessionID, session.UserID)
	return nil
}

// GetBySessionID returns one record found by session ID.
func (r *Repository) GetBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error) {
	sessionKey := fmt.Sprintf("%s%s", sessionKeyPrefix, sessionID)

	data, err := r.Redis.Get(ctx, sessionKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, repositoryshared.RedisMsg(err, domainsession.ErrNotFound, "session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session domainsession.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// GetByUserID returns one record found by user ID.
func (r *Repository) GetByUserID(ctx context.Context, userID string) ([]*domainsession.Session, error) {
	userSessionKey := fmt.Sprintf("%s%s", userSessionsKey, userID)

	sessionIDs, err := r.Redis.SMembers(ctx, userSessionKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	sessions := make([]*domainsession.Session, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		session, err := r.GetBySessionID(ctx, sessionID)
		if err != nil {
			logus.Logf(logus.LevelDebug, "Skipping invalid session %s: %v", sessionID, err)
			r.Redis.SRem(ctx, userSessionKey, sessionID)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// GetByToken returns one record found by token.
func (r *Repository) GetByToken(ctx context.Context, token string) (*domainsession.Session, error) {
	return r.getByTokenKey(ctx, accessTokenSessionKey, token, "token")
}

// GetByRefreshToken returns one record found by refresh token.
func (r *Repository) GetByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error) {
	return r.getByTokenKey(ctx, refreshTokenSessionKey, refreshToken, "refresh token")
}

// getByTokenKey resolves a session through one of its token indexes. kind
// names the token in the error messages.
func (r *Repository) getByTokenKey(ctx context.Context, keyPrefix, token, kind string) (*domainsession.Session, error) {
	tokenKey := fmt.Sprintf("%s%s", keyPrefix, token)

	sessionID, err := r.Redis.Get(ctx, tokenKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, repositoryshared.RedisMsg(err, domainsession.ErrNotFound, "session not found for "+kind)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session by %s: %w", kind, err)
	}

	return r.GetBySessionID(ctx, sessionID)
}

// Delete deletes the record.
func (r *Repository) Delete(ctx context.Context, sessionID string) error {
	session, err := r.GetBySessionID(ctx, sessionID)
	if err != nil {
		return err
	}

	sessionKey := fmt.Sprintf("%s%s", sessionKeyPrefix, sessionID)
	userSessionKey := fmt.Sprintf("%s%s", userSessionsKey, session.UserID)
	accessTokenKey := fmt.Sprintf("%s%s", accessTokenSessionKey, session.AccessToken)
	refreshTokenKey := fmt.Sprintf("%s%s", refreshTokenSessionKey, session.RefreshToken)

	pipe := r.Redis.Pipeline()
	pipe.Del(ctx, sessionKey)
	pipe.SRem(ctx, userSessionKey, sessionID)
	pipe.Del(ctx, accessTokenKey)
	pipe.Del(ctx, refreshTokenKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	logus.Logf(logus.LevelDebug, "Session deleted: %s", sessionID)
	return nil
}

// DeleteByUserID deletes the by user ID.
func (r *Repository) DeleteByUserID(ctx context.Context, userID string) error {
	sessions, err := r.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if err := r.Delete(ctx, session.SessionID); err != nil {
			logus.Logf(logus.LevelError, "Failed to delete session %s: %v", session.SessionID, err)
		}
	}

	return nil
}

// RotateTokens implements the rotate tokens operation.
func (r *Repository) RotateTokens(ctx context.Context, sessionID string, accessToken string, refreshToken string, expiresAt time.Time) error {
	session, err := r.GetBySessionID(ctx, sessionID)
	if err != nil {
		return err
	}

	sessionKey := fmt.Sprintf("%s%s", sessionKeyPrefix, sessionID)
	oldAccessTokenKey := fmt.Sprintf("%s%s", accessTokenSessionKey, session.AccessToken)
	oldRefreshTokenKey := fmt.Sprintf("%s%s", refreshTokenSessionKey, session.RefreshToken)
	newAccessTokenKey := fmt.Sprintf("%s%s", accessTokenSessionKey, accessToken)
	newRefreshTokenKey := fmt.Sprintf("%s%s", refreshTokenSessionKey, refreshToken)

	session.AccessToken = accessToken
	session.RefreshToken = refreshToken
	session.LastActivity = time.Now()
	session.ExpiresAt = expiresAt

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session already expired")
	}

	pipe := r.Redis.Pipeline()
	pipe.Del(ctx, oldAccessTokenKey)
	pipe.Del(ctx, oldRefreshTokenKey)
	pipe.Set(ctx, sessionKey, sessionData, ttl)
	pipe.Set(ctx, newAccessTokenKey, sessionID, ttl)
	pipe.Set(ctx, newRefreshTokenKey, sessionID, ttl)
	userSessionKey := fmt.Sprintf("%s%s", userSessionsKey, session.UserID)
	pipe.Expire(ctx, userSessionKey, ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to rotate session tokens: %w", err)
	}

	return nil
}

// DeleteExpired deletes the expired.
func (r *Repository) DeleteExpired(ctx context.Context) error {
	logus.Log(logus.LevelDebug, "Expired sessions are automatically removed by Redis TTL")
	return nil
}
