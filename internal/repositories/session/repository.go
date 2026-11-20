package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zazhedho/logus"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"github.com/redis/go-redis/v9"
)

type Repository struct {
	Redis redis.UniversalClient
}

func NewRepository(redisClient redis.UniversalClient) *Repository {
	return &Repository{
		Redis: redisClient,
	}
}

const (
	sessionKeyPrefix       = "session:"
	userSessionsKey        = "user_sessions:"
	accessTokenSessionKey  = "access_token_session:"
	refreshTokenSessionKey = "refresh_token_session:"
	refreshUsedKey         = "refresh_token_used:"
)

// HashToken is the form tokens take in Redis keys and records: the hex sha256,
// so a Redis dump does not hand out usable tokens.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionKey(id string) string        { return sessionKeyPrefix + id }
func userSessionKey(id string) string    { return userSessionsKey + id }
func accessIndexKey(hash string) string  { return accessTokenSessionKey + hash }
func refreshIndexKey(hash string) string { return refreshTokenSessionKey + hash }

func (r *Repository) Create(ctx context.Context, session *domainsession.Session) error {
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session already expired")
	}
	session.AccessTokenHash = HashToken(session.AccessToken)
	session.RefreshTokenHash = HashToken(session.RefreshToken)

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	pipe := r.Redis.Pipeline()
	pipe.Set(ctx, sessionKey(session.SessionID), sessionData, ttl)
	pipe.SAdd(ctx, userSessionKey(session.UserID), session.SessionID)
	pipe.Expire(ctx, userSessionKey(session.UserID), ttl)
	pipe.Set(ctx, accessIndexKey(session.AccessTokenHash), session.SessionID, ttl)
	pipe.Set(ctx, refreshIndexKey(session.RefreshTokenHash), session.SessionID, ttl)
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	logus.Logf(logus.LevelDebug, "Session created: %s for user: %s", session.SessionID, session.UserID)
	return nil
}

func (r *Repository) GetBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error) {
	data, err := r.Redis.Get(ctx, sessionKey(sessionID)).Result()
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

func (r *Repository) GetByUserID(ctx context.Context, userID string) ([]*domainsession.Session, error) {
	sessionIDs, err := r.Redis.SMembers(ctx, userSessionKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	sessions := make([]*domainsession.Session, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		session, err := r.GetBySessionID(ctx, sessionID)
		if err != nil {
			if !errors.Is(err, domainsession.ErrNotFound) {
				return nil, err
			}
			logus.Logf(logus.LevelDebug, "Skipping invalid session %s: %v", sessionID, err)
			r.Redis.SRem(ctx, userSessionKey(userID), sessionID)
			continue
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (r *Repository) GetByToken(ctx context.Context, token string) (*domainsession.Session, error) {
	return r.getByTokenKey(ctx, accessIndexKey(HashToken(token)), "token")
}

// HasAccessTokenSession reports whether the access token still belongs to a
// live session. Auth calls it on every request, so it only checks the index.
func (r *Repository) HasAccessTokenSession(ctx context.Context, token string) (bool, error) {
	n, err := r.Redis.Exists(ctx, accessIndexKey(HashToken(token))).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check access token session: %w", err)
	}
	return n > 0, nil
}

// HasSession reports whether the session record still exists.
func (r *Repository) HasSession(ctx context.Context, sessionID string) (bool, error) {
	n, err := r.Redis.Exists(ctx, sessionKey(sessionID)).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session: %w", err)
	}
	return n > 0, nil
}

// GetByRefreshToken revokes the session and returns ErrRefreshReused for a
// token that was already rotated away: only an attacker or a broken client
// replays one.
func (r *Repository) GetByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error) {
	hash := HashToken(refreshToken)
	session, err := r.getByTokenKey(ctx, refreshIndexKey(hash), "refresh token")
	if err == nil || !errors.Is(err, domainsession.ErrNotFound) {
		return session, err
	}
	sessionID, usedErr := r.Redis.Get(ctx, refreshUsedKey+hash).Result()
	if errors.Is(usedErr, redis.Nil) {
		return nil, err
	}
	if usedErr != nil {
		return nil, fmt.Errorf("failed to check refresh token reuse: %w", usedErr)
	}
	if delErr := r.Delete(ctx, sessionID); delErr != nil && !errors.Is(delErr, domainsession.ErrNotFound) {
		return nil, errors.Join(domainsession.ErrRefreshReused, delErr)
	}
	return nil, domainsession.ErrRefreshReused
}

// getByTokenKey resolves a session through one of its token indexes. kind
// names the token in the error messages.
func (r *Repository) getByTokenKey(ctx context.Context, tokenKey, kind string) (*domainsession.Session, error) {
	sessionID, err := r.Redis.Get(ctx, tokenKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, repositoryshared.RedisMsg(err, domainsession.ErrNotFound, "session not found for "+kind)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session by %s: %w", kind, err)
	}
	return r.GetBySessionID(ctx, sessionID)
}

func (r *Repository) Delete(ctx context.Context, sessionID string) error {
	session, err := r.GetBySessionID(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := r.deleteSessions(ctx, session); err != nil {
		return err
	}
	logus.Logf(logus.LevelDebug, "Session deleted: %s", sessionID)
	return nil
}

// deleteSessions removes the sessions and their indexes in one round trip.
func (r *Repository) deleteSessions(ctx context.Context, sessions ...*domainsession.Session) error {
	if len(sessions) == 0 {
		return nil
	}
	pipe := r.Redis.Pipeline()
	for _, s := range sessions {
		pipe.Del(ctx, sessionKey(s.SessionID))
		pipe.SRem(ctx, userSessionKey(s.UserID), s.SessionID)
		pipe.Del(ctx, accessIndexKey(s.AccessTokenHash))
		pipe.Del(ctx, refreshIndexKey(s.RefreshTokenHash))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteByUserID deletes every session of the user.
func (r *Repository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.DeleteOthers(ctx, userID, "")
}

// DeleteOthers deletes every session of the user but keepSessionID (empty keeps
// none), in one batch.
func (r *Repository) DeleteOthers(ctx context.Context, userID, keepSessionID string) error {
	sessions, err := r.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}
	doomed := make([]*domainsession.Session, 0, len(sessions))
	for _, s := range sessions {
		if s.SessionID != keepSessionID {
			doomed = append(doomed, s)
		}
	}
	return r.deleteSessions(ctx, doomed...)
}

// RotateTokens claims the old refresh token with SET NX (one winner; the loser
// gets ErrRefreshReused and the session is revoked), then swaps in one
// MULTI/EXEC, releasing the claim if that fails.
func (r *Repository) RotateTokens(ctx context.Context, sessionID, accessToken, refreshToken string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session already expired")
	}
	session, err := r.GetBySessionID(ctx, sessionID)
	if err != nil {
		return err
	}

	claimed, err := r.Redis.SetNX(ctx, refreshUsedKey+session.RefreshTokenHash, sessionID, ttl).Result()
	if err != nil {
		return fmt.Errorf("failed to claim refresh token: %w", err)
	}
	if !claimed {
		if delErr := r.Delete(ctx, sessionID); delErr != nil && !errors.Is(delErr, domainsession.ErrNotFound) {
			return errors.Join(domainsession.ErrRefreshReused, delErr)
		}
		return domainsession.ErrRefreshReused
	}

	oldAccess, oldRefresh := session.AccessTokenHash, session.RefreshTokenHash
	session.AccessTokenHash = HashToken(accessToken)
	session.RefreshTokenHash = HashToken(refreshToken)
	session.LastActivity = time.Now()
	session.ExpiresAt = expiresAt

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	pipe := r.Redis.TxPipeline()
	pipe.Del(ctx, accessIndexKey(oldAccess))
	pipe.Del(ctx, refreshIndexKey(oldRefresh))
	pipe.Set(ctx, sessionKey(sessionID), sessionData, ttl)
	pipe.Set(ctx, accessIndexKey(session.AccessTokenHash), sessionID, ttl)
	pipe.Set(ctx, refreshIndexKey(session.RefreshTokenHash), sessionID, ttl)
	pipe.Expire(ctx, userSessionKey(session.UserID), ttl)
	if _, err = pipe.Exec(ctx); err != nil {
		// Give the claim back, or the client could never retry this token.
		if delErr := r.Redis.Del(ctx, refreshUsedKey+oldRefresh).Err(); delErr != nil {
			err = errors.Join(err, delErr)
		}
		return fmt.Errorf("failed to rotate session tokens: %w", err)
	}
	return nil
}
