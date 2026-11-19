package session

import (
	"context"
	"fmt"
	"time"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"

	"github.com/google/uuid"
)

type Service struct {
	SessionRepo Repository
	RefreshTTL  time.Duration
}

// NewService builds the session service; refreshTTL is the lifetime of a
// session.
func NewService(sessionRepo Repository, refreshTTL time.Duration) *Service {
	return &Service{
		SessionRepo: sessionRepo,
		RefreshTTL:  refreshTTL,
	}
}

func (s *Service) CreateSession(ctx context.Context, user *domainuser.Users, accessToken string, refreshToken string, requestMeta domainsession.RequestMeta) (*domainsession.Session, error) {
	sessionID := uuid.New().String()

	expiresAt := time.Now().Add(s.RefreshTTL)

	userAgent := requestMeta.UserAgent
	deviceInfo := requestMeta.DeviceInfo
	if deviceInfo == "" {
		deviceInfo = extractDeviceInfo(userAgent)
	}

	session := &domainsession.Session{
		SessionID:    sessionID,
		UserID:       user.ID,
		Username:     user.Name,
		Email:        user.Email,
		Role:         user.Role,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		DeviceInfo:   deviceInfo,
		IP:           requestMeta.IP,
		UserAgent:    userAgent,
		LoginAt:      time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
	}

	if err := s.SessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

func (s *Service) GetUserSessions(ctx context.Context, userID string, currentSessionID string) ([]*domainsession.Info, error) {
	sessions, err := s.SessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessionInfos := make([]*domainsession.Info, 0, len(sessions))
	for _, session := range sessions {
		info := &domainsession.Info{
			SessionID:        session.SessionID,
			DeviceInfo:       session.DeviceInfo,
			IP:               session.IP,
			LoginAt:          session.LoginAt,
			LastActivity:     session.LastActivity,
			IsCurrentSession: session.SessionID == currentSessionID,
		}
		sessionInfos = append(sessionInfos, info)
	}

	return sessionInfos, nil
}

func (s *Service) DestroySession(ctx context.Context, sessionID string) error {
	return s.SessionRepo.Delete(ctx, sessionID)
}

func (s *Service) DestroySessionByToken(ctx context.Context, token string) error {
	session, err := s.SessionRepo.GetByToken(ctx, token)
	if err != nil {
		return err
	}
	return s.SessionRepo.Delete(ctx, session.SessionID)
}

func (s *Service) GetSessionByToken(ctx context.Context, token string) (*domainsession.Session, error) {
	return s.SessionRepo.GetByToken(ctx, token)
}

func (s *Service) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error) {
	return s.SessionRepo.GetByRefreshToken(ctx, refreshToken)
}

func (s *Service) GetSessionBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error) {
	return s.SessionRepo.GetBySessionID(ctx, sessionID)
}

func (s *Service) RotateSessionTokens(ctx context.Context, sessionID string, accessToken string, refreshToken string, expiresAt time.Time) error {
	return s.SessionRepo.RotateTokens(ctx, sessionID, accessToken, refreshToken, expiresAt)
}

func (s *Service) DestroyAllUserSessions(ctx context.Context, userID string) error {
	return s.SessionRepo.DeleteByUserID(ctx, userID)
}

func (s *Service) DestroyOtherSessions(ctx context.Context, userID string, currentSessionID string) error {
	sessions, err := s.SessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.SessionID != currentSessionID {
			if err := s.SessionRepo.Delete(ctx, session.SessionID); err != nil {
				return err
			}
		}
	}

	return nil
}
