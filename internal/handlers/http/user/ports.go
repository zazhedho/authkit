package user

import (
	"context"
	"time"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
)

type Service interface {
	RegisterUser(ctx context.Context, req dtouser.UserRegister) (domainuser.Users, error)
	AdminCreateUser(ctx context.Context, actor domainauth.Actor, req dtouser.AdminCreateUser) (domainuser.Users, error)
	LoginUser(ctx context.Context, req dtouser.Login, logId string, metadata dtouser.LoginMetadata) (string, error)
	LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error)
	LogoutUser(ctx context.Context, token string) error
	ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserId string, logId string) (string, error)
	StopImpersonation(ctx context.Context, actor domainauth.Actor, logId string) (string, error)
	GetUserById(ctx context.Context, id string) (domainuser.Users, error)
	GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error)
	GetUserByAuth(ctx context.Context, id string) (map[string]any, error)
	GetAllUsers(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainuser.Users, int64, error)
	Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.UserUpdate) (domainuser.Users, error)
	ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (domainuser.Users, error)
	ForgotPassword(ctx context.Context, req dtouser.ForgotPasswordRequest) (string, error)
	ResetPassword(ctx context.Context, req dtouser.ResetPasswordRequest) error
	ResetPasswordByEmail(ctx context.Context, email, newPassword string) error
	Delete(ctx context.Context, id string) error
	// IsTokenRevoked reports whether a token was revoked at logout.
	IsTokenRevoked(ctx context.Context, token string) (bool, error)
}

// LoginLimiter throttles login attempts per identifier. A nil value means
// limiting is off.
type LoginLimiter interface {
	IsBlocked(ctx context.Context, key string) (bool, time.Duration, error)
	RegisterFailure(ctx context.Context, key string) (bool, time.Duration, error)
	Reset(ctx context.Context, key string) error
}

// SessionService is the Redis-backed session store; the handler treats a nil
// value as "sessions are off".
type SessionService interface {
	CreateSession(ctx context.Context, user *domainuser.Users, accessToken string, refreshToken string, requestMeta domainsession.RequestMeta) (*domainsession.Session, error)
	DestroySessionByToken(ctx context.Context, token string) error
	DestroyAllUserSessions(ctx context.Context, userID string) error
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error)
	RotateSessionTokens(ctx context.Context, sessionID string, accessToken string, refreshToken string, expiresAt time.Time) error
}

// AppConfigService reads the feature flags the handler consults.
type AppConfigService interface {
	IsEnabled(ctx context.Context, configKey string, fallback bool) (bool, error)
}

// OTPService sends and verifies registration OTP codes.
type OTPService interface {
	SendRegisterOTP(ctx context.Context, email, appName string) error
	VerifyRegisterOTP(ctx context.Context, email, code string) error
}

// ResetService starts and verifies password resets.
type ResetService interface {
	RequestReset(ctx context.Context, email, appName string) error
	VerifyReset(ctx context.Context, token string) (string, error)
}

// TokenIssuer issues and reads the JWTs the login and refresh flows need.
type TokenIssuer interface {
	Generate(userID, username, role, logID string) (string, error)
	GenerateRefresh(userID, username, role, logID string) (string, error)
	GenerateImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error)
	GenerateRefreshImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error)
	Claims(tokenString string) (map[string]any, error)
}
