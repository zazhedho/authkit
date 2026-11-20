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
	RegisterUser(ctx context.Context, req dtouser.Register) (domainuser.Users, error)
	AdminCreateUser(ctx context.Context, actor domainauth.Actor, req dtouser.AdminCreateUser) (domainuser.Users, error)
	LoginUser(ctx context.Context, req dtouser.Login, metadata dtouser.LoginMetadata) (string, error)
	LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error)
	LogoutUser(ctx context.Context, token string) error
	ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserID, reason string, bind domainuser.ActorBinding) (string, error)
	// StopImpersonation takes the iat_ms of the impersonation token being ended.
	StopImpersonation(ctx context.Context, actor domainauth.Actor, issuedAtMS int64) (string, error)
	GetUserByID(ctx context.Context, id string) (domainuser.Users, error)
	GetUserForActor(ctx context.Context, actor domainauth.Actor, id string) (domainuser.Users, error)
	GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error)
	GetUserByAuth(ctx context.Context, id string) (map[string]any, error)
	GetAllUsers(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainuser.Users, int64, error)
	Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.Update) (domainuser.Users, error)
	// ChangePassword returns the token cut-off the caller issues new tokens after.
	ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (time.Time, error)
	ResetPasswordByEmail(ctx context.Context, email, newPassword string) error
	Delete(ctx context.Context, actor domainauth.Actor, id string) error
	VerifyPassword(ctx context.Context, id, password string) error
	// ValidatePassword checks a new password against the strength rules.
	ValidatePassword(password string) error
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
	DestroySession(ctx context.Context, sessionID string) error
	DestroySessionByToken(ctx context.Context, token string) error
	DestroyAllUserSessions(ctx context.Context, userID string) error
	GetSessionByToken(ctx context.Context, token string) (*domainsession.Session, error)
	GetSessionBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error)
	DestroyOtherSessions(ctx context.Context, userID string, currentSessionID string) error
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
	// VerifyReset consumes the token and returns its e-mail.
	VerifyReset(ctx context.Context, token string) (string, error)
	// RestoreReset puts a consumed token back, for a reset that failed after it.
	RestoreReset(ctx context.Context, token, email string) error
}

// AsyncRunner runs background work with the request's context values but not
// its cancellation. Go returns false when the work was dropped.
type AsyncRunner interface {
	Go(ctx context.Context, fn func(ctx context.Context)) bool
}

// TokenIssuer issues and reads the JWTs the login and refresh flows need.
type TokenIssuer interface {
	Generate(userID, username, role string, after time.Time) (string, error)
	GenerateRefresh(userID, username, role string, after time.Time) (string, error)
	Claims(tokenString string) (map[string]any, error)
}
