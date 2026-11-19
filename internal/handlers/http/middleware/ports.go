package middleware

import (
	"context"
	"net/http"
	"time"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// TokenRevocations reports whether an access token was revoked at logout.
type TokenRevocations interface {
	ExistsByToken(ctx context.Context, token string) (bool, error)
}

// PermissionLookup loads the permissions granted to a user.
type PermissionLookup interface {
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
}

// PermissionCache keeps a user's permission keys between requests. A nil value
// disables caching.
type PermissionCache interface {
	Get(ctx context.Context, userID string) ([]string, bool)
	Set(ctx context.Context, userID string, keys []string, ttl time.Duration)
}

// UserStates loads the current auth state of a live user; a missing or
// soft-deleted user is domainuser.ErrNotFound.
type UserStates interface {
	GetAuthState(ctx context.Context, userID string) (domainuser.AuthState, error)
}

// StateCache keeps auth states between requests, invalidated when a user's role
// or tokens change. A nil value disables caching.
type StateCache interface {
	GetAuthState(ctx context.Context, userID string) (domainuser.AuthState, bool)
	SetAuthState(ctx context.Context, userID string, state domainuser.AuthState, ttl time.Duration)
}

// SessionIndex answers whether an access token still belongs to a live
// session. A nil value means sessions are off.
type SessionIndex interface {
	HasAccessTokenSession(ctx context.Context, token string) (bool, error)
}

// TokenVerifier reads and verifies the bearer token of a request.
type TokenVerifier interface {
	ClaimsFromRequest(request *http.Request) (string, map[string]any, error)
}

// tokenTypeAccess is the token_type claim of an access token. The token
// package issues it; the middleware only accepts that value.
const tokenTypeAccess = "access"
