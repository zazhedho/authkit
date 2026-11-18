package middleware

import (
	"context"
	"net/http"
	"time"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
)

// TokenRevocations reports whether an access token was revoked at logout.
type TokenRevocations interface {
	ExistsByToken(ctx context.Context, token string) (bool, error)
}

// PermissionLookup loads the permissions granted to a user.
type PermissionLookup interface {
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}

// PermissionCache keeps a user's permission keys between requests. A nil value
// disables caching.
type PermissionCache interface {
	Get(ctx context.Context, userID string) ([]string, bool)
	Set(ctx context.Context, userID string, keys []string, ttl time.Duration)
}

// TokenVerifier reads and verifies the bearer token of a request.
type TokenVerifier interface {
	ClaimsFromRequest(request *http.Request) (string, map[string]any, error)
}

// tokenTypeAccess is the token_type claim of an access token. The token
// package issues it; the middleware only accepts that value.
const tokenTypeAccess = "access"
