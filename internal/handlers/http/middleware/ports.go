package middleware

import (
	"context"
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
