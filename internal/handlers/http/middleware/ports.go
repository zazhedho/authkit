package middleware

import (
	"context"

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
