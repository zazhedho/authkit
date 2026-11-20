package shared

import (
	"context"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
)

// PermissionRepository is the lookup HasPermission needs; each service passes
// its own repository port, which already has this method.
type PermissionRepository interface {
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
}
