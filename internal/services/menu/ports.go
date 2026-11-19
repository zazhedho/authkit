package menu

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
)

// Repository is the persistence port of the menu service.
type Repository interface {
	GetByID(ctx context.Context, id string) (domainmenu.Item, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error)
	Update(ctx context.Context, data domainmenu.Item) error
}

// PermissionRepository resolves a user's permissions for menu filtering.
type PermissionRepository interface {
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
}
