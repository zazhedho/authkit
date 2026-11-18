package menu

import (
	"context"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	"github.com/zazhedho/gokit"
)

// Repository is the menu persistence the service needs.
type Repository interface {
	GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainmenu.MenuItem, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	Update(ctx context.Context, data domainmenu.MenuItem) error
}

// PermissionRepository resolves a user's permissions for menu filtering.
type PermissionRepository interface {
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}
