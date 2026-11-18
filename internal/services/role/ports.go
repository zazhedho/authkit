package role

import (
	"context"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	"github.com/zazhedho/gokit"
)

// Repository is the role persistence the service needs.
type Repository interface {
	Store(ctx context.Context, data domainrole.Role) error
	GetByID(ctx context.Context, id string) (domainrole.Role, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainrole.Role, int64, error)
	Update(ctx context.Context, data domainrole.Role) error
	Delete(ctx context.Context, id string) error
	GetByName(ctx context.Context, name string) (domainrole.Role, error)
	AssignPermissions(ctx context.Context, roleId string, permissionIds []string) error
	GetRolePermissions(ctx context.Context, roleId string) ([]string, error)
}

// PermissionRepository validates permission ids and resolves a user's grants.
type PermissionRepository interface {
	GetByID(ctx context.Context, id string) (domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}

// MenuRepository lists the menus a role's permissions can reach.
type MenuRepository interface {
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
}
