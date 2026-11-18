package role

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
)

type Repository interface {
	Store(ctx context.Context, data domainrole.Role) error
	GetByID(ctx context.Context, id string) (domainrole.Role, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainrole.Role, int64, error)
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

// PermissionCache drops cached permission sets when grants change.
type PermissionCache interface {
	DeleteAll(ctx context.Context)
}
