package interfacepermission

import (
	"context"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	"github.com/zazhedho/gokit"
)

type RepoPermissionInterface interface {
	gokit.CRUDRepository[domainpermission.Permission]

	GetByName(ctx context.Context, name string) (domainpermission.Permission, error)
	GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}
