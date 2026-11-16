package interfacepermission

import (
	"context"
	domainpermission "github.com/zazhedho/authkit/domain/permission"
	interfacegeneric "github.com/zazhedho/gokit/repository"
)

type RepoPermissionInterface interface {
	interfacegeneric.GenericRepository[domainpermission.Permission]

	GetByName(ctx context.Context, name string) (domainpermission.Permission, error)
	GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}
