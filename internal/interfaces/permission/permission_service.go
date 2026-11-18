package permission

import (
	"context"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
	"github.com/zazhedho/gokit"
)

type ServicePermissionInterface interface {
	Create(ctx context.Context, req dtopermission.PermissionCreate) (domainpermission.Permission, error)
	GetByID(ctx context.Context, id string) (domainpermission.Permission, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainpermission.Permission, int64, error)
	GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
	Update(ctx context.Context, id string, req dtopermission.PermissionUpdate) (domainpermission.Permission, error)
	Delete(ctx context.Context, id string) error
}
