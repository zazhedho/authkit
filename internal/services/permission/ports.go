package permission

import (
	"context"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	"github.com/zazhedho/gokit"
)

// Repository is the persistence the service needs.
type Repository interface {
	Store(ctx context.Context, data domainpermission.Permission) error
	GetByID(ctx context.Context, id string) (domainpermission.Permission, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainpermission.Permission, int64, error)
	Update(ctx context.Context, data domainpermission.Permission) error
	Delete(ctx context.Context, id string) error
	GetByName(ctx context.Context, name string) (domainpermission.Permission, error)
	GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}
