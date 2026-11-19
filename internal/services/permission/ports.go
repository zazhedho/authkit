package permission

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
)

type Repository interface {
	Store(ctx context.Context, data domainpermission.Permission) error
	GetByID(ctx context.Context, id string) (domainpermission.Permission, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error)
	Update(ctx context.Context, data domainpermission.Permission) error
	Delete(ctx context.Context, id string) error
	GetByName(ctx context.Context, name string) (domainpermission.Permission, error)
	GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
}

// Cache drops cached permission sets when grants change.
type Cache interface {
	DeleteAll(ctx context.Context)
}
