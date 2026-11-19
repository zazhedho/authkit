package permission

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
)

// Service is the permission service the handler calls.
type Service interface {
	Create(ctx context.Context, req dtopermission.Create) (domainpermission.Permission, error)
	GetByID(ctx context.Context, id string) (domainpermission.Permission, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error)
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
	Update(ctx context.Context, id string, req dtopermission.Update) (domainpermission.Permission, error)
	Delete(ctx context.Context, id string) error
}
