package role

import (
	"context"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"

	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
)

// Service is what the role handlers call.
type Service interface {
	Create(ctx context.Context, req dtorole.RoleCreate) (domainrole.Role, error)
	GetByID(ctx context.Context, id string) (domainrole.Role, error)
	GetByIDWithDetails(ctx context.Context, id string) (dtorole.RoleWithDetails, error)
	GetAll(ctx context.Context, actor domainauth.Actor, req dtorole.ListRequest) ([]domainrole.Role, int64, error)
	Update(ctx context.Context, id string, req dtorole.RoleUpdate) (domainrole.Role, error)
	Delete(ctx context.Context, id string) error
	AssignPermissions(ctx context.Context, actor domainauth.Actor, roleId string, req dtorole.AssignPermissions) error
	AssignMenus(ctx context.Context, roleId string, req dtorole.AssignMenus) error
	GetRolePermissions(ctx context.Context, roleId string) ([]string, error)
	GetRoleMenus(ctx context.Context, roleId string) ([]string, error)
}
