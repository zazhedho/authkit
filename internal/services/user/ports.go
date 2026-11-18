package user

import (
	"context"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/gokit"
)

// Repository is the user persistence the service needs.
type Repository interface {
	Store(ctx context.Context, data domainuser.Users) error
	GetByID(ctx context.Context, id string) (domainuser.Users, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainuser.Users, int64, error)
	Update(ctx context.Context, data domainuser.Users) error
	Delete(ctx context.Context, id string) error
	GetByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetByPhone(ctx context.Context, phone string) (domainuser.Users, error)
}

// BlacklistRepository stores revoked access tokens.
type BlacklistRepository interface {
	Store(ctx context.Context, m domainauth.Blacklist) error
	ExistsByToken(ctx context.Context, token string) (bool, error)
}

// RoleRepository resolves a role by name when assigning one to a user.
type RoleRepository interface {
	GetByName(ctx context.Context, name string) (domainrole.Role, error)
}

// PermissionRepository loads a user's permissions for authorisation checks.
type PermissionRepository interface {
	GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error)
}
