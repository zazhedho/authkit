package user

import (
	"context"
	"time"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// Repository is the persistence port of the user service.
type Repository interface {
	Store(ctx context.Context, data domainuser.Users) error
	GetByID(ctx context.Context, id string) (domainuser.Users, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainuser.Users, int64, error)
	Update(ctx context.Context, data domainuser.Users) error
	Delete(ctx context.Context, id string) error
	GetByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetByPhone(ctx context.Context, phone string) (domainuser.Users, error)
	CountByRole(ctx context.Context, role string) (int64, error)
	// UpdateFields writes only the named columns.
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
}

// TokenRevocations stores revoked access tokens and answers whether one was
// revoked.
type TokenRevocations interface {
	Store(ctx context.Context, m domainauth.Blacklist) error
	ExistsByToken(ctx context.Context, token string) (bool, error)
}

// RoleRepository resolves a role by name when assigning one to a user.
type RoleRepository interface {
	GetByName(ctx context.Context, name string) (domainrole.Role, error)
}

// PermissionRepository loads a user's permissions for authorisation checks.
type PermissionRepository interface {
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
	GetByRoleName(ctx context.Context, roleName string) ([]domainpermission.Permission, error)
}

// TokenIssuer issues and reads the JWTs the user flows need.
type TokenIssuer interface {
	Generate(userID, username, role, logID string) (string, error)
	GenerateImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error)
	Claims(tokenString string) (map[string]any, error)
	ExpiresAt(tokenString string) (time.Time, error)
}

// PermissionCache drops a user's cached permission set when their role changes.
type PermissionCache interface {
	DeleteUser(ctx context.Context, userIDs ...string)
}
