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

type Repository interface {
	Store(ctx context.Context, data domainuser.Users) error
	GetByID(ctx context.Context, id string) (domainuser.Users, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainuser.Users, int64, error)
	// GetAllExcludingRole lists users who do not hold role, in the query, so the
	// total stays right.
	GetAllExcludingRole(ctx context.Context, req dtoshared.ListRequest, role string) ([]domainuser.Users, int64, error)
	// Delete soft-deletes a user; deleting the last superadmin is ErrLastSuperAdmin.
	Delete(ctx context.Context, id string) error
	GetByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetByPhone(ctx context.Context, phone string) (domainuser.Users, error)
	GetByGoogleSubject(ctx context.Context, subject string) (domainuser.Users, error)
	// UpdateFields writes only the named columns.
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// UpdateFieldsRevoking writes the columns and sets tokens_valid_after to the
	// database clock in the same statement; it returns that instant. Demoting
	// the last superadmin is ErrLastSuperAdmin.
	UpdateFieldsRevoking(ctx context.Context, id string, fields map[string]any) (time.Time, error)
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
	Generate(userID, username, role string, after time.Time) (string, error)
	GenerateNoSession(userID, username, role string, after time.Time) (string, error)
	GenerateImpersonated(userID, username, role, originalUserID, originalUsername, originalRole string, after time.Time) (string, error)
	Claims(tokenString string) (map[string]any, error)
	ExpiresAt(tokenString string) (time.Time, error)
}

// SessionRevoker ends every session of a user.
type SessionRevoker interface {
	DestroyAllUserSessions(ctx context.Context, userID string) error
}

// PermissionCache drops a user's cached permission set when their role changes.
type PermissionCache interface {
	DeleteUser(ctx context.Context, userIDs ...string)
}
