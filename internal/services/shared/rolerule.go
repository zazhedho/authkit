package shared

import (
	"context"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// RoleRuleRepository is what CheckRoleCoverage reads: the actor's permissions
// and the permissions of the role being managed or assigned.
type RoleRuleRepository interface {
	GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error)
	GetByRoleName(ctx context.Context, roleName string) ([]domainpermission.Permission, error)
}

// CheckRoleCoverage applies domainuser.CheckRoleCoverage to the actor and the
// named role. Every path that updates, deletes, impersonates or assigns a role
// goes through it.
func CheckRoleCoverage(ctx context.Context, repo RoleRuleRepository, actor domainauth.Actor, targetRole string) error {
	if actor.Role == domainuser.RoleSuperAdmin {
		return nil
	}
	if targetRole == domainuser.RoleSuperAdmin {
		return domainuser.ErrRoleAboveActor
	}

	// The scope's set was loaded server-side by the permission middleware; the
	// self routes skip that middleware, so fall back to the repository.
	actorKeys := actor.Permissions
	if len(actorKeys) == 0 {
		held, err := repo.GetUserPermissions(ctx, actor.UserID)
		if err != nil {
			return err
		}
		actorKeys = make(map[string]struct{}, len(held))
		for _, p := range held {
			actorKeys[domainauth.PermissionKey(p.Resource, p.Action)] = struct{}{}
		}
	}

	required, err := repo.GetByRoleName(ctx, targetRole)
	if err != nil {
		return err
	}
	requiredKeys := make([]string, 0, len(required))
	for _, p := range required {
		requiredKeys = append(requiredKeys, domainauth.PermissionKey(p.Resource, p.Action))
	}
	return domainuser.CheckRoleCoverage(actor.Role, actorKeys, targetRole, requiredKeys)
}
