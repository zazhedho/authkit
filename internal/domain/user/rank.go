package user

import "errors"

// Role-rule failures. Services return them wrapped or as is; handlers map them
// to 403 (above actor, protected) or 409 (last superadmin).
var (
	ErrRoleAboveActor    = errors.New("access denied: the role holds permissions you do not have")
	ErrSelfRoleChange    = errors.New("you cannot change your own role")
	ErrLastSuperAdmin    = errors.New("the last superadmin cannot be deleted or demoted")
	ErrEmailRequired     = errors.New("a valid email is required")
	ErrReasonRequired    = errors.New("a reason is required")
	ErrPasswordRequired  = errors.New("current password is required")
	ErrPasswordIncorrect = errors.New("current password is incorrect")
)

// CheckRoleCoverage is the one role rule: an actor may update, delete,
// impersonate or assign a role only when every permission of that role is also
// held by the actor. Superadmin is above everything and only a superadmin may
// touch the superadmin role. Keys are "resource:action".
func CheckRoleCoverage(actorRole string, actorKeys map[string]struct{}, targetRole string, targetKeys []string) error {
	if actorRole == RoleSuperAdmin {
		return nil
	}
	if targetRole == RoleSuperAdmin {
		return ErrRoleAboveActor
	}
	for _, key := range targetKeys {
		if _, ok := actorKeys[key]; !ok {
			return ErrRoleAboveActor
		}
	}
	return nil
}
