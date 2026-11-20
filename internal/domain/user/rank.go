package user

import (
	"errors"
	"time"
)

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
	ErrAccessDenied      = errors.New("access denied")
	ErrInvalidRole       = errors.New("invalid role")
	ErrSessionRevocation = errors.New("sessions could not be ended")
	ErrSamePassword      = errors.New("new password must be different from current password")
)

// Impersonation failures; handlers map them to 403, 400 or 401.
var (
	ErrNestedImpersonation = errors.New("cannot start nested impersonation")
	ErrSelfImpersonation   = errors.New("cannot impersonate your own account")
	ErrTargetRequired      = errors.New("target user id is required")
	ErrOriginalRequired    = errors.New("original user id is required")
	ErrNotImpersonated     = errors.New("current session is not impersonated")
	ErrImpersonatorRevoked = errors.New("the impersonating user's session is no longer valid")
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

// AuthState is what request authentication needs about a live user: the
// current role and the instant before which issued tokens are void.
type AuthState struct {
	Role             string
	TokensValidAfter *time.Time
}
