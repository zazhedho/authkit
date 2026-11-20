package role

import (
	"errors"
	"net/http"

	"github.com/zazhedho/gokit"

	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/google/uuid"
)

func roleMutationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	// A dangling permission id or a deleted actor surfaces as a 404 too.
	if httpshared.IsNotFound(err) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, "role not found")
	}
	if errors.Is(err, domainrole.ErrDuplicate) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgExists, logID, "role with this name already exists")
	}

	if errors.Is(err, domainuser.ErrRoleAboveActor) {
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	}
	if errors.Is(err, domainrole.ErrInUse) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgSomethingWrong, logID, err.Error())
	}

	switch {
	case errors.Is(err, domainrole.ErrSystemRole), errors.Is(err, domainuser.ErrAccessDenied):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case errors.Is(err, domainrole.ErrInvalidPermission):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, err.Error())
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}
