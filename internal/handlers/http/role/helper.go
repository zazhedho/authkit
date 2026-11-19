package role

import (
	"errors"
	"net/http"
	"strings"

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
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logID, "role with this name already exists")
	}

	if errors.Is(err, domainuser.ErrRoleAboveActor) {
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	}
	if errors.Is(err, domainrole.ErrInUse) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgSomethingWrong, logID, err.Error())
	}

	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "already exists"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logID, errMsg)
	case strings.HasPrefix(errMsg, "cannot update system"),
		strings.HasPrefix(errMsg, "cannot delete system"),
		strings.HasPrefix(errMsg, "access denied:"):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case strings.HasPrefix(errMsg, "invalid permission ID:"),
		strings.Contains(errMsg, "menu access is derived"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}
