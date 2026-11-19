package permission

import (
	"errors"
	"net/http"

	"github.com/zazhedho/gokit"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/google/uuid"
)

func permissionMutationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	if httpshared.IsNotFound(err) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, "permission not found")
	}
	if errors.Is(err, domainpermission.ErrDuplicate) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgExists, logID, "permission with this name already exists")
	}
	if errors.Is(err, domainpermission.ErrInUse) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgSomethingWrong, logID, err.Error())
	}

	return http.StatusInternalServerError, gokit.InternalServerError(logID)
}
