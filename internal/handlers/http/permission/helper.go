package permission

import (
	"errors"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	"github.com/zazhedho/gokit"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func permissionMutationErrorResponse(logId uuid.UUID, err error) (int, *gokit.ApiResponse) {
	if errors.Is(err, domainpermission.ErrNotFound) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, "permission not found")
	}
	if errors.Is(err, domainpermission.ErrDuplicate) {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, "permission with this name already exists")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "already exists") {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, errMsg)
	}

	return http.StatusInternalServerError, gokit.InternalServerError(logId)
}
