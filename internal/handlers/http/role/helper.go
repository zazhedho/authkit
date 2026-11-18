package role

import (
	"errors"
	"github.com/zazhedho/gokit"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func roleMutationErrorResponse(logId uuid.UUID, err error) (int, *gokit.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, "role not found")
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, "role with this name already exists")
	}

	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "already exists"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, errMsg)
	case strings.HasPrefix(errMsg, "cannot update system"),
		strings.HasPrefix(errMsg, "cannot delete system"),
		strings.HasPrefix(errMsg, "access denied:"):
		return http.StatusForbidden, gokit.Forbidden(logId, gokit.MsgAccessDenied)
	case strings.HasPrefix(errMsg, "invalid permission ID:"),
		strings.Contains(errMsg, "menu access is derived"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logId)
	}
}
