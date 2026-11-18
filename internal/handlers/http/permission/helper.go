package permission

import (
	"errors"
	"github.com/zazhedho/gokit"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func permissionMutationErrorResponse(logId uuid.UUID, err error) (int, *gokit.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, "permission not found")
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, "permission with this name already exists")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "already exists") {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, errMsg)
	}

	return http.StatusInternalServerError, gokit.InternalServerError(logId)
}
