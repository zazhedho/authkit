package permission

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func TestPermissionMutationErrorResponseMapsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"permission not found", domainpermission.ErrNotFound, http.StatusNotFound},
		{"wrapped permission not found", fmt.Errorf("load: %w", domainpermission.ErrNotFound), http.StatusNotFound},
		{"other domain not found", domainuser.ErrNotFound, http.StatusNotFound},
		{"menu not found", domainmenu.ErrNotFound, http.StatusNotFound},
		{"duplicate", domainpermission.ErrDuplicate, http.StatusConflict},
		{"in use", domainpermission.ErrInUse, http.StatusConflict},
		{"unrelated error", fmt.Errorf("boom"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, res := permissionMutationErrorResponse(uuid.New(), tt.err)
			if code != tt.code || res == nil {
				t.Fatalf("expected %d, got %d", tt.code, code)
			}
		})
	}
}
