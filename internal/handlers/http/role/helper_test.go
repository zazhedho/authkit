package role

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func TestRoleMutationErrorResponseMapsDomainErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"role not found", domainrole.ErrNotFound, http.StatusNotFound},
		{"wrapped role not found", fmt.Errorf("load: %w", domainrole.ErrNotFound), http.StatusNotFound},
		{"dangling permission", domainpermission.ErrNotFound, http.StatusNotFound},
		{"actor row deleted", domainuser.ErrNotFound, http.StatusNotFound},
		{"wrapped actor row deleted", fmt.Errorf("check: %w", domainuser.ErrNotFound), http.StatusNotFound},
		{"unrelated error", fmt.Errorf("boom"), http.StatusInternalServerError},
		{"duplicate role", domainrole.ErrDuplicate, http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, res := roleMutationErrorResponse(uuid.New(), tt.err)
			if code != tt.code || res == nil {
				t.Fatalf("expected %d, got %d", tt.code, code)
			}
		})
	}
}
