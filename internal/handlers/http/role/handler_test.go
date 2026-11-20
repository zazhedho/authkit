package role

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zazhedho/gokit"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	"github.com/gin-gonic/gin"
)

type roleServiceHandlerTestDouble struct {
	role                 domainrole.Role
	details              dtorole.WithDetails
	roles                []domainrole.Role
	total                int64
	assigned             []string
	deletedID            string
	err                  error
	getByIDErr           error
	getAllErr            error
	deleteErr            error
	assignPermissionsErr error
}

func (m *roleServiceHandlerTestDouble) Create(ctx context.Context, req dtorole.Create) (domainrole.Role, error) {
	return m.role, m.err
}
func (m *roleServiceHandlerTestDouble) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	if m.getByIDErr != nil {
		return domainrole.Role{}, m.getByIDErr
	}
	return m.role, nil
}
func (m *roleServiceHandlerTestDouble) GetByIDWithDetails(ctx context.Context, id string) (dtorole.WithDetails, error) {
	return m.details, m.err
}
func (m *roleServiceHandlerTestDouble) GetAll(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainrole.Role, int64, error) {
	if m.getAllErr != nil {
		return nil, 0, m.getAllErr
	}
	return m.roles, m.total, m.err
}
func (m *roleServiceHandlerTestDouble) Update(ctx context.Context, id string, req dtorole.Update) (domainrole.Role, error) {
	return m.role, m.err
}
func (m *roleServiceHandlerTestDouble) Delete(ctx context.Context, id string) error {
	m.deletedID = id
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return m.err
}
func (m *roleServiceHandlerTestDouble) AssignPermissions(ctx context.Context, actor domainauth.Actor, roleID string, req dtorole.AssignPermissions) error {
	m.assigned = req.PermissionIDs
	if m.assignPermissionsErr != nil {
		return m.assignPermissionsErr
	}
	return m.err
}
func (m *roleServiceHandlerTestDouble) GetRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	return []string{"perm-old"}, nil
}

type auditServiceRoleTestDouble struct{}

func (m *auditServiceRoleTestDouble) Store(ctx context.Context, req domainaudit.AuditEvent) error {
	return nil
}
func (m *auditServiceRoleTestDouble) GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	return nil, 0, nil
}
func (m *auditServiceRoleTestDouble) GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error) {
	return dtoaudit.AuditTrailResponse{}, nil
}

func performRoleRequest(method, routePath, requestPath string, body any, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, routePath, handler)
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, requestPath, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func performRoleRawRequest(method, routePath, requestPath, body string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, routePath, handler)
	req := httptest.NewRequest(method, requestPath, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestRoleCRUDHandlers(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{
		role:    domainrole.Role{ID: "role-1", Name: "staff"},
		details: dtorole.WithDetails{ID: "role-1", Name: "staff"},
		roles:   []domainrole.Role{{ID: "role-1", Name: "staff"}},
		total:   1,
	}, &auditServiceRoleTestDouble{})

	if rec := performRoleRequest(http.MethodPost, "/roles", "/roles", dtorole.Create{Name: "staff", DisplayName: "Staff"}, handler.Create); rec.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d", rec.Code)
	}
	if rec := performRoleRequest(http.MethodGet, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", nil, handler.GetByID); rec.Code != http.StatusOK {
		t.Fatalf("expected get by id 200, got %d", rec.Code)
	}
	if rec := performRoleRequest(http.MethodGet, "/roles", "/roles", nil, handler.GetAll); rec.Code != http.StatusOK {
		t.Fatalf("expected get all 200, got %d", rec.Code)
	}
	if rec := performRoleRequest(http.MethodPut, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", dtorole.Update{DisplayName: "Staff"}, handler.Update); rec.Code != http.StatusOK {
		t.Fatalf("expected update 200, got %d", rec.Code)
	}
	if rec := performRoleRequest(http.MethodDelete, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", nil, handler.Delete); rec.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d", rec.Code)
	}
}

func TestRoleMutationErrorsAndAssignments(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{err: domainrole.ErrDuplicate}, &auditServiceRoleTestDouble{})
	rec := performRoleRequest(http.MethodPost, "/roles", "/roles", dtorole.Create{Name: "staff", DisplayName: "Staff"}, handler.Create)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected duplicate create 409, got %d", rec.Code)
	}

	service := &roleServiceHandlerTestDouble{}
	handler = New(service, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodPost, "/roles/:id/permissions", "/roles/550e8400-e29b-41d4-a716-446655440000/permissions", dtorole.AssignPermissions{PermissionIDs: []string{"perm-1"}}, handler.AssignPermissions)
	if rec.Code != http.StatusOK || len(service.assigned) != 1 || service.assigned[0] != "perm-1" {
		t.Fatalf("expected permission assignment, code=%d assigned=%v", rec.Code, service.assigned)
	}
}

func TestRoleHandlersRejectInvalidJSON(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{}, &auditServiceRoleTestDouble{})

	tests := []struct {
		name      string
		method    string
		routePath string
		path      string
		call      gin.HandlerFunc
	}{
		{name: "create", method: http.MethodPost, routePath: "/roles", path: "/roles", call: handler.Create},
		{name: "update", method: http.MethodPut, routePath: "/roles/:id", path: "/roles/550e8400-e29b-41d4-a716-446655440000", call: handler.Update},
		{name: "assign permissions", method: http.MethodPost, routePath: "/roles/:id/permissions", path: "/roles/550e8400-e29b-41d4-a716-446655440000/permissions", call: handler.AssignPermissions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performRoleRawRequest(tt.method, tt.routePath, tt.path, `{`, tt.call)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRoleHandlersServiceErrorBranches(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{err: domainrole.ErrNotFound}, &auditServiceRoleTestDouble{})
	rec := performRoleRequest(http.MethodGet, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", nil, handler.GetByID)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected get by id 404, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&roleServiceHandlerTestDouble{}, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodGet, "/roles", "/roles?page=bad", nil, handler.GetAll)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected get all bad query 400, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&roleServiceHandlerTestDouble{getAllErr: errors.New("database down")}, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodGet, "/roles", "/roles", nil, handler.GetAll)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected get all 500, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&roleServiceHandlerTestDouble{err: domainrole.ErrSystemRole}, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodPut, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", dtorole.Update{DisplayName: "System"}, handler.Update)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected update forbidden, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&roleServiceHandlerTestDouble{deleteErr: domainrole.ErrNotFound}, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodDelete, "/roles/:id", "/roles/550e8400-e29b-41d4-a716-446655440000", nil, handler.Delete)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected delete 404, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&roleServiceHandlerTestDouble{assignPermissionsErr: fmt.Errorf("%w: perm-x", domainrole.ErrInvalidPermission)}, &auditServiceRoleTestDouble{})
	rec = performRoleRequest(http.MethodPost, "/roles/:id/permissions", "/roles/550e8400-e29b-41d4-a716-446655440000/permissions", dtorole.AssignPermissions{PermissionIDs: []string{"perm-x"}}, handler.AssignPermissions)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected assign permissions 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRoleAssignmentsMapDeletedActorToNotFound(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{assignPermissionsErr: fmt.Errorf("check actor: %w", domainuser.ErrNotFound)}, &auditServiceRoleTestDouble{})
	rec := performRoleRequest(http.MethodPost, "/roles/:id/permissions", "/roles/550e8400-e29b-41d4-a716-446655440000/permissions", dtorole.AssignPermissions{PermissionIDs: []string{"perm-1"}}, handler.AssignPermissions)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected assign permissions 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRoleRoutesRejectANonUUIDID(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{}, &auditServiceRoleTestDouble{})
	for name, call := range map[string]gin.HandlerFunc{"get": handler.GetByID, "update": handler.Update, "delete": handler.Delete, "assign": handler.AssignPermissions} {
		method := http.MethodGet
		if name != "get" {
			method = http.MethodPost
		}
		rec := performRoleRequest(method, "/roles/:id", "/roles/not-a-uuid", dtorole.Update{DisplayName: "x"}, call)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}

type failingRoleAudit struct{ auditServiceRoleTestDouble }

func (failingRoleAudit) Store(context.Context, domainaudit.AuditEvent) error {
	return errors.New("audit down")
}

func TestRBACChangesFailWhenTheAuditRecordCannotBeWritten(t *testing.T) {
	handler := New(&roleServiceHandlerTestDouble{}, &failingRoleAudit{})
	rec := performRoleRequest(http.MethodPost, "/roles", "/roles", dtorole.Create{Name: "staff", DisplayName: "Staff"}, handler.Create)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create: got %d, want 500 when the change cannot be audited", rec.Code)
	}
	rec = performRoleRequest(http.MethodPost, "/roles/:id/permissions", "/roles/550e8400-e29b-41d4-a716-446655440000/permissions", dtorole.AssignPermissions{PermissionIDs: []string{}}, handler.AssignPermissions)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("assign: got %d, want 500", rec.Code)
	}
}
