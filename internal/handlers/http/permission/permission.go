package permission

import (
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
)

// Handler serves the permission HTTP endpoints.
type Handler struct {
	Service Service
	httpshared.AuditWriter
}

// New creates the permission handler.
func New(s Service, auditService httpshared.AuditService) *Handler {
	return &Handler{
		Service:     s,
		AuditWriter: httpshared.NewAuditWriter(auditService, "PermissionHandler"),
	}
}

var permissionResource = httpshared.Resource[domainpermission.Permission]{
	Name:          "permission",
	Audit:         "permission",
	ID:            func(p domainpermission.Permission) string { return p.ID },
	MutationError: permissionMutationErrorResponse,
}

// Create handles the create request.
func (h *Handler) Create(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Create]")
	req, ok := httpshared.Bind[dtopermission.Create](f)
	if !ok {
		return
	}
	httpshared.Create(f, h.AuditWriter, permissionResource, req, h.Service.Create)
}

// GetByID handles the get by ID request.
func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetByID]")
	httpshared.GetByID(f, "permission", "Service.GetByID", f.ID(), h.Service.GetByID)
}

// GetAll handles the get all request.
func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{OrderBy: "resource", Direction: "asc", Limit: 10, Policy: dtoshared.ReferenceList}, h.Service.GetAll)
}

// Update handles the update request.
func (h *Handler) Update(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Update]")
	req, ok := httpshared.Bind[dtopermission.Update](f)
	if !ok {
		return
	}
	httpshared.Update(f, h.AuditWriter, permissionResource, f.ID(), req, h.Service.GetByID, h.Service.Update)
}

// Delete handles the delete request.
func (h *Handler) Delete(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Delete]")
	httpshared.Delete(f, h.AuditWriter, permissionResource, f.ID(), h.Service.GetByID, h.Service.Delete)
}

// GetUserPermissions handles the get user permissions request.
func (h *Handler) GetUserPermissions(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetUserPermissions]")
	httpshared.ForCurrentUser(f, "Service.GetUserPermissions", "Get user permissions successfully", h.Service.GetUserPermissions)
}
