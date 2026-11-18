package permission

import (
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	Service Service
	httpshared.AuditWriter
}

func New(s Service, auditService httpshared.AuditService) *Handler {
	return &Handler{
		Service:     s,
		AuditWriter: httpshared.NewAuditWriter(auditService, "PermissionHandler"),
	}
}

var permissionResource = httpshared.Resource[domainpermission.Permission]{
	Name:          "permission",
	Audit:         "permission",
	ID:            func(p domainpermission.Permission) string { return p.Id },
	MutationError: permissionMutationErrorResponse,
}

func (h *Handler) Create(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Create]")
	req, ok := httpshared.Bind[dtopermission.PermissionCreate](f)
	if !ok {
		return
	}
	httpshared.Create(f, h.AuditWriter, permissionResource, req, h.Service.Create)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetByID]")
	httpshared.GetByID(f, "permission", "Service.GetByID", f.ID(), h.Service.GetByID)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{OrderBy: "resource", Direction: "asc", Limit: 10}, h.Service.GetAll)
}

func (h *Handler) Update(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Update]")
	req, ok := httpshared.Bind[dtopermission.PermissionUpdate](f)
	if !ok {
		return
	}
	httpshared.Update(f, h.AuditWriter, permissionResource, f.ID(), req, h.Service.GetByID, h.Service.Update)
}

func (h *Handler) Delete(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][Delete]")
	httpshared.Delete(f, h.AuditWriter, permissionResource, f.ID(), h.Service.GetByID, h.Service.Delete)
}

func (h *Handler) GetUserPermissions(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[PermissionHandler][GetUserPermissions]")
	httpshared.ForCurrentUser(f, "Service.GetUserPermissions", "Get user permissions successfully", h.Service.GetUserPermissions)
}
