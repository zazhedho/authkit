package role

import (
	"context"
	"net/http"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
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
		AuditWriter: httpshared.NewAuditWriter(auditService, "RoleHandler"),
	}
}

var roleResource = httpshared.Resource[domainrole.Role]{
	Name:          "role",
	Audit:         "role",
	ID:            func(r domainrole.Role) string { return r.ID },
	MutationError: roleMutationErrorResponse,
}

func (h *Handler) Create(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[RoleHandler][Create]")
	req, ok := httpshared.Bind[dtorole.Create](f)
	if !ok {
		return
	}
	httpshared.Create(f, h.AuditWriter, roleResource, req, h.Service.Create)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[RoleHandler][GetByID]")
	httpshared.GetByID(f, "role", "Service.GetByIDWithDetails", f.ID(), h.Service.GetByIDWithDetails)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[RoleHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{OrderBy: "name", Direction: "asc", Limit: 10, Policy: dtoshared.ReferenceList},
		func(reqCtx context.Context, req dtoshared.ListRequest) ([]domainrole.Role, int64, error) {
			return h.Service.GetAll(reqCtx, httpshared.ActorFrom(reqCtx), req)
		})
}

func (h *Handler) Update(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[RoleHandler][Update]")
	req, ok := httpshared.Bind[dtorole.Update](f)
	if !ok {
		return
	}
	httpshared.Update(f, h.AuditWriter, roleResource, f.ID(), req, h.Service.GetByID, h.Service.Update)
}

func (h *Handler) Delete(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[RoleHandler][Delete]")
	httpshared.Delete(f, h.AuditWriter, roleResource, f.ID(), h.Service.GetByID, h.Service.Delete)
}

func (h *Handler) AssignPermissions(ctx *gin.Context) {
	var req dtorole.AssignPermissions
	handleRoleRelationAssignment(h, ctx, &req, roleRelationAssignment[dtorole.AssignPermissions]{
		logPrefix:      "[RoleHandler][AssignPermissions]",
		resource:       "role_permissions",
		beforeDataKey:  "permission_ids",
		failedMessage:  "Failed to assign permissions to role",
		successMessage: "Assigned permissions to role",
		responseMsg:    "Permissions assigned successfully",
		debugMsg:       "Permissions assigned",
		serviceName:    "AssignPermissions",
		getBefore:      h.Service.GetRolePermissions,
		assign: func(ctx context.Context, roleID string, req dtorole.AssignPermissions) error {
			return h.Service.AssignPermissions(ctx, httpshared.ActorFrom(ctx), roleID, req)
		},
	})
}

type roleRelationAssignment[T any] struct {
	logPrefix      string
	resource       string
	beforeDataKey  string
	failedMessage  string
	successMessage string
	responseMsg    string
	debugMsg       string
	serviceName    string
	getBefore      func(context.Context, string) ([]string, error)
	assign         func(context.Context, string, T) error
}

func handleRoleRelationAssignment[T any](h *Handler, ctx *gin.Context, req *T, assignment roleRelationAssignment[T]) {
	id := ctx.Param("id")
	logID := gokit.RequestID(ctx)
	reqCtx := ctx.Request.Context()

	if !gokit.BindJSON(ctx, logID, assignment.logPrefix, req) {
		return
	}

	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", assignment.logPrefix, gokit.JSONEncode(*req))

	beforeIDs, _ := assignment.getBefore(reqCtx, id)
	beforeData := map[string]any{assignment.beforeDataKey: beforeIDs}
	if err := assignment.assign(reqCtx, id, *req); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionAssign,
			Resource:     assignment.resource,
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      assignment.failedMessage,
			ErrorMessage: err.Error(),
			BeforeData:   beforeData,
			AfterData:    *req,
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.%s; Error: %+v", assignment.logPrefix, assignment.serviceName, err)
		statusCode, res := roleMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionAssign,
		Resource:   assignment.resource,
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    assignment.successMessage,
		BeforeData: beforeData,
		AfterData:  *req,
	})

	res := gokit.Response(http.StatusOK, assignment.responseMsg, logID, nil)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; %s", assignment.logPrefix, assignment.debugMsg)
	ctx.JSON(http.StatusOK, res)
}
