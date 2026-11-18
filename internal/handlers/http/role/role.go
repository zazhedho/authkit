package role

import (
	"context"
	"fmt"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	"net/http"

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

func (h *Handler) Create(ctx *gin.Context) {
	var req dtorole.RoleCreate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Create]"
	reqCtx := ctx.Request.Context()

	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(req)))

	data, err := h.Service.Create(reqCtx, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "role",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create role",
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Create; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "role",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created role",
		AfterData:  data,
	})

	res := gokit.Response(http.StatusCreated, "Role created successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetByIDWithDetails(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByIDWithDetails; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, "Role not found", logId, nil)
		res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "role not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get role successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "name", "asc", 10)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, total, err := h.Service.GetAll(reqCtx, params)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Update(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dtorole.RoleUpdate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Update]"
	reqCtx := ctx.Request.Context()

	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(req)))

	before, _ := h.Service.GetByID(reqCtx, id)
	data, err := h.Service.Update(reqCtx, id, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "role",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update role",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "role",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated role",
		BeforeData: before,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, "Role updated successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Delete(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Delete]"
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetByID(reqCtx, id)

	if err := h.Service.Delete(reqCtx, id); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "role",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete role",
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "role",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted role",
		BeforeData: before,
	})

	res := gokit.Response(http.StatusOK, "Role deleted successfully", logId, nil)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: Role deleted", logPrefix))
	ctx.JSON(http.StatusOK, res)
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
		assign:         h.Service.AssignPermissions,
	})
}

func (h *Handler) AssignMenus(ctx *gin.Context) {
	var req dtorole.AssignMenus
	handleRoleRelationAssignment(h, ctx, &req, roleRelationAssignment[dtorole.AssignMenus]{
		logPrefix:      "[RoleHandler][AssignMenus]",
		resource:       "role_menus",
		beforeDataKey:  "menu_ids",
		failedMessage:  "Failed to assign menus to role",
		successMessage: "Assigned menus to role",
		responseMsg:    "Menus assigned successfully",
		debugMsg:       "Menus assigned",
		serviceName:    "AssignMenus",
		getBefore:      h.Service.GetRoleMenus,
		assign:         h.Service.AssignMenus,
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
	logId := gokit.GenerateLogId(ctx)
	reqCtx := ctx.Request.Context()

	if !gokit.BindJSON(ctx, logId, assignment.logPrefix, req) {
		return
	}

	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", assignment.logPrefix, gokit.JsonEncode(*req)))

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
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.%s; Error: %+v", assignment.logPrefix, assignment.serviceName, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
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

	res := gokit.Response(http.StatusOK, assignment.responseMsg, logId, nil)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; %s", assignment.logPrefix, assignment.debugMsg))
	ctx.JSON(http.StatusOK, res)
}
