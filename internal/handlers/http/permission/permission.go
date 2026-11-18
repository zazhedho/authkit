package permission

import (
	"fmt"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
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
		AuditWriter: httpshared.NewAuditWriter(auditService, "PermissionHandler"),
	}
}

func (h *Handler) Create(ctx *gin.Context) {
	var req dtopermission.PermissionCreate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][Create]"
	reqCtx := ctx.Request.Context()

	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(req)))

	data, err := h.Service.Create(reqCtx, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "permission",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create permission",
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Create; Error: %+v", logPrefix, err))
		statusCode, res := permissionMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "permission",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created permission",
		AfterData:  data,
	})

	res := gokit.Response(http.StatusCreated, "Permission created successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, "Permission not found", logId, nil)
		res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "permission not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get permission successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "resource", "asc", 10)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, total, err := h.Service.GetAll(reqCtx, httpshared.ListRequest(params))
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
	var req dtopermission.PermissionUpdate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][Update]"
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
			Resource:     "permission",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update permission",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		statusCode, res := permissionMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "permission",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated permission",
		BeforeData: before,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, "Permission updated successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Delete(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][Delete]"
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetByID(reqCtx, id)

	if err := h.Service.Delete(reqCtx, id); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "permission",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete permission",
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %+v", logPrefix, err))
		statusCode, res := permissionMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "permission",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted permission",
		BeforeData: before,
	})

	res := gokit.Response(http.StatusOK, "Permission deleted successfully", logId, nil)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: Permission deleted", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetUserPermissions(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[PermissionHandler][GetUserPermissions]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; User ID not found in context", logPrefix))
		res := gokit.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	data, err := h.Service.GetUserPermissions(reqCtx, scope.UserID)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserPermissions; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get user permissions successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}
