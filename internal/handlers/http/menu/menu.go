package menu

import (
	"fmt"
	"net/http"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
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
		AuditWriter: httpshared.NewAuditWriter(auditService, "MenuHandler"),
	}
}

func (h *Handler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, "Menu not found", logId, nil)
		res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "menu not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get menu successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "order_index", "asc", 100)
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

func (h *Handler) GetActiveMenus(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetActiveMenus]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetActiveMenus(reqCtx)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetActiveMenus; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get active menus successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetUserMenus(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetUserMenus]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; User ID not found in context", logPrefix))
		res := gokit.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	data, err := h.Service.GetUserMenus(reqCtx, scope.UserID)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserMenus; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get user menus successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Update(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dtomenu.MenuUpdate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][Update]"
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
			Resource:     "menu",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update menu",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "menu",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated menu",
		BeforeData: before,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, "Menu updated successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}
