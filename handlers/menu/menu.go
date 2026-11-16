package handlermenu

import (
	"fmt"
	"github.com/zazhedho/authkit/authscope"
	domainaudit "github.com/zazhedho/authkit/domain/audit"
	"github.com/zazhedho/authkit/dto"
	"github.com/zazhedho/authkit/handlers/auditwriter"
	interfaceaudit "github.com/zazhedho/authkit/interfaces/audit"
	interfacemenu "github.com/zazhedho/authkit/interfaces/menu"
	"github.com/zazhedho/gokit/filter"
	"github.com/zazhedho/gokit/handlercommon"
	"github.com/zazhedho/gokit/messages"
	"github.com/zazhedho/gokit/response"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"net/http"

	"github.com/gin-gonic/gin"
)

type MenuHandler struct {
	Service interfacemenu.ServiceMenuInterface
	auditwriter.AuditWriter
}

func NewMenuHandler(s interfacemenu.ServiceMenuInterface, auditService interfaceaudit.ServiceAuditInterface) *MenuHandler {
	return &MenuHandler{
		Service:     s,
		AuditWriter: auditwriter.NewAuditWriter(auditService, "MenuHandler"),
	}
}

func (h *MenuHandler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusNotFound, "Menu not found", logId, nil)
		res.Error = response.Errors{Code: http.StatusNotFound, Message: "menu not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := response.Response(http.StatusOK, "Get menu successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *MenuHandler) GetAll(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := filter.GetBaseParams(ctx.Request.URL.Query(), "order_index", "asc", 100)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, total, err := h.Service.GetAll(reqCtx, params)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *MenuHandler) GetActiveMenus(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetActiveMenus]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetActiveMenus(reqCtx)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetActiveMenus; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get active menus successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *MenuHandler) GetUserMenus(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][GetUserMenus]"
	reqCtx := ctx.Request.Context()

	scope := authscope.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; User ID not found in context", logPrefix))
		res := response.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	data, err := h.Service.GetUserMenus(reqCtx, scope.UserID)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserMenus; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get user menus successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *MenuHandler) Update(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dto.MenuUpdate
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[MenuHandler][Update]"
	reqCtx := ctx.Request.Context()

	if !handlercommon.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

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
		res := response.InternalServerError(logId)
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

	res := response.Response(http.StatusOK, "Menu updated successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}
