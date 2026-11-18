package appconfig

import (
	"errors"
	"fmt"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
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
		AuditWriter: httpshared.NewAuditWriter(auditService, "AppConfigHandler"),
	}
}

func (h *Handler) GetAll(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "category", "asc", 50)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	params.Filters = gokit.WhitelistStringFilter(params.Filters, []string{"category"})

	data, total, err := h.Service.GetAll(reqCtx, httpshared.ListRequest[dtoappconfig.ListRequest](params))
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, "Configuration not found", logId, nil)
		res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "configuration not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get configuration successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Update(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][Update]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}

	var req dtoappconfig.UpdateAppConfig
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	before, _ := h.Service.GetByID(reqCtx, id)
	data, err := h.Service.Update(reqCtx, id, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "config",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update configuration",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})

		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		if errors.Is(err, domainappconfig.ErrNotFound) {
			res := gokit.Response(http.StatusNotFound, gokit.MsgResourceNotFound, logId, nil)
			res.Error = "config data not found"
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "config",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated configuration",
		BeforeData: before,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, "Configuration updated successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}
