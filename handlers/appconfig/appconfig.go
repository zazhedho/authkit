package handlerappconfig

import (
	"errors"
	"fmt"
	domainaudit "github.com/zazhedho/authkit/domain/audit"
	"github.com/zazhedho/authkit/dto"
	"github.com/zazhedho/authkit/handlers/auditwriter"
	interfaceappconfig "github.com/zazhedho/authkit/interfaces/appconfig"
	interfaceaudit "github.com/zazhedho/authkit/interfaces/audit"
	"github.com/zazhedho/gokit/filter"
	"github.com/zazhedho/gokit/handlercommon"
	"github.com/zazhedho/gokit/messages"
	"github.com/zazhedho/gokit/response"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AppConfigHandler struct {
	Service interfaceappconfig.ServiceAppConfigInterface
	auditwriter.AuditWriter
}

func NewAppConfigHandler(s interfaceappconfig.ServiceAppConfigInterface, auditService interfaceaudit.ServiceAuditInterface) *AppConfigHandler {
	return &AppConfigHandler{
		Service:     s,
		AuditWriter: auditwriter.NewAuditWriter(auditService, "AppConfigHandler"),
	}
}

func (h *AppConfigHandler) GetAll(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := filter.GetBaseParams(ctx.Request.URL.Query(), "category", "asc", 50)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	params.Filters = filter.WhitelistStringFilter(params.Filters, []string{"category"})

	data, total, err := h.Service.GetAll(reqCtx, params)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *AppConfigHandler) GetByID(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	id, err := handlercommon.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusNotFound, "Configuration not found", logId, nil)
		res.Error = response.Errors{Code: http.StatusNotFound, Message: "configuration not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := response.Response(http.StatusOK, "Get configuration successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *AppConfigHandler) Update(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][Update]"
	reqCtx := ctx.Request.Context()

	id, err := handlercommon.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	var req dto.UpdateAppConfig
	if !handlercommon.BindJSON(ctx, logId, logPrefix, &req) {
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.NotFound, logId, nil)
			res.Error = "config data not found"
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.InternalServerError(logId)
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

	res := response.Response(http.StatusOK, "Configuration updated successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}
