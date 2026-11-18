package audit

import (
	"fmt"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	Service Service
}

func New(s Service) *Handler {
	return &Handler{Service: s}
}

func (h *Handler) GetAll(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[AuditHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "occurred_at", "desc", 20)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	params.Filters = gokit.WhitelistStringFilter(params.Filters, []string{"actor_user_id", "actor_role", "action", "resource", "status", "request_id"})

	data, total, err := h.Service.GetAll(reqCtx, params)
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
	logPrefix := "[AuditHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetByID(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, "Audit trail not found", logId, nil)
		res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "audit trail not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get audit trail successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}
