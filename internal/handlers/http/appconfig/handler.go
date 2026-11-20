package appconfig

import (
	"errors"
	"net/http"

	"github.com/zazhedho/gokit"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

var configResource = httpshared.Resource[domainappconfig.AppConfig]{
	Name:          "configuration",
	Audit:         "config",
	ID:            func(c domainappconfig.AppConfig) string { return c.ID },
	MutationError: configMutationErrorResponse,
}

func configMutationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	if errors.Is(err, domainappconfig.ErrNotFound) {
		res := gokit.ErrorResponse(http.StatusNotFound, gokit.MsgResourceNotFound, logID, "config data not found")
		return http.StatusNotFound, res
	}
	if errors.Is(err, domainappconfig.ErrInvalidValue) {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error())
		return http.StatusBadRequest, res
	}
	return httpshared.InternalErrorResponse(logID, err)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewQuietFlow(ctx, "[AppConfigHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{
		OrderBy: "category", Direction: "asc", Limit: 50, FilterKeys: []string{"category"},
	}, h.Service.GetAll)
}

func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewQuietFlow(ctx, "[AppConfigHandler][GetByID]")
	id, ok := f.UUIDParam()
	if !ok {
		return
	}
	httpshared.GetByID(f, "configuration", "Service.GetByID", id, h.Service.GetByID)
}

func (h *Handler) Update(ctx *gin.Context) {
	f := httpshared.NewQuietFlow(ctx, "[AppConfigHandler][Update]")
	id, ok := f.UUIDParam()
	if !ok {
		return
	}
	req, ok := httpshared.Bind[dtoappconfig.UpdateAppConfig](f)
	if !ok {
		return
	}
	httpshared.Update(f, h.AuditWriter, configResource, id, req, h.Service.GetByID, h.Service.Update)
}
