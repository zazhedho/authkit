package audit

import (
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
)

// Handler serves the audit HTTP endpoints.
type Handler struct {
	Service Service
}

// New creates the audit handler.
func New(s Service) *Handler {
	return &Handler{Service: s}
}

// GetAll handles the get all request.
func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewQuietFlow(ctx, "[AuditHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{
		OrderBy: "occurred_at", Direction: "desc", Limit: 20,
		FilterKeys: []string{"actor_user_id", "actor_role", "action", "resource", "status", "request_id"},
	}, h.Service.GetAll)
}

// GetByID handles the get by ID request.
func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewQuietFlow(ctx, "[AuditHandler][GetByID]")
	id, ok := f.UUIDParam()
	if !ok {
		return
	}
	httpshared.GetByID(f, "audit trail", "Service.GetByID", id, h.Service.GetByID)
}
