package menu

import (
	"net/http"

	"github.com/zazhedho/gokit"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
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
		AuditWriter: httpshared.NewAuditWriter(auditService, "MenuHandler"),
	}
}

var menuResource = httpshared.Resource[domainmenu.MenuItem]{
	Name:          "menu",
	Audit:         "menu",
	ID:            func(m domainmenu.MenuItem) string { return m.ID },
	MutationError: httpshared.InternalErrorResponse,
}

func (h *Handler) GetByID(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[MenuHandler][GetByID]")
	httpshared.GetByID(f, "menu", "Service.GetByID", f.ID(), h.Service.GetByID)
}

func (h *Handler) GetAll(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[MenuHandler][GetAll]")
	httpshared.List(f, httpshared.ListOptions{OrderBy: "order_index", Direction: "asc", Limit: 100, Policy: dtoshared.ReferenceList}, h.Service.GetAll)
}

func (h *Handler) GetActiveMenus(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[MenuHandler][GetActiveMenus]")

	data, err := h.Service.GetActiveMenus(f.ReqCtx())
	if err != nil {
		f.LogError("Service.GetActiveMenus", err)
		httpshared.RespondInternalError(ctx, f.LogID)
		return
	}

	res := gokit.Response(http.StatusOK, "Get active menus successfully", f.LogID, data)
	f.LogResponse(data)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetUserMenus(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[MenuHandler][GetUserMenus]")
	httpshared.ForCurrentUser(f, "Service.GetUserMenus", "Get user menus successfully", h.Service.GetUserMenus)
}

func (h *Handler) Update(ctx *gin.Context) {
	f := httpshared.NewFlow(ctx, "[MenuHandler][Update]")
	req, ok := httpshared.Bind[dtomenu.MenuUpdate](f)
	if !ok {
		return
	}
	httpshared.Update(f, h.AuditWriter, menuResource, f.ID(), req, h.Service.GetByID, h.Service.Update)
}
