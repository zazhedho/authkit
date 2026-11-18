package audit

import (
	"context"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainaudit.AuditTrail]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainaudit.AuditTrail](db)}
}

func (r *Repository) GetAll(ctx context.Context, params gokit.BaseParams) (ret []domainaudit.AuditTrail, totalData int64, err error) {
	return r.Repository.GetAll(ctx, params, gokit.QueryOptions{
		Search:         gokit.BuildSearchFunc("action", "resource", "status", "actor_role", "message", "error_message", "request_id", "ip_address"),
		AllowedFilters: []string{"actor_user_id", "actor_role", "action", "resource", "status", "request_id"},
		AllowedOrderColumns: []string{
			"occurred_at",
			"created_at",
			"action",
			"resource",
			"status",
			"actor_role",
		},
		DefaultOrders: []string{"occurred_at DESC", "created_at DESC"},
	})
}
