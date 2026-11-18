package audit

import (
	"context"

	"github.com/zazhedho/gokit"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainaudit.AuditTrail]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainaudit.AuditTrail](db)}
}

func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainaudit.AuditTrail, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
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

func (r *Repository) GetByID(ctx context.Context, id string) (domainaudit.AuditTrail, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, repositoryshared.Gorm(err, domainaudit.ErrNotFound, nil)
}
