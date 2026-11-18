package audit

import (
	"context"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/gokit"
)

// Repository is the persistence the service needs.
type Repository interface {
	Store(ctx context.Context, data domainaudit.AuditTrail) error
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainaudit.AuditTrail, int64, error)
	GetByID(ctx context.Context, id string) (domainaudit.AuditTrail, error)
}
