package audit

import (
	"context"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
)

// Repository is the persistence the service needs.
type Repository interface {
	Store(ctx context.Context, data domainaudit.AuditTrail) error
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainaudit.AuditTrail, int64, error)
	GetByID(ctx context.Context, id string) (domainaudit.AuditTrail, error)
}
