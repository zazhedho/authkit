package audit

import (
	"context"

	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
)

// Service is what the audit handlers call.
type Service interface {
	GetAll(ctx context.Context, req dtoaudit.ListRequest) ([]dtoaudit.AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error)
}
