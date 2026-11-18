package audit

import (
	"context"

	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	"github.com/zazhedho/gokit"
)

// Service is what the audit handlers call.
type Service interface {
	GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error)
}
