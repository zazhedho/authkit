package shared

import (
	"context"

	"github.com/zazhedho/gokit"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
)

// AuditService is what an AuditWriter stores events through. Its method set
// matches authkit.AuditService on purpose: AuditWriter.Service is public API,
// so narrowing it would break callers that read the field.
type AuditService interface {
	Store(ctx context.Context, req domainaudit.AuditEvent) error
	GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error)
}
