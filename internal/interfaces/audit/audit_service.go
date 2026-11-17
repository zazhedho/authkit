package interfaceaudit

import (
	"context"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/authkit/internal/dto"
	"github.com/zazhedho/gokit"
)

type ServiceAuditInterface interface {
	Store(ctx context.Context, req domainaudit.AuditEvent) error
	GetAll(ctx context.Context, params gokit.BaseParams) ([]dto.AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (dto.AuditTrailResponse, error)
}
