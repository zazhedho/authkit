package audit

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
)

type Service interface {
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]dtoaudit.AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error)
}
