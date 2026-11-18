package authkit

import (
	"context"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	serviceappconfig "github.com/zazhedho/authkit/internal/services/appconfig"
	serviceaudit "github.com/zazhedho/authkit/internal/services/audit"
	"github.com/zazhedho/gokit"
)

// The services take a ListRequest so they stay free of gokit, but the public
// AuditService and AppConfigService interfaces take gokit.BaseParams. These
// adapters keep those signatures.

type auditFacade struct{ *serviceaudit.Service }

func (a auditFacade) GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	return a.Service.GetAll(ctx, httpshared.ListRequest(params))
}

type appConfigFacade struct{ *serviceappconfig.Service }

func (a appConfigFacade) GetAll(ctx context.Context, params gokit.BaseParams) ([]domainappconfig.AppConfig, int64, error) {
	return a.Service.GetAll(ctx, httpshared.ListRequest(params))
}
