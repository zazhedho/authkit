package router

import (
	"context"

	"github.com/zazhedho/gokit"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	serviceappconfig "github.com/zazhedho/authkit/internal/services/appconfig"
	serviceaudit "github.com/zazhedho/authkit/internal/services/audit"
)

// The services take a ListRequest so they stay free of gokit, but the public
// AuditService and AppConfigService interfaces take gokit.BaseParams. These
// adapters keep those signatures.

// AuditList is the audit service with the public gokit.BaseParams signature.
type AuditList struct{ *serviceaudit.Service }

// GetAll lists audit entries for params.
func (a AuditList) GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	return a.Service.GetAll(ctx, httpshared.ListRequest(params))
}

// AppConfigList is the app-config service with the public gokit.BaseParams signature.
type AppConfigList struct{ *serviceappconfig.Service }

// GetAll lists app-config entries for params.
func (a AppConfigList) GetAll(ctx context.Context, params gokit.BaseParams) ([]domainappconfig.AppConfig, int64, error) {
	return a.Service.GetAll(ctx, httpshared.ListRequest(params))
}
