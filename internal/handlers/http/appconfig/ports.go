package appconfig

import (
	"context"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	"github.com/zazhedho/gokit"
)

// Service is what the app-config handlers call.
type Service interface {
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainappconfig.AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error)
	Update(ctx context.Context, id string, req dtoappconfig.UpdateAppConfig) (domainappconfig.AppConfig, error)
}
