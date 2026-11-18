package appconfig

import (
	"context"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	"github.com/zazhedho/gokit"
)

// Repository is the persistence the service needs.
type Repository interface {
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainappconfig.AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error)
	GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error)
	Update(ctx context.Context, data domainappconfig.AppConfig) error
}
