package appconfig

import (
	"context"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
)

// Repository is the persistence the service needs.
type Repository interface {
	GetAll(ctx context.Context, req dtoappconfig.ListRequest) ([]domainappconfig.AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error)
	GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error)
	Update(ctx context.Context, data domainappconfig.AppConfig) error
}
