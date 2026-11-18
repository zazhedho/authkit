package appconfig

import (
	"context"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
)

type Repository interface {
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainappconfig.AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error)
	GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error)
	Update(ctx context.Context, data domainappconfig.AppConfig) error
}
