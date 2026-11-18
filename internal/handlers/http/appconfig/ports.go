package appconfig

import (
	"context"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
)

type Service interface {
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainappconfig.AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error)
	Update(ctx context.Context, id string, req dtoappconfig.UpdateAppConfig) (domainappconfig.AppConfig, error)
}
