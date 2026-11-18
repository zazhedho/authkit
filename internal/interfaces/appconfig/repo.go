package appconfig

import (
	"context"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	"github.com/zazhedho/gokit"
)

type RepoAppConfigInterface interface {
	gokit.CRUDRepository[domainappconfig.AppConfig]

	GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error)
}
