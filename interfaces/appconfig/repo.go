package interfaceappconfig

import (
	"context"
	domainappconfig "github.com/zazhedho/authkit/domain/appconfig"
	interfacegeneric "github.com/zazhedho/gokit/repository"
)

type RepoAppConfigInterface interface {
	interfacegeneric.GenericRepository[domainappconfig.AppConfig]

	GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error)
}
