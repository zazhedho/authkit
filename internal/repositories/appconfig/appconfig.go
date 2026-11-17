package repositoryappconfig

import (
	"context"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	interfaceappconfig "github.com/zazhedho/authkit/internal/interfaces/appconfig"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type repo struct {
	*gokit.Repository[domainappconfig.AppConfig]
}

func NewAppConfigRepo(db *gorm.DB) interfaceappconfig.RepoAppConfigInterface {
	return &repo{Repository: gokit.NewRepository[domainappconfig.AppConfig](db)}
}

func (r *repo) GetAll(ctx context.Context, params gokit.BaseParams) (ret []domainappconfig.AppConfig, totalData int64, err error) {
	return r.Repository.GetAll(ctx, params, gokit.QueryOptions{
		Search:          gokit.BuildSearchFunc("config_key", "display_name", "category"),
		AllowedFilters:  []string{"category", "is_active"},
		FilterSanitizer: gokit.WhitelistStringFilter,
		AllowedOrderColumns: []string{
			"config_key",
			"display_name",
			"category",
			"is_active",
			"created_at",
			"updated_at",
		},
		DefaultOrders: []string{"category ASC", "display_name ASC"},
	})
}

func (r *repo) GetByKey(ctx context.Context, configKey string) (ret domainappconfig.AppConfig, err error) {
	return r.GetOneByField(ctx, "config_key", configKey)
}
