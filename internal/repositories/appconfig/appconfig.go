package appconfig

import (
	"context"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainappconfig.AppConfig]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainappconfig.AppConfig](db)}
}

func (r *Repository) GetAll(ctx context.Context, params gokit.BaseParams) (ret []domainappconfig.AppConfig, totalData int64, err error) {
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

func (r *Repository) GetByKey(ctx context.Context, configKey string) (ret domainappconfig.AppConfig, err error) {
	return r.GetOneByField(ctx, "config_key", configKey)
}
