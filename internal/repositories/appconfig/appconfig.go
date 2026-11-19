package appconfig

import (
	"context"

	"github.com/zazhedho/gokit"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

// Repository stores appconfig data.
type Repository struct {
	*gokit.Repository[domainappconfig.AppConfig]
}

// NewRepository creates the appconfig repository on db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainappconfig.AppConfig](db)}
}

// GetAll returns a page of records.
func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainappconfig.AppConfig, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		MaxLimit:        dtoshared.PagedList.MaxLimit,
		AllowAll:        dtoshared.PagedList.AllowAll,
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

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainappconfig.ErrNotFound, nil)
}

// GetByID returns one record found by ID.
func (r *Repository) GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

// Update updates the record.
func (r *Repository) Update(ctx context.Context, config domainappconfig.AppConfig) error {
	return translateErr(r.Repository.Update(ctx, &config))
}

// GetByKey returns one record found by key.
func (r *Repository) GetByKey(ctx context.Context, configKey string) (ret domainappconfig.AppConfig, err error) {
	ret, err = r.GetOneByField(ctx, "config_key", configKey)
	return ret, translateErr(err)
}
