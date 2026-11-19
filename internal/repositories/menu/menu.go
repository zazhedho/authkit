package menu

import (
	"context"

	"github.com/zazhedho/gokit"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainmenu.Item]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainmenu.Item](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainmenu.ErrNotFound, nil)
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

func (r *Repository) Update(ctx context.Context, item domainmenu.Item) error {
	return translateErr(r.Repository.Update(ctx, &item))
}

func (r *Repository) GetByName(ctx context.Context, name string) (ret domainmenu.Item, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainmenu.Item, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		MaxLimit:       dtoshared.ReferenceList.MaxLimit,
		AllowAll:       dtoshared.ReferenceList.AllowAll,
		Search:         gokit.BuildSearchFunc("name", "display_name", "path"),
		AllowedFilters: []string{"id", "name", "display_name", "path", "parent_id", "order_index", "is_active", "created_at", "updated_at"},
		AllowedOrderColumns: []string{
			"name",
			"display_name",
			"path",
			"order_index",
			"created_at",
			"updated_at",
		},
	})
}

func (r *Repository) GetActiveMenus(ctx context.Context) (ret []domainmenu.Item, err error) {
	if err = r.DB.WithContext(ctx).Where("is_active = ?", true).Order("order_index ASC").Find(&ret).Error; err != nil {
		return nil, err
	}
	return ret, nil
}
