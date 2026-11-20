package menu

import (
	"context"
	"fmt"

	"github.com/zazhedho/gokit"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// menuParent is one row of the parent chain: a menu item and its parent.
type menuParent struct {
	ID       string
	ParentID *string
}

// Update saves the item. It locks the menu rows and re-checks the parent chain
// inside the transaction, so two concurrent re-parentings cannot form a loop.
func (r *Repository) Update(ctx context.Context, item domainmenu.Item) error {
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []menuParent
		if err := tx.Model(&domainmenu.Item{}).Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id, parent_id").Find(&rows).Error; err != nil {
			return translateErr(err)
		}
		if createsLoop(item, rows) {
			return fmt.Errorf("%w: that parent would create a loop", domainmenu.ErrInvalidParent)
		}
		return translateErr(gokit.NewRepository[domainmenu.Item](tx).Update(ctx, &item))
	})
}

// createsLoop reports whether saving item with its parent would make its
// parent chain return to itself.
func createsLoop(item domainmenu.Item, rows []menuParent) bool {
	parents := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.ParentID != nil {
			parents[row.ID] = *row.ParentID
		}
	}
	if item.ParentID != nil {
		parents[item.ID] = *item.ParentID
	} else {
		delete(parents, item.ID)
	}
	for current, steps := item.ID, 0; current != ""; steps++ {
		if steps > len(rows)+1 {
			return true
		}
		current = parents[current]
		if current == item.ID {
			return true
		}
	}
	return false
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
