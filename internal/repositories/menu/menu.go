package menu

import (
	"context"
	"sort"

	"github.com/zazhedho/gokit"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

// Repository stores menu data.
type Repository struct {
	*gokit.Repository[domainmenu.Item]
}

// NewRepository creates the menu repository on db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainmenu.Item](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainmenu.ErrNotFound, nil)
}

// GetByID returns one record found by ID.
func (r *Repository) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

// Update updates the record.
func (r *Repository) Update(ctx context.Context, item domainmenu.Item) error {
	return translateErr(r.Repository.Update(ctx, &item))
}

// GetByName returns one record found by name.
func (r *Repository) GetByName(ctx context.Context, name string) (ret domainmenu.Item, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

// GetAll returns a page of records.
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

// GetActiveMenus returns the active menus.
func (r *Repository) GetActiveMenus(ctx context.Context) (ret []domainmenu.Item, err error) {
	if err = r.DB.WithContext(ctx).Where("is_active = ?", true).Order("order_index ASC").Find(&ret).Error; err != nil {
		return nil, err
	}
	return ret, nil
}

// GetUserMenus returns the user menus.
func (r *Repository) GetUserMenus(ctx context.Context, userID string) (ret []domainmenu.Item, err error) {
	var user struct {
		RoleID *string
		Role   string
	}
	if err = r.DB.WithContext(ctx).Table("users").Select("role_id, role").Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, repositoryshared.Gorm(err, domainuser.ErrNotFound, nil)
	}

	if user.Role == domainuser.RoleSuperAdmin {
		return r.GetActiveMenus(ctx)
	}

	if user.RoleID == nil || *user.RoleID == "" {
		return []domainmenu.Item{}, nil
	}

	query := `
		SELECT DISTINCT m.*
		FROM menu_items m
		INNER JOIN permissions p ON p.resource = m.name
		INNER JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = ?
		  AND m.is_active = true
		  AND m.deleted_at IS NULL
		  AND p.deleted_at IS NULL
		ORDER BY m.order_index ASC
	`
	if err = r.DB.WithContext(ctx).Raw(query, *user.RoleID).Scan(&ret).Error; err != nil {
		return nil, err
	}

	ret, err = r.includeActiveParents(ctx, ret)
	if err != nil {
		return nil, err
	}

	sort.SliceStable(ret, func(i, j int) bool {
		if ret[i].OrderIndex == ret[j].OrderIndex {
			return ret[i].DisplayName < ret[j].DisplayName
		}
		return ret[i].OrderIndex < ret[j].OrderIndex
	})

	return ret, nil
}

func (r *Repository) includeActiveParents(ctx context.Context, menus []domainmenu.Item) ([]domainmenu.Item, error) {
	menuByID := make(map[string]domainmenu.Item, len(menus))
	pendingParentIDs := collectMenuParentIDs(menus, menuByID)
	for len(pendingParentIDs) > 0 {
		var parents []domainmenu.Item
		if err := r.DB.WithContext(ctx).
			Where("id IN ? AND is_active = ? AND deleted_at IS NULL", pendingParentIDs, true).
			Find(&parents).Error; err != nil {
			return nil, err
		}
		pendingParentIDs = appendActiveMenuParents(parents, menuByID, &menus)
	}
	return menus, nil
}

func collectMenuParentIDs(menus []domainmenu.Item, menuByID map[string]domainmenu.Item) []string {
	parentIDs := make([]string, 0)
	for _, menu := range menus {
		menuByID[menu.ID] = menu
		if menu.ParentID != nil && *menu.ParentID != "" {
			if _, exists := menuByID[*menu.ParentID]; !exists {
				parentIDs = append(parentIDs, *menu.ParentID)
			}
		}
	}
	return parentIDs
}

func appendActiveMenuParents(parents []domainmenu.Item, menuByID map[string]domainmenu.Item, menus *[]domainmenu.Item) []string {
	nextParentIDs := make([]string, 0)
	for _, menu := range parents {
		if _, exists := menuByID[menu.ID]; exists {
			continue
		}
		menuByID[menu.ID] = menu
		*menus = append(*menus, menu)
		if menu.ParentID != nil && *menu.ParentID != "" {
			if _, exists := menuByID[*menu.ParentID]; !exists {
				nextParentIDs = append(nextParentIDs, *menu.ParentID)
			}
		}
	}
	return nextParentIDs
}
