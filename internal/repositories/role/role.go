package role

import (
	"context"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainrole.Role]
}

const roleIDFilter = "role_id = ?"

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainrole.Role](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainrole.ErrNotFound, domainrole.ErrDuplicate)
}

func (r *Repository) Store(ctx context.Context, role domainrole.Role) error {
	return translateErr(r.Repository.Store(ctx, role))
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

func (r *Repository) Update(ctx context.Context, role domainrole.Role) error {
	return translateErr(r.Repository.Update(ctx, role))
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	return translateErr(r.Repository.Delete(ctx, id))
}

func (r *Repository) GetByName(ctx context.Context, name string) (ret domainrole.Role, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

func (r *Repository) GetAll(ctx context.Context, req dtorole.ListRequest) (ret []domainrole.Role, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		Search:         gokit.BuildSearchFunc("name", "display_name", "description"),
		AllowedFilters: []string{"id", "name", "display_name", "is_system", "created_at", "updated_at"},
		AllowedOrderColumns: []string{
			"name",
			"display_name",
			"is_system",
			"created_at",
			"updated_at",
		},
	})
}

func (r *Repository) AssignPermissions(ctx context.Context, roleId string, permissionIds []string) error {
	tx := r.DB.WithContext(ctx).Begin()
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Where(roleIDFilter, roleId).Delete(&domainrole.RolePermission{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	for _, permissionId := range permissionIds {
		rolePermission := domainrole.RolePermission{
			Id:           gokit.CreateUUID(),
			RoleId:       roleId,
			PermissionId: permissionId,
		}
		if err := tx.Create(&rolePermission).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (r *Repository) RemovePermissions(ctx context.Context, roleId string, permissionIds []string) error {
	return r.DB.WithContext(ctx).Where("role_id = ? AND permission_id IN ?", roleId, permissionIds).Delete(&domainrole.RolePermission{}).Error
}

func (r *Repository) GetRolePermissions(ctx context.Context, roleId string) ([]string, error) {
	var rolePermissions []domainrole.RolePermission
	if err := r.DB.WithContext(ctx).Where(roleIDFilter, roleId).Find(&rolePermissions).Error; err != nil {
		return nil, err
	}

	permissionIds := make([]string, len(rolePermissions))
	for i, rp := range rolePermissions {
		permissionIds[i] = rp.PermissionId
	}

	return permissionIds, nil
}

func (r *Repository) AssignMenus(ctx context.Context, roleId string, menuIds []string) error {
	tx := r.DB.WithContext(ctx).Begin()
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Where(roleIDFilter, roleId).Delete(&domainrole.RoleMenu{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	for _, menuId := range menuIds {
		roleMenu := domainrole.RoleMenu{
			Id:         gokit.CreateUUID(),
			RoleId:     roleId,
			MenuItemId: menuId,
		}
		if err := tx.Create(&roleMenu).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (r *Repository) RemoveMenus(ctx context.Context, roleId string, menuIds []string) error {
	return r.DB.WithContext(ctx).Where("role_id = ? AND menu_item_id IN ?", roleId, menuIds).Delete(&domainrole.RoleMenu{}).Error
}

func (r *Repository) GetRoleMenus(ctx context.Context, roleId string) ([]string, error) {
	var roleMenus []domainrole.RoleMenu
	if err := r.DB.WithContext(ctx).Where(roleIDFilter, roleId).Find(&roleMenus).Error; err != nil {
		return nil, err
	}

	menuIds := make([]string, len(roleMenus))
	for i, rm := range roleMenus {
		menuIds[i] = rm.MenuItemId
	}

	return menuIds, nil
}
