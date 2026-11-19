package role

import (
	"context"

	"github.com/zazhedho/gokit"

	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

// Repository stores role data.
type Repository struct {
	*gokit.Repository[domainrole.Role]
}

const roleIDFilter = "role_id = ?"

// NewRepository creates the role repository on db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainrole.Role](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainrole.ErrNotFound, domainrole.ErrDuplicate)
}

// Store stores the record.
func (r *Repository) Store(ctx context.Context, role domainrole.Role) error {
	return translateErr(r.Repository.Store(ctx, &role))
}

// GetByID returns one record found by ID.
func (r *Repository) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

// Update updates the record.
func (r *Repository) Update(ctx context.Context, role domainrole.Role) error {
	return translateErr(r.Repository.Update(ctx, &role))
}

// Delete deletes the record.
func (r *Repository) Delete(ctx context.Context, id string) error {
	return translateErr(r.Repository.Delete(ctx, id))
}

// GetByName returns one record found by name.
func (r *Repository) GetByName(ctx context.Context, name string) (ret domainrole.Role, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

// GetAll returns a page of records.
func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainrole.Role, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		MaxLimit:       dtoshared.ReferenceList.MaxLimit,
		AllowAll:       dtoshared.ReferenceList.AllowAll,
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

// AssignPermissions assigns the permissions.
func (r *Repository) AssignPermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(roleIDFilter, roleID).Delete(&domainrole.Permission{}).Error; err != nil {
			return err
		}
		for _, permissionID := range permissionIDs {
			rolePermission := domainrole.Permission{
				ID:           gokit.CreateUUID(),
				RoleID:       roleID,
				PermissionID: permissionID,
			}
			if err := tx.Create(&rolePermission).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// CountUsers counts the live users that hold the role.
func (r *Repository) CountUsers(ctx context.Context, roleID string) (int64, error) {
	var n int64
	err := r.DB.WithContext(ctx).Table("users").Where("role_id = ? AND deleted_at IS NULL", roleID).Count(&n).Error
	return n, err
}

// GetRolePermissions returns the role permissions.
func (r *Repository) GetRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	var rolePermissions []domainrole.Permission
	if err := r.DB.WithContext(ctx).Where(roleIDFilter, roleID).Find(&rolePermissions).Error; err != nil {
		return nil, err
	}

	permissionIDs := make([]string, len(rolePermissions))
	for i, rp := range rolePermissions {
		permissionIDs[i] = rp.PermissionID
	}

	return permissionIDs, nil
}
