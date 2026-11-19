package permission

import (
	"context"

	"github.com/zazhedho/gokit"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

// Repository stores permission data.
type Repository struct {
	*gokit.Repository[domainpermission.Permission]
}

// NewRepository creates the permission repository on db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainpermission.Permission](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainpermission.ErrNotFound, domainpermission.ErrDuplicate)
}

// Store stores the record.
func (r *Repository) Store(ctx context.Context, permission domainpermission.Permission) error {
	return translateErr(r.Repository.Store(ctx, &permission))
}

// GetByID returns one record found by ID.
func (r *Repository) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

// Update updates the record.
func (r *Repository) Update(ctx context.Context, permission domainpermission.Permission) error {
	return translateErr(r.Repository.Update(ctx, &permission))
}

// Delete deletes the record.
func (r *Repository) Delete(ctx context.Context, id string) error {
	return translateErr(r.Repository.Delete(ctx, id))
}

// GetByName returns one record found by name.
func (r *Repository) GetByName(ctx context.Context, name string) (ret domainpermission.Permission, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

// GetAll returns a page of records.
func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainpermission.Permission, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		MaxLimit:       dtoshared.ReferenceList.MaxLimit,
		AllowAll:       dtoshared.ReferenceList.AllowAll,
		Search:         gokit.BuildSearchFunc("name", "display_name", "description", "resource"),
		AllowedFilters: []string{"id", "name", "display_name", "resource", "action", "created_at", "updated_at"},
		AllowedOrderColumns: []string{
			"name",
			"display_name",
			"resource",
			"action",
			"created_at",
			"updated_at",
		},
	})
}

// GetByResource returns one record found by resource.
func (r *Repository) GetByResource(ctx context.Context, resource string) (ret []domainpermission.Permission, err error) {
	return r.GetManyByField(ctx, "resource", resource, gokit.DefaultMaxLimit, "action asc")
}

// GetUserPermissions returns the user permissions.
func (r *Repository) GetUserPermissions(ctx context.Context, userID string) (ret []domainpermission.Permission, err error) {
	var user struct {
		RoleID *string
		Role   string
	}
	if err = r.DB.WithContext(ctx).Table("users").Select("role_id, role").Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return nil, repositoryshared.Gorm(err, domainuser.ErrNotFound, nil)
	}

	if user.Role == domainuser.RoleSuperAdmin {
		if err = r.DB.WithContext(ctx).Where("deleted_at IS NULL").Order("resource, action").Find(&ret).Error; err != nil {
			return nil, err
		}
		return ret, nil
	}

	if user.RoleID == nil || *user.RoleID == "" {
		return []domainpermission.Permission{}, nil
	}

	query := `
		SELECT DISTINCT p.*
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON r.id = rp.role_id AND r.deleted_at IS NULL
		WHERE rp.role_id = ? AND p.deleted_at IS NULL
		ORDER BY p.resource, p.action
	`
	if err = r.DB.WithContext(ctx).Raw(query, *user.RoleID).Scan(&ret).Error; err != nil {
		return nil, err
	}

	return ret, nil
}

// GetByRoleName returns the live permissions of the live role with that name.
func (r *Repository) GetByRoleName(ctx context.Context, roleName string) (ret []domainpermission.Permission, err error) {
	query := `
		SELECT DISTINCT p.*
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON r.id = rp.role_id AND r.deleted_at IS NULL
		WHERE r.name = ? AND p.deleted_at IS NULL
		ORDER BY p.resource, p.action
	`
	if err = r.DB.WithContext(ctx).Raw(query, roleName).Scan(&ret).Error; err != nil {
		return nil, err
	}
	return ret, nil
}
