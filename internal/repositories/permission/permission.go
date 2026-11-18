package permission

import (
	"context"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainpermission.Permission]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainpermission.Permission](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainpermission.ErrNotFound, domainpermission.ErrDuplicate)
}

func (r *Repository) Store(ctx context.Context, permission domainpermission.Permission) error {
	return translateErr(r.Repository.Store(ctx, permission))
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

func (r *Repository) Update(ctx context.Context, permission domainpermission.Permission) error {
	return translateErr(r.Repository.Update(ctx, permission))
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	return translateErr(r.Repository.Delete(ctx, id))
}

func (r *Repository) GetByName(ctx context.Context, name string) (ret domainpermission.Permission, err error) {
	ret, err = r.GetOneByField(ctx, "name", name)
	return ret, translateErr(err)
}

func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainpermission.Permission, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
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

func (r *Repository) GetByResource(ctx context.Context, resource string) (ret []domainpermission.Permission, err error) {
	return r.GetManyByField(ctx, "resource", resource)
}

func (r *Repository) GetUserPermissions(ctx context.Context, userId string) (ret []domainpermission.Permission, err error) {
	var user struct {
		RoleId *string
		Role   string
	}
	if err = r.DB.WithContext(ctx).Table("users").Select("role_id, role").Where("id = ?", userId).First(&user).Error; err != nil {
		return nil, repositoryshared.Gorm(err, domainuser.ErrNotFound, nil)
	}

	if user.Role == domainuser.RoleSuperAdmin {
		if err = r.DB.WithContext(ctx).Where("deleted_at IS NULL").Order("resource, action").Find(&ret).Error; err != nil {
			return nil, err
		}
		return ret, nil
	}

	if user.RoleId == nil || *user.RoleId == "" {
		return []domainpermission.Permission{}, nil
	}

	query := `
		SELECT DISTINCT p.*
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ? AND p.deleted_at IS NULL
		ORDER BY p.resource, p.action
	`
	if err = r.DB.WithContext(ctx).Raw(query, *user.RoleId).Scan(&ret).Error; err != nil {
		return nil, err
	}

	return ret, nil
}
