package user

import (
	"context"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainuser.Users]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainuser.Users](db)}
}

func (r *Repository) Store(ctx context.Context, user domainuser.Users) error {
	if user.Phone == "" {
		return r.DB.WithContext(ctx).Omit("phone").Create(&user).Error
	}
	return r.Repository.Store(ctx, user)
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (ret domainuser.Users, err error) {
	return r.GetOneByField(ctx, "email", email)
}

func (r *Repository) GetByPhone(ctx context.Context, phone string) (ret domainuser.Users, err error) {
	return r.GetOneByField(ctx, "phone", phone)
}

func (r *Repository) GetAll(ctx context.Context, params gokit.BaseParams) (ret []domainuser.Users, totalData int64, err error) {
	return r.Repository.GetAll(ctx, params, gokit.QueryOptions{
		Search:         gokit.BuildSearchFunc("name", "email", "phone"),
		AllowedFilters: []string{"id", "name", "email", "phone", "role", "role_id", "created_at", "updated_at"},
		AllowedOrderColumns: []string{
			"name",
			"email",
			"phone",
			"role",
			"last_login_at",
			"login_provider",
			"created_at",
			"updated_at",
		},
	})
}
