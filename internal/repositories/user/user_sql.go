package user

import (
	"context"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	interfaceuser "github.com/zazhedho/authkit/internal/interfaces/user"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type repo struct {
	*gokit.Repository[domainuser.Users]
}

func NewUserRepo(db *gorm.DB) interfaceuser.RepoUserInterface {
	return &repo{Repository: gokit.NewRepository[domainuser.Users](db)}
}

func (r *repo) Store(ctx context.Context, user domainuser.Users) error {
	if user.Phone == "" {
		return r.DB.WithContext(ctx).Omit("phone").Create(&user).Error
	}
	return r.Repository.Store(ctx, user)
}

func (r *repo) GetByEmail(ctx context.Context, email string) (ret domainuser.Users, err error) {
	return r.GetOneByField(ctx, "email", email)
}

func (r *repo) GetByPhone(ctx context.Context, phone string) (ret domainuser.Users, err error) {
	return r.GetOneByField(ctx, "phone", phone)
}

func (r *repo) GetAll(ctx context.Context, params gokit.BaseParams) (ret []domainuser.Users, totalData int64, err error) {
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
