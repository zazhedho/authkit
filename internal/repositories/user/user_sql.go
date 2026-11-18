package user

import (
	"context"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"
	"github.com/zazhedho/gokit"

	"gorm.io/gorm"
)

type Repository struct {
	*gokit.Repository[domainuser.Users]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainuser.Users](db)}
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainuser.ErrNotFound, domainuser.ErrDuplicate)
}

func (r *Repository) Store(ctx context.Context, user domainuser.Users) error {
	if user.Phone == "" {
		return translateErr(r.DB.WithContext(ctx).Omit("phone").Create(&user).Error)
	}
	return translateErr(r.Repository.Store(ctx, user))
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainuser.Users, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

func (r *Repository) Update(ctx context.Context, user domainuser.Users) error {
	return translateErr(r.Repository.Update(ctx, user))
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	return translateErr(r.Repository.Delete(ctx, id))
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (ret domainuser.Users, err error) {
	ret, err = r.GetOneByField(ctx, "email", email)
	return ret, translateErr(err)
}

func (r *Repository) GetByPhone(ctx context.Context, phone string) (ret domainuser.Users, err error) {
	ret, err = r.GetOneByField(ctx, "phone", phone)
	return ret, translateErr(err)
}

func (r *Repository) GetAll(ctx context.Context, req dtouser.ListRequest) (ret []domainuser.Users, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
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
