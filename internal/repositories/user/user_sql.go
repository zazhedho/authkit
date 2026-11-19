package user

import (
	"context"
	"fmt"
	"time"

	"github.com/zazhedho/gokit"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

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
	return translateErr(r.Repository.Store(ctx, &user))
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainuser.Users, error) {
	ret, err := r.Repository.GetByID(ctx, id)
	return ret, translateErr(err)
}

// editableColumns are the columns an edit may write; everything else (login
// bookkeeping, tokens_valid_after, the password) has its own targeted update.
var editableColumns = []string{"name", "email", "phone", "role", "role_id", "email_verified_at", "phone_verified_at", "password", "password_changed_at", "avatar_url", "updated_at"}

// Update writes the editable columns of user and nothing else, so a concurrent
// login or token revocation is not overwritten.
func (r *Repository) Update(ctx context.Context, user domainuser.Users) error {
	user.UpdatedAt = new(time.Now())
	res := r.DB.WithContext(ctx).Model(&domainuser.Users{}).Where("id = ?", user.ID).Select(editableColumns).Updates(&user)
	if res.Error != nil {
		return translateErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domainuser.ErrNotFound
	}
	return nil
}

// updatableFields are the columns UpdateFields accepts.
var updatableFields = map[string]struct{}{
	"tokens_valid_after":    {},
	"last_login_at":         {},
	"last_login_ip":         {},
	"last_login_user_agent": {},
	"login_provider":        {},
	"google_subject":        {},
	"password":              {},
	"password_changed_at":   {},
	"email_verified_at":     {},
	"avatar_url":            {},
	"metadata":              {},
}

// UpdateFields writes only the named columns of a live user.
func (r *Repository) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	for column := range fields {
		if _, ok := updatableFields[column]; !ok {
			return fmt.Errorf("user: column %q cannot be updated", column)
		}
	}
	res := r.DB.WithContext(ctx).Model(&domainuser.Users{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return translateErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domainuser.ErrNotFound
	}
	return nil
}

// GetByGoogleSubject returns the live user linked to a Google "sub".
func (r *Repository) GetByGoogleSubject(ctx context.Context, subject string) (domainuser.Users, error) {
	var ret domainuser.Users
	err := r.DB.WithContext(ctx).Where("google_subject = ?", subject).First(&ret).Error
	return ret, translateErr(err)
}

// CountByRole counts the live users holding the role.
func (r *Repository) CountByRole(ctx context.Context, role string) (int64, error) {
	var n int64
	err := r.DB.WithContext(ctx).Model(&domainuser.Users{}).Where("role = ?", role).Count(&n).Error
	return n, translateErr(err)
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

func (r *Repository) GetAll(ctx context.Context, req dtoshared.ListRequest) (ret []domainuser.Users, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		MaxLimit:       dtoshared.PagedList.MaxLimit,
		AllowAll:       dtoshared.PagedList.AllowAll,
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

// GetAuthState returns the role and token cut-off of a live user.
func (r *Repository) GetAuthState(ctx context.Context, id string) (domainuser.AuthState, error) {
	var row struct {
		Role             string
		TokensValidAfter *time.Time
	}
	err := r.DB.WithContext(ctx).Table("users").Select("role, tokens_valid_after").
		Where("id = ? AND deleted_at IS NULL", id).First(&row).Error
	if err != nil {
		return domainuser.AuthState{}, translateErr(err)
	}
	return domainuser.AuthState{Role: row.Role, TokensValidAfter: row.TokensValidAfter}, nil
}
