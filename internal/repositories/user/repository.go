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
	"gorm.io/gorm/clause"
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

// updatableFields are the columns UpdateFields accepts. tokens_valid_after is
// not among them: only UpdateFieldsRevoking writes it, with the database clock.
var updatableFields = map[string]struct{}{
	"name":                  {},
	"email":                 {},
	"phone":                 {},
	"role":                  {},
	"role_id":               {},
	"email_verified_at":     {},
	"phone_verified_at":     {},
	"password":              {},
	"password_changed_at":   {},
	"avatar_url":            {},
	"last_login_at":         {},
	"last_login_ip":         {},
	"last_login_user_agent": {},
	"login_provider":        {},
	"google_subject":        {},
	"metadata":              {},
	"updated_at":            {},
}

// UpdateFields writes only the named columns of a live user.
func (r *Repository) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	_, err := r.write(ctx, id, fields, false)
	return err
}

// UpdateFieldsRevoking writes the named columns and, in the same statement,
// sets tokens_valid_after to the database's now(); it returns that instant. A
// write that demotes the last superadmin is refused.
func (r *Repository) UpdateFieldsRevoking(ctx context.Context, id string, fields map[string]any) (time.Time, error) {
	return r.write(ctx, id, fields, true)
}

func (r *Repository) write(ctx context.Context, id string, fields map[string]any, revoke bool) (time.Time, error) {
	updates := make(map[string]any, len(fields)+2)
	for column, value := range fields {
		if _, ok := updatableFields[column]; !ok {
			return time.Time{}, fmt.Errorf("user: column %q cannot be updated", column)
		}
		updates[column] = value
	}
	if _, ok := updates["updated_at"]; !ok {
		updates["updated_at"] = time.Now()
	}
	if revoke {
		updates["tokens_valid_after"] = gorm.Expr("now()")
	}
	demotes := false
	if role, ok := fields["role"].(string); ok && role != domainuser.RoleSuperAdmin {
		demotes = true
	}

	var cutoff time.Time
	err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if demotes {
			if err := guardLastSuperAdmin(tx, id); err != nil {
				return err
			}
		}
		var row domainuser.Users
		query := tx.Model(&row).Where("id = ?", id)
		if revoke {
			query = query.Clauses(clause.Returning{Columns: []clause.Column{{Name: "tokens_valid_after"}}})
		}
		res := query.Updates(updates)
		if res.Error != nil {
			return translateErr(res.Error)
		}
		if res.RowsAffected == 0 {
			return domainuser.ErrNotFound
		}
		if revoke && row.TokensValidAfter != nil {
			cutoff = *row.TokensValidAfter
		}
		return nil
	})
	return cutoff, err
}

// guardLastSuperAdmin locks every live superadmin row and refuses when id is
// the only one, so two concurrent removals serialize: the second sees the
// first's committed result.
func guardLastSuperAdmin(tx *gorm.DB, id string) error {
	var ids []string
	err := tx.Model(&domainuser.Users{}).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("role = ?", domainuser.RoleSuperAdmin).Pluck("id", &ids).Error
	if err != nil {
		return translateErr(err)
	}
	if len(ids) == 1 && ids[0] == id {
		return domainuser.ErrLastSuperAdmin
	}
	return nil
}

// GetByGoogleSubject returns the live user linked to a Google "sub".
func (r *Repository) GetByGoogleSubject(ctx context.Context, subject string) (domainuser.Users, error) {
	var ret domainuser.Users
	err := r.DB.WithContext(ctx).Where("google_subject = ?", subject).First(&ret).Error
	return ret, translateErr(err)
}

// Delete soft-deletes a user. Deleting the last superadmin is refused.
func (r *Repository) Delete(ctx context.Context, id string) error {
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := guardLastSuperAdmin(tx, id); err != nil {
			return err
		}
		res := tx.Where("id = ?", id).Delete(&domainuser.Users{})
		if res.Error != nil {
			return translateErr(res.Error)
		}
		if res.RowsAffected == 0 {
			return domainuser.ErrNotFound
		}
		return nil
	})
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
	return r.getAll(ctx, req, nil)
}

// GetAllExcludingRole lists the users who do not hold role. The exclusion is in
// the query, so the page size and the total both leave those rows out.
func (r *Repository) GetAllExcludingRole(ctx context.Context, req dtoshared.ListRequest, role string) ([]domainuser.Users, int64, error) {
	return r.getAll(ctx, req, func(db *gorm.DB) *gorm.DB { return db.Where("role <> ?", role) })
}

func (r *Repository) getAll(ctx context.Context, req dtoshared.ListRequest, base gokit.QueryFunc) (ret []domainuser.Users, totalData int64, err error) {
	return r.Repository.GetAll(ctx, repositoryshared.BaseParams(req), gokit.QueryOptions{
		BaseQuery:      base,
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
