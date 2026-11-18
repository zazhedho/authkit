package auth

import (
	"context"
	"errors"
	"time"

	"github.com/zazhedho/gokit"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	repositoryshared "github.com/zazhedho/authkit/internal/repositories/shared"

	"gorm.io/gorm"
)

var ErrBlacklistExpiryRequired = errors.New("blacklist expiry is required")

type Repository struct {
	*gokit.Repository[domainauth.Blacklist]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{
		Repository: gokit.NewRepository[domainauth.Blacklist](db),
	}
}

func (r *Repository) Store(ctx context.Context, blacklist domainauth.Blacklist) error {
	if blacklist.ExpiresAt.IsZero() {
		return ErrBlacklistExpiryRequired
	}

	if err := r.DeleteExpired(ctx, time.Now()); err != nil {
		return err
	}

	return translateErr(r.Repository.Store(ctx, blacklist))
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainauth.ErrNotFound, domainauth.ErrDuplicate)
}

func (r *Repository) GetByToken(ctx context.Context, token string) (domainauth.Blacklist, error) {
	ret, err := r.GetOneByField(ctx, "token", token)
	return ret, translateErr(err)
}

func (r *Repository) ExistsByToken(ctx context.Context, token string) (bool, error) {
	return r.ExistsByField(ctx, "token", token)
}

func (r *Repository) DeleteExpired(ctx context.Context, now time.Time) error {
	return r.DB.WithContext(ctx).
		Where("expires_at IS NULL OR expires_at <= ?", now).
		Delete(&domainauth.Blacklist{}).Error
}
