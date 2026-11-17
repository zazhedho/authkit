package repositoryauth

import (
	"context"
	"errors"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	interfaceauth "github.com/zazhedho/authkit/internal/interfaces/auth"
	"github.com/zazhedho/gokit"
	"time"

	"gorm.io/gorm"
)

var ErrBlacklistExpiryRequired = errors.New("blacklist expiry is required")

type blacklistRepo struct {
	*gokit.Repository[domainauth.Blacklist]
}

func NewBlacklistRepo(db *gorm.DB) interfaceauth.RepoAuthInterface {
	return &blacklistRepo{
		Repository: gokit.NewRepository[domainauth.Blacklist](db),
	}
}

func (r *blacklistRepo) Store(ctx context.Context, blacklist domainauth.Blacklist) error {
	if blacklist.ExpiresAt.IsZero() {
		return ErrBlacklistExpiryRequired
	}

	if err := r.DeleteExpired(ctx, time.Now()); err != nil {
		return err
	}

	return r.Repository.Store(ctx, blacklist)
}

func (r *blacklistRepo) GetByToken(ctx context.Context, token string) (domainauth.Blacklist, error) {
	return r.GetOneByField(ctx, "token", token)
}

func (r *blacklistRepo) ExistsByToken(ctx context.Context, token string) (bool, error) {
	return r.ExistsByField(ctx, "token", token)
}

func (r *blacklistRepo) DeleteExpired(ctx context.Context, now time.Time) error {
	return r.DB.WithContext(ctx).
		Where("expires_at IS NULL OR expires_at <= ?", now).
		Delete(&domainauth.Blacklist{}).Error
}
