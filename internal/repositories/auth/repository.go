package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	if err := r.purgeExpired(ctx, time.Now()); err != nil {
		return err
	}
	blacklist.Token = hashToken(blacklist.Token)

	return translateErr(r.Repository.Store(ctx, &blacklist))
}

func translateErr(err error) error {
	return repositoryshared.Gorm(err, domainauth.ErrNotFound, domainauth.ErrDuplicate)
}

func (r *Repository) ExistsByToken(ctx context.Context, token string) (bool, error) {
	return r.ExistsByField(ctx, "token", hashToken(token))
}

// hashToken is what the table stores: the hex sha256 of the token, so a
// database leak does not hand out usable tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (r *Repository) purgeExpired(ctx context.Context, now time.Time) error {
	return r.DB.WithContext(ctx).
		Where("expires_at IS NULL OR expires_at <= ?", now).
		Delete(&domainauth.Blacklist{}).Error
}
