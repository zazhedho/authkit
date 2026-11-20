package auth

import (
	"errors"
	"testing"

	"gorm.io/gorm"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
)

func TestRepositoryTranslatesErrorsToDomain(t *testing.T) {
	requireTranslated(t, translateErr(gorm.ErrRecordNotFound), domainauth.ErrNotFound, gorm.ErrRecordNotFound)
}

func requireTranslated(t *testing.T, err, domain, cause error) {
	t.Helper()
	if !errors.Is(err, domain) || !errors.Is(err, cause) {
		t.Fatalf("expected both %v and %v in the chain, got %v", domain, cause, err)
	}
}
