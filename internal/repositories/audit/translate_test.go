package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/authkit/internal/testutil"
	"gorm.io/gorm"
)

func TestRepositoryTranslatesErrorsToDomain(t *testing.T) {
	db, mock := testutil.NewMockDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err := repo.GetByID(ctx, "a1")
	requireTranslated(t, err, domainaudit.ErrNotFound, gorm.ErrRecordNotFound)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func requireTranslated(t *testing.T, err, domain, cause error) {
	t.Helper()
	if !errors.Is(err, domain) || !errors.Is(err, cause) {
		t.Fatalf("expected both %v and %v in the chain, got %v", domain, cause, err)
	}
}
