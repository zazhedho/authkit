package role

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/gorm"

	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	"github.com/zazhedho/authkit/internal/testutil"
)

func TestRepositoryTranslatesErrorsToDomain(t *testing.T) {
	db, mock := testutil.NewMockDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err := repo.GetByID(ctx, "r1")
	requireTranslated(t, err, domainrole.ErrNotFound, gorm.ErrRecordNotFound)

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err = repo.GetByName(ctx, "x")
	requireTranslated(t, err, domainrole.ErrNotFound, gorm.ErrRecordNotFound)

	mock.ExpectExec(".*").WillReturnError(gorm.ErrDuplicatedKey)
	err = repo.Store(ctx, domainrole.Role{ID: "r1"})
	requireTranslated(t, err, domainrole.ErrDuplicate, gorm.ErrDuplicatedKey)

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
