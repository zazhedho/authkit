package user

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/testutil"
	"gorm.io/gorm"
)

func TestRepositoryTranslatesErrorsToDomain(t *testing.T) {
	db, mock := testutil.NewMockDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err := repo.GetByID(ctx, "u1")
	requireTranslated(t, err, domainuser.ErrNotFound, gorm.ErrRecordNotFound)

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err = repo.GetByEmail(ctx, "a@b.c")
	requireTranslated(t, err, domainuser.ErrNotFound, gorm.ErrRecordNotFound)

	mock.ExpectQuery(".*").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	_, err = repo.GetByPhone(ctx, "6281")
	requireTranslated(t, err, domainuser.ErrNotFound, gorm.ErrRecordNotFound)

	mock.ExpectExec(".*").WillReturnError(gorm.ErrDuplicatedKey)
	err = repo.Store(ctx, domainuser.Users{Id: "u1", Phone: "6281"})
	requireTranslated(t, err, domainuser.ErrDuplicate, gorm.ErrDuplicatedKey)

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
