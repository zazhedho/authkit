package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	"github.com/zazhedho/authkit/internal/testutil"
)

const rawToken = "raw.jwt.token" //nolint:gosec // test fixture, not a credential

func TestBlacklistStoresAndLooksUpTheTokenHash(t *testing.T) {
	sum := sha256.Sum256([]byte(rawToken))
	want := hex.EncodeToString(sum[:])

	db, mock := testutil.NewMockDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectExec(`DELETE FROM "blacklist"`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO "blacklist"`).
		WithArgs(sqlmock.AnyArg(), want, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := repo.Store(ctx, domainauth.Blacklist{ID: "id", Token: rawToken, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery(`SELECT 1 FROM "blacklist" WHERE "token" = \$1`).
		WithArgs(want, 1).
		WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	ok, err := repo.ExistsByToken(ctx, rawToken)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
