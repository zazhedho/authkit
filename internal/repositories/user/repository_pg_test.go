package user

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/testutil"
)

func seedUser(t *testing.T, db *gorm.DB, email, role string) string {
	t.Helper()
	id := uuid.NewString()
	err := db.Exec(`INSERT INTO users (id, name, email, password, role) VALUES (?, 'N', ?, 'x', ?)`, id, email, role).Error
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func countRole(t *testing.T, db *gorm.DB, role string) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(`SELECT count(*) FROM users WHERE role = ? AND deleted_at IS NULL`, role).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// Two superadmins removing each other at once must leave one.
func TestConcurrentSuperAdminRemovalsKeepOne(t *testing.T) {
	db := testutil.PostgresSchema(t, os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	repo := NewRepository(db)
	ctx := t.Context()
	for round := range 15 {
		a := seedUser(t, db, uuid.NewString()+"@a.test", domainuser.RoleSuperAdmin)
		b := seedUser(t, db, uuid.NewString()+"@b.test", domainuser.RoleSuperAdmin)
		// Make a and b the only superadmins.
		db.Exec(`UPDATE users SET role = 'viewer' WHERE role = 'superadmin' AND id NOT IN (?, ?)`, a, b)

		ops := []func() error{
			func() error { return repo.Delete(ctx, a) },
			func() error {
				_, err := repo.UpdateFieldsRevoking(ctx, b, map[string]any{"role": "viewer"})
				return err
			},
		}
		if round%2 == 1 {
			ops[0] = func() error { return repo.Delete(ctx, b) }
			ops[1] = func() error {
				_, err := repo.UpdateFieldsRevoking(ctx, a, map[string]any{"role": "viewer"})
				return err
			}
		}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range ops {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = ops[i]() }()
		}
		wg.Wait()

		if n := countRole(t, db, domainuser.RoleSuperAdmin); n != 1 {
			t.Fatalf("round %d: %d superadmins left, want 1 (errs %v)", round, n, errs)
		}
		failed := 0
		for _, err := range errs {
			if errors.Is(err, domainuser.ErrLastSuperAdmin) {
				failed++
			}
		}
		if failed != 1 {
			t.Fatalf("round %d: want exactly one ErrLastSuperAdmin, got %v", round, errs)
		}
	}
}

func TestUpdateFieldsRevokingWritesTheCutoffWithTheFieldsAndReturnsIt(t *testing.T) {
	db := testutil.PostgresSchema(t, os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	repo := NewRepository(db)
	id := seedUser(t, db, "u@x.test", "viewer")

	before := time.Now().Add(-time.Second)
	cutoff, err := repo.UpdateFieldsRevoking(t.Context(), id, map[string]any{"password": "new-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if cutoff.Before(before) || cutoff.After(time.Now().Add(time.Second)) {
		t.Fatalf("cutoff %v is not about now", cutoff)
	}
	state, err := repo.GetAuthState(t.Context(), id)
	if err != nil || state.TokensValidAfter == nil || state.TokensValidAfter.UnixMicro() != cutoff.UnixMicro() {
		t.Fatalf("stored cutoff %v does not match the returned %v (%v)", state.TokensValidAfter, cutoff, err)
	}
	got, err := repo.GetByID(t.Context(), id)
	if err != nil || got.Password != "new-hash" {
		t.Fatalf("password not written: %v %v", got.Password, err)
	}
}

func TestUpdateFieldsRejectsUnknownColumnsAndCannotSetTheCutoff(t *testing.T) {
	db := testutil.PostgresSchema(t, os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	repo := NewRepository(db)
	id := seedUser(t, db, "u@x.test", "viewer")
	if err := repo.UpdateFields(t.Context(), id, map[string]any{"tokens_valid_after": time.Now()}); err == nil {
		t.Fatal("tokens_valid_after must only be written through UpdateFieldsRevoking")
	}
	if err := repo.UpdateFields(t.Context(), id, map[string]any{"deleted_at": nil}); err == nil {
		t.Fatal("unknown column accepted")
	}
}
