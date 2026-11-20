package menu

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	"github.com/zazhedho/authkit/internal/testutil"
)

// Two menus each moved under the other at once must not form a loop.
func TestConcurrentReparentingCannotCreateALoop(t *testing.T) {
	db := testutil.PostgresSchema(t, os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	repo := NewRepository(db)
	for round := range 10 {
		a, b := uuid.NewString(), uuid.NewString()
		for _, id := range []string{a, b} {
			if err := db.Exec(`INSERT INTO menu_items (id, name, display_name, path) VALUES (?, ?, 'M', '/m')`, id, id).Error; err != nil {
				t.Fatal(err)
			}
		}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, pair := range [][2]string{{a, b}, {b, a}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				item, err := repo.GetByID(t.Context(), pair[0])
				if err != nil {
					errs[i] = err
					return
				}
				item.ParentID = &pair[1]
				errs[i] = repo.Update(t.Context(), item)
			}()
		}
		wg.Wait()
		bad := 0
		for _, err := range errs {
			if errors.Is(err, domainmenu.ErrInvalidParent) {
				bad++
			} else if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if bad != 1 {
			t.Fatalf("round %d: want exactly one loop refusal, got %v", round, errs)
		}
	}
}
