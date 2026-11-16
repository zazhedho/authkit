package authkit

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestMissingFromSchema(t *testing.T) {
	expected := map[string][]string{
		"users": {"id", "email", "locked_until"},
		"roles": {"id", "name"},
	}
	full := map[string][]string{
		"users": {"id", "email", "locked_until"},
		"roles": {"id", "name"},
	}

	t.Run("complete", func(t *testing.T) {
		if got := missingFromSchema(expected, full); len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})
	t.Run("missing table", func(t *testing.T) {
		actual := map[string][]string{"users": full["users"]}
		if got, want := missingFromSchema(expected, actual), []string{"roles"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("missing column", func(t *testing.T) {
		actual := map[string][]string{"users": {"id", "email"}, "roles": full["roles"]}
		if got, want := missingFromSchema(expected, actual), []string{"users.locked_until"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("extra columns and tables ignored", func(t *testing.T) {
		actual := map[string][]string{
			"users": {"id", "email", "locked_until", "tenant_id"},
			"roles": {"id", "name", "color"},
			"trips": {"id"},
		}
		if got := missingFromSchema(expected, actual); len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})
	t.Run("sorted", func(t *testing.T) {
		got := missingFromSchema(expected, map[string][]string{"users": {"id"}})
		want := []string{"roles", "users.email", "users.locked_until"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

// TestEmbeddedMigrationsMatchStarterKit compares the embedded baseline with the
// original files. Set AUTHKIT_STARTER_KIT_DIR to the starter-kit checkout.
func TestEmbeddedMigrationsMatchStarterKit(t *testing.T) {
	dir := os.Getenv("AUTHKIT_STARTER_KIT_DIR")
	if dir == "" {
		t.Skip("AUTHKIT_STARTER_KIT_DIR is not set")
	}
	src := filepath.Join(dir, "migrations")
	st, err := os.Stat(src) //nolint:gosec // test-only path from the environment
	if err != nil || !st.IsDir() {
		t.Skipf("no migrations directory in %s", dir)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 {
		t.Fatalf("embedded migrations: got %d files, want 8", len(entries))
	}
	for _, e := range entries {
		got, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(src, e.Name())) //nolint:gosec // test-only path from the environment
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the starter-kit copy", e.Name())
		}
	}
}

func TestBaselineSchemaCoversEmbeddedTables(t *testing.T) {
	want := []string{"users", "blacklist", "roles", "permissions", "menu_items",
		"role_permissions", "role_menus", "audit_trails", "app_configs"}
	got := make([]string, 0, len(baselineSchema))
	for table := range baselineSchema {
		got = append(got, table)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("baselineSchema tables = %v, want %v", got, want)
	}
}
