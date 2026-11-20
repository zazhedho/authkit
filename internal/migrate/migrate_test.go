package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/zazhedho/authkit/internal/moduleseed"
)

// adminDB returns a connection to the database named by AUTHKIT_TEST_DATABASE_URL.
func adminDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db, dsn
}

func newSchemaName() string {
	return "authkit_t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

// testSchema creates a uniquely named schema, opens a connection whose
// search_path is that schema, and drops the schema when the test ends.
func testSchema(t *testing.T) (db *gorm.DB, schema string, admin *gorm.DB) {
	t.Helper()
	admin, dsn := adminDB(t)
	schema = newSchemaName()
	if err := admin.Exec(`CREATE SCHEMA ` + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`).Error })

	return openSchemaDB(t, dsn, "", schema), schema, admin
}

// openSchemaDB opens a new connection pool whose search_path is schema, as
// user when it is not empty.
func openSchemaDB(t *testing.T, dsn, user, schema string) *gorm.DB {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		u.User = url.UserPassword(user, "pw-"+user)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := gorm.Open(postgres.Open(u.String()), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func count(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(`SELECT count(*) FROM ` + table).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func counts(t *testing.T, db *gorm.DB) map[string]int64 {
	out := map[string]int64{}
	for _, tb := range []string{"role_permissions", "menu_items", "roles", "permissions", "role_menus", "app_configs"} {
		out[tb] = count(t, db, tb)
	}
	return out
}

func tableExists(t *testing.T, db *gorm.DB, table string) bool {
	t.Helper()
	var n int
	if err := db.Raw(`SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?`, table).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func versionRow(t *testing.T, db *gorm.DB) (version int, dirty bool, rows int) {
	t.Helper()
	var rs []struct {
		Version int
		Dirty   bool
	}
	if err := db.Raw(`SELECT version, dirty FROM ` + Table).Scan(&rs).Error; err != nil {
		t.Fatalf("read version table: %v", err)
	}
	if len(rs) > 0 {
		version, dirty = rs[0].Version, rs[0].Dirty
	}
	return version, dirty, len(rs)
}

func actualSchema(t *testing.T, db *gorm.DB) map[string][]string {
	t.Helper()
	var rows []struct{ TableName, ColumnName string }
	if err := db.Raw(`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, r := range rows {
		out[r.TableName] = append(out[r.TableName], r.ColumnName)
	}
	return out
}

// lockFree reports whether the advisory lock the migration library takes for
// this schema is free (nothing leaked it).
func lockFree(t *testing.T, admin *gorm.DB, schema string) bool {
	t.Helper()
	var dbName string
	if err := admin.Raw(`SELECT current_database()`).Scan(&dbName).Error; err != nil {
		t.Fatal(err)
	}
	id, err := database.GenerateAdvisoryLockId(dbName, schema, Table)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := admin.DB()
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(context.Background(), `SELECT pg_try_advisory_lock($1)`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, id)
	}
	return got
}

// latestVersion is the newest embedded migration.
const latestVersion = 20260101000300

// expectedSchema lists the tables and columns the migrations leave behind; the
// tests compare it with a real database in both directions.
var expectedSchema = map[string][]string{
	"users": {
		"id", "name", "email", "phone", "password", "role", "role_id",
		"email_verified_at", "phone_verified_at", "last_login_at", "last_login_ip",
		"last_login_user_agent", "password_changed_at", "tokens_valid_after", "google_subject",
		"login_provider", "avatar_url", "metadata", "created_at", "updated_at", "deleted_at",
	},
	"blacklist": {"id", "token", "created_at", "expires_at"},
	"roles":     {"id", "name", "display_name", "description", "is_system", "created_at", "updated_at", "deleted_at"},
	"permissions": {
		"id", "name", "display_name", "description", "resource", "action",
		"created_at", "updated_at", "deleted_at",
	},
	"menu_items": {
		"id", "name", "display_name", "path", "icon", "parent_id", "order_index",
		"is_active", "created_at", "updated_at", "deleted_at",
	},
	"role_permissions": {"id", "role_id", "permission_id", "created_at"},
	"role_menus":       {"id", "role_id", "menu_item_id", "created_at"},
	"audit_trails": {
		"id", "occurred_at", "actor_user_id", "actor_role", "action", "resource",
		"resource_id", "status", "message", "error_message", "request_id",
		"ip_address", "user_agent", "before_data", "after_data", "metadata", "created_at",
	},
	"app_configs": {
		"id", "config_key", "display_name", "category", "value", "description",
		"is_active", "created_at", "updated_at", "deleted_at",
	},
}

// missingFromSchema returns, sorted, the "table" or "table.column" entries that
// expected has and actual lacks.
func missingFromSchema(expected, actual map[string][]string) []string {
	var missing []string
	for table, cols := range expected {
		have, ok := actual[table]
		if !ok {
			missing = append(missing, table)
			continue
		}
		set := map[string]bool{}
		for _, c := range have {
			set[c] = true
		}
		for _, c := range cols {
			if !set[c] {
				missing = append(missing, table+"."+c)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func TestMigrateEmptyDatabase(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	ctx := context.Background()

	if err := Up(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for tb := range expectedSchema {
		if !tableExists(t, db, tb) {
			t.Errorf("table %s missing", tb)
		}
	}
	if v, dirty, rows := versionRow(t, db); v != latestVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d, want %d false 1", v, dirty, rows, latestVersion)
	}
	actual := actualSchema(t, db)
	if missing := missingFromSchema(expectedSchema, actual); len(missing) != 0 {
		t.Fatalf("expectedSchema does not match the SQL, missing %v", missing)
	}
	// Reverse direction: everything the SQL created must be in expectedSchema.
	delete(actual, Table)
	if extra := missingFromSchema(actual, expectedSchema); len(extra) != 0 {
		t.Fatalf("the SQL creates tables or columns that expectedSchema lacks: %v", extra)
	}
	before := counts(t, db)

	if err := Up(ctx, db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("second Migrate changed data: %v -> %v", before, after)
	}
	if err := db.Exec("SELECT 1").Error; err != nil {
		t.Fatalf("caller connection unusable after Migrate: %v", err)
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
}

func TestMigrateDoesNotCloseCallerDB(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Fatalf("ping after Migrate: %v", err)
	}
	var n int
	if err := db.Raw(`SELECT 1`).Scan(&n).Error; err != nil || n != 1 {
		t.Fatalf("query after Migrate: n=%d err=%v", n, err)
	}
}

func extraSource(t *testing.T) func() (source.Driver, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := fs.ReadFile(migrationsFS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		fsys[e.Name()] = &fstest.MapFile{Data: raw}
	}
	fsys["20260101000400_extra_test.up.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE authkit_extra_test (id int);`)}
	fsys["20260101000400_extra_test.down.sql"] = &fstest.MapFile{Data: []byte(`DROP TABLE authkit_extra_test;`)}
	return func() (source.Driver, error) { return iofs.New(fsys, ".") }
}

func TestMigrateAppliesALaterMigration(t *testing.T) {
	t.Parallel()
	db, _, admin := testSchema(t)
	ctx := context.Background()

	if err := Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	before := counts(t, db)
	if err := up(ctx, db, extraSource(t)); err != nil {
		t.Fatalf("migrate with the extra migration: %v", err)
	}
	if !tableExists(t, db, "authkit_extra_test") {
		t.Fatal("the extra migration was not applied")
	}
	if v, dirty, _ := versionRow(t, db); v != 20260101000400 || dirty {
		t.Fatalf("version = %d dirty=%v, want 20260101000400 false", v, dirty)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("baseline data changed: %v -> %v", before, after)
	}
	_ = admin
}

func TestMigrateDirtyVersionTableFails(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	if err := db.Exec(`CREATE TABLE ` + Table + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + Table + ` VALUES (2, true)`).Error; err != nil {
		t.Fatal(err)
	}
	err := Up(context.Background(), db)
	if err == nil || !strings.Contains(err.Error(), "dirty") || !strings.Contains(err.Error(), Table) {
		t.Fatalf("err = %v, want dirty error naming %s", err, Table)
	}
	if v, dirty, _ := versionRow(t, db); v != 2 || !dirty {
		t.Fatalf("version table was modified: %d %v", v, dirty)
	}
	if tableExists(t, db, "users") {
		t.Fatal("migrations ran on a dirty database")
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
}

// A users table in another schema must not matter to the connection's schema.
func TestMigrateIgnoresUsersTableInOtherSchema(t *testing.T) {
	t.Parallel()
	db, _, admin := testSchema(t)
	other := newSchemaName()
	if err := admin.Exec(`CREATE SCHEMA ` + other).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + other + ` CASCADE`).Error })
	if err := admin.Exec(`CREATE TABLE ` + other + `.users (id int)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := Up(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if missing := missingFromSchema(expectedSchema, actualSchema(t, db)); len(missing) != 0 {
		t.Fatalf("schema incomplete: %v", missing)
	}
}

func TestMigrateDirtyErrorStillMatchesSentinel(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := db.Exec(`CREATE TABLE ` + Table + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + Table + ` VALUES (3, true)`).Error; err != nil {
		t.Fatal(err)
	}
	err := Up(context.Background(), db)
	if !errors.Is(err, ErrDirty) || !strings.Contains(err.Error(), Table) {
		t.Fatalf("err = %v, want ErrDirty naming %s", err, Table)
	}
	if strings.Contains(err.Error(), "delete") && !strings.Contains(err.Error(), "never delete") {
		t.Fatalf("advice must not suggest deleting the record: %v", err)
	}
}

func TestMigrateConcurrentFirstStart(t *testing.T) {
	t.Parallel()
	_, dsn := adminDB(t)
	ref, _, _ := testSchema(t)
	if err := Up(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	want := counts(t, ref)

	db, schema, admin := testSchema(t)
	const n = 4
	pools := make([]*gorm.DB, n)
	for i := range pools {
		pools[i] = openSchemaDB(t, dsn, "", schema)
	}
	start := make(chan struct{})
	errs := make(chan error, n)
	for _, pool := range pools {
		go func(pool *gorm.DB) {
			<-start
			errs <- Up(context.Background(), pool)
		}(pool)
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("Migrate: %v", err)
		}
	}
	if v, dirty, rows := versionRow(t, db); v != latestVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d, want %d false 1", v, dirty, rows, latestVersion)
	}
	if got := counts(t, db); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("seed counts differ from a single instance: %v vs %v", got, want)
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
}

func TestPartialUniqueIndexesAllowReuseAfterSoftDelete(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO users (id, name, email, phone, password) VALUES (gen_random_uuid(), 'A', 'dup@example.test', '628111', 'x')`
	if err := db.Exec(insert).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(insert).Error; err == nil {
		t.Fatal("two live users must not share an email or phone")
	}
	if err := db.Exec(`UPDATE users SET deleted_at = now() WHERE email = 'dup@example.test'`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(insert).Error; err != nil {
		t.Fatalf("email and phone must be reusable after a soft delete: %v", err)
	}
	if err := db.Exec(`UPDATE roles SET deleted_at = now() WHERE name = 'viewer'`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO roles (id, name, display_name) VALUES (gen_random_uuid(), 'viewer', 'Viewer 2')`).Error; err != nil {
		t.Fatalf("role name must be reusable after a soft delete: %v", err)
	}
}

func TestMigrationsGoDownAndUpAgain(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	run := func(suffix string, reverse bool) {
		files, err := fs.Glob(migrationsFS, "*."+suffix+".sql")
		if err != nil || len(files) == 0 {
			t.Fatalf("glob %s: %v %v", suffix, files, err)
		}
		sort.Strings(files)
		if reverse {
			sort.Sort(sort.Reverse(sort.StringSlice(files)))
		}
		for _, f := range files {
			raw, err := fs.ReadFile(migrationsFS, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Exec(string(raw)).Error; err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	}
	run("down", true)
	for tb := range expectedSchema {
		if tableExists(t, db, tb) {
			t.Errorf("table %s survived the down migrations", tb)
		}
	}
	run("up", false)
	if missing := missingFromSchema(expectedSchema, actualSchema(t, db)); len(missing) != 0 {
		t.Fatalf("schema after down and up is missing %v", missing)
	}
	run("down", true)
}

func TestTokensValidAfterColumnExists(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO users (id, name, email, password, tokens_valid_after) VALUES (gen_random_uuid(), 'A', 'a@example.test', 'x', now())`).Error; err != nil {
		t.Fatalf("tokens_valid_after: %v", err)
	}
}

func TestModuleSeedSQLRunsAndDetectsPermissionNameCollisions(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	seed := func(def moduleseed.Definition) error {
		sql, err := moduleseed.RenderSQL(def)
		if err != nil {
			t.Fatal(err)
		}
		return db.Exec(sql).Error
	}
	projects := moduleseed.Definition{Name: "projects", DisplayName: "Projects", Path: "/projects", GrantRoles: []string{"admin"}}
	if err := seed(projects); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := counts(t, db)
	if err := seed(projects); err != nil {
		t.Fatalf("second run must be idempotent: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("second run changed data: %v -> %v", before, after)
	}
	// "list_users" is a built-in permission for resource users; a module named
	// users with another resource would silently lose its permission.
	err := seed(moduleseed.Definition{Name: "users", DisplayName: "Users 2", Path: "/u2", Resource: "people", Actions: []string{"list"}})
	if err == nil || !strings.Contains(err.Error(), "module-seed") {
		t.Fatalf("collision err = %v, want the module-seed guard", err)
	}
}

func TestEveryTimestampColumnIsTimestamptzAndTheBlacklistIndexIsNotDuplicated(t *testing.T) {
	db, _, _ := testSchema(t)
	if err := Up(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	var plain []string
	err := db.Raw(`SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type = 'timestamp without time zone'
		AND table_name <> 'authkit_schema_migrations' ORDER BY 1`).Scan(&plain).Error
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Fatalf("timestamp columns without a time zone: %v", plain)
	}
	var dup int64
	if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_blacklist_token'`).Scan(&dup).Error; err != nil || dup != 0 {
		t.Fatalf("idx_blacklist_token duplicates the UNIQUE constraint (found %d, err %v)", dup, err)
	}
}
