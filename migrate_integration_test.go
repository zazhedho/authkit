package authkit

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

func testKit(t *testing.T, db *gorm.DB) *Kit {
	t.Helper()
	k, err := New(Config{DB: db, AppName: "migrate-test", JWTKey: testJWTKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return k
}

func applyBaselineDirectly(t *testing.T, db *gorm.DB) {
	t.Helper()
	files, err := fs.Glob(migrationsFS, "migrations/*.up.sql")
	if err != nil || len(files) != 4 {
		t.Fatalf("glob: %v %v", files, err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := fs.ReadFile(migrationsFS, f)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(string(raw)).Error; err != nil {
			t.Fatalf("apply %s: %v", f, err)
		}
	}
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
	if err := db.Raw(`SELECT version, dirty FROM ` + MigrationsTable).Scan(&rs).Error; err != nil {
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
	id, err := database.GenerateAdvisoryLockId(dbName, schema, MigrationsTable)
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

// legacyDatabase builds a database as the pre-authkit project left it: the four
// baseline files applied directly, then admin edits that a replay would undo.
func legacyDatabase(t *testing.T, db *gorm.DB) {
	t.Helper()
	applyBaselineDirectly(t, db)
	stmts := []string{
		`DELETE FROM role_permissions WHERE id = (SELECT rp.id FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.name = 'admin' LIMIT 1)`,
		`DELETE FROM menu_items WHERE name = 'audits'`,
		`INSERT INTO permissions (name, display_name, resource, action) VALUES ('list_trips', 'List Trips', 'trips', 'list')`,
	}
	for _, s := range stmts {
		if err := db.Exec(s).Error; err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func TestMigrateEmptyDatabase(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	k := testKit(t, db)
	ctx := context.Background()

	if err := k.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for tb := range baselineSchema {
		if !tableExists(t, db, tb) {
			t.Errorf("table %s missing", tb)
		}
	}
	if v, dirty, rows := versionRow(t, db); v != BaselineVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d, want %d false 1", v, dirty, rows, BaselineVersion)
	}
	actual := actualSchema(t, db)
	if missing := missingFromSchema(baselineSchema, actual); len(missing) != 0 {
		t.Fatalf("baselineSchema does not match the SQL, missing %v", missing)
	}
	// Reverse direction: everything the SQL created must be in baselineSchema.
	delete(actual, MigrationsTable)
	if extra := missingFromSchema(actual, baselineSchema); len(extra) != 0 {
		t.Fatalf("the SQL creates tables or columns that baselineSchema lacks: %v", extra)
	}
	before := counts(t, db)

	if err := k.Migrate(ctx); err != nil {
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

func TestMigrateLegacyDatabaseIsStampedNotReplayed(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	legacyDatabase(t, db)
	before := counts(t, db)

	if err := testKit(t, db).Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("legacy data changed: %v -> %v", before, after)
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id WHERE r.name = 'staff' AND p.name = 'list_trips'`).Scan(&n).Error; err != nil || n != 0 {
		t.Fatalf("staff got list_trips: n=%d err=%v", n, err)
	}
	if err := db.Raw(`SELECT count(*) FROM menu_items WHERE name = 'audits'`).Scan(&n).Error; err != nil || n != 0 {
		t.Fatalf("audits menu resurrected: n=%d err=%v", n, err)
	}
	if v, dirty, rows := versionRow(t, db); v != BaselineVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d", v, dirty, rows)
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
	// Second call is a no-op.
	if err := testKit(t, db).Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("second Migrate changed data: %v -> %v", before, after)
	}
}

func TestMigrateLegacyDatabaseWithMissingColumnFails(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	legacyDatabase(t, db)
	if err := db.Exec(`ALTER TABLE users DROP COLUMN locked_until`).Error; err != nil {
		t.Fatal(err)
	}
	before := counts(t, db)

	err := testKit(t, db).Migrate(context.Background())
	if !errors.Is(err, ErrLegacySchemaIncomplete) {
		t.Fatalf("err = %v, want ErrLegacySchemaIncomplete", err)
	}
	if !strings.Contains(err.Error(), "users.locked_until") {
		t.Fatalf("error does not name the column: %v", err)
	}
	if tableExists(t, db, MigrationsTable) {
		t.Fatal("version table was created on the incomplete-schema path")
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("data changed: %v -> %v", before, after)
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
}

func TestMigrateDoesNotCloseCallerDB(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	k := testKit(t, db)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Migrate(context.Background()); err != nil {
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
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		fsys[e.Name()] = &fstest.MapFile{Data: raw}
	}
	fsys["000005_extra.up.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE authkit_extra_test (id int);`)}
	fsys["000005_extra.down.sql"] = &fstest.MapFile{Data: []byte(`DROP TABLE authkit_extra_test;`)}
	return func() (source.Driver, error) { return iofs.New(fsys, ".") }
}

func TestMigrateAfterStampAppliesLaterMigration(t *testing.T) {
	t.Parallel()
	db, _, admin := testSchema(t)
	legacyDatabase(t, db)
	ctx := context.Background()

	if err := testKit(t, db).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	before := counts(t, db)
	if err := migrateUp(ctx, db, extraSource(t)); err != nil {
		t.Fatalf("migrate with 000005: %v", err)
	}
	if !tableExists(t, db, "authkit_extra_test") {
		t.Fatal("000005 was not applied")
	}
	if v, dirty, _ := versionRow(t, db); v != 5 || dirty {
		t.Fatalf("version = %d dirty=%v, want 5 false", v, dirty)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("baseline data changed: %v -> %v", before, after)
	}
	_ = admin
}

func TestMigrateDirtyVersionTableFails(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	if err := db.Exec(`CREATE TABLE ` + MigrationsTable + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + MigrationsTable + ` VALUES (2, true)`).Error; err != nil {
		t.Fatal(err)
	}
	err := testKit(t, db).Migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dirty") || !strings.Contains(err.Error(), MigrationsTable) {
		t.Fatalf("err = %v, want dirty error naming %s", err, MigrationsTable)
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

func TestMigrateExistingVersionTableIsNotLegacy(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	legacyDatabase(t, db)
	if err := db.Exec(`CREATE TABLE ` + MigrationsTable + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + MigrationsTable + ` VALUES (4, false)`).Error; err != nil {
		t.Fatal(err)
	}
	// Even an incomplete schema is not examined: the version table decides.
	if err := db.Exec(`ALTER TABLE users DROP COLUMN locked_until`).Error; err != nil {
		t.Fatal(err)
	}
	before := counts(t, db)
	if err := testKit(t, db).Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("data changed: %v -> %v", before, after)
	}
}

// A stamp interrupted after the version table was created leaves it empty; the
// baseline must still not be replayed over existing data.
func TestMigrateEmptyVersionTableOnLegacyDatabaseIsStamped(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	legacyDatabase(t, db)
	if err := db.Exec(`CREATE TABLE ` + MigrationsTable + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	before := counts(t, db)
	if err := testKit(t, db).Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := counts(t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("data changed: %v -> %v", before, after)
	}
	if v, dirty, rows := versionRow(t, db); v != BaselineVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d", v, dirty, rows)
	}
}

// Legacy detection must look at the schema the connection uses, not at other
// schemas that happen to contain a users table.
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
	if err := testKit(t, db).Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if missing := missingFromSchema(baselineSchema, actualSchema(t, db)); len(missing) != 0 {
		t.Fatalf("schema incomplete: %v", missing)
	}
}

// The unlocked detection must not turn a dirty row into an error: another
// instance may be mid-migration. The verdict comes from the locked Up().
func TestDetectLegacyDirtyRowIsNotAnError(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := db.Exec(`CREATE TABLE ` + MigrationsTable + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + MigrationsTable + ` VALUES (1, true)`).Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	legacy, err := detectLegacy(context.Background(), conn)
	if err != nil || legacy {
		t.Fatalf("detectLegacy = %v, %v; want false, nil", legacy, err)
	}
}

func TestMigrateDirtyErrorStillMatchesSentinel(t *testing.T) {
	t.Parallel()
	db, _, _ := testSchema(t)
	if err := db.Exec(`CREATE TABLE ` + MigrationsTable + ` (version bigint not null primary key, dirty boolean not null)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO ` + MigrationsTable + ` VALUES (3, true)`).Error; err != nil {
		t.Fatal(err)
	}
	err := testKit(t, db).Migrate(context.Background())
	if !errors.Is(err, ErrMigrationsDirty) || !strings.Contains(err.Error(), MigrationsTable) {
		t.Fatalf("err = %v, want ErrMigrationsDirty naming %s", err, MigrationsTable)
	}
	if strings.Contains(err.Error(), "delete") && !strings.Contains(err.Error(), "never delete") {
		t.Fatalf("advice must not suggest deleting the record: %v", err)
	}
}

func TestMigrateConcurrentFirstStart(t *testing.T) {
	t.Parallel()
	_, dsn := adminDB(t)
	ref, _, _ := testSchema(t)
	if err := testKit(t, ref).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := counts(t, ref)

	db, schema, admin := testSchema(t)
	const n = 4
	kits := make([]*Kit, n)
	for i := range kits {
		kits[i] = testKit(t, openSchemaDB(t, dsn, "", schema))
	}
	start := make(chan struct{})
	errs := make(chan error, n)
	for _, k := range kits {
		go func(k *Kit) {
			<-start
			errs <- k.Migrate(context.Background())
		}(k)
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("Migrate: %v", err)
		}
	}
	if v, dirty, rows := versionRow(t, db); v != BaselineVersion || dirty || rows != 1 {
		t.Fatalf("version = %d dirty=%v rows=%d, want %d false 1", v, dirty, rows, BaselineVersion)
	}
	if got := counts(t, db); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("seed counts differ from a single instance: %v vs %v", got, want)
	}
	if !lockFree(t, admin, schema) {
		t.Fatal("advisory lock leaked")
	}
}

// Table presence must not depend on the role's privileges: information_schema
// hides tables the role cannot access.
func TestPresenceDetectionIgnoresPrivileges(t *testing.T) {
	t.Parallel()
	db, schema, admin := testSchema(t)
	applyBaselineDirectly(t, db)
	_, dsn := adminDB(t)

	role := "authkit_r_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if err := admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'pw-%s'`, role, role)).Error; err != nil {
		t.Skipf("cannot create role: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(`DROP OWNED BY ` + role).Error
		_ = admin.Exec(`DROP ROLE IF EXISTS ` + role).Error
	})
	if err := admin.Exec(fmt.Sprintf(`GRANT USAGE ON SCHEMA %s TO %s`, schema, role)).Error; err != nil {
		t.Fatal(err)
	}
	low := openSchemaDB(t, dsn, role, schema)
	sqlDB, _ := low.DB()
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// Precondition: the role really cannot see the table through information_schema.
	var visible int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'users'`).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("precondition: information_schema shows users to the role (n=%d err=%v)", visible, err)
	}
	hasUsers, _, err := presentTables(context.Background(), conn)
	if err != nil || !hasUsers {
		t.Fatalf("presentTables hasUsers=%v err=%v; want true", hasUsers, err)
	}
	cols, err := currentColumns(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if missing := missingFromSchema(baselineSchema, cols); len(missing) != 0 {
		t.Fatalf("columns hidden from the low-privilege role: %v", missing)
	}
}
