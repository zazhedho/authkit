package authkit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/internal/migrations"
)

// MigrationsTable is the version table authkit uses, so it never collides with
// the host project's own golang-migrate table (schema_migrations by default).
const MigrationsTable = "authkit_schema_migrations"

// BaselineVersion is the version of the migrations that create the users, auth
// and RBAC tables (000001 to 000004). Databases created by the original
// project that already hold them are recorded as being at this version.
const BaselineVersion = 4

// ErrLegacySchemaIncomplete is returned by Migrate when the database already
// has the users table but no authkit version record, and its schema lacks
// tables or columns the baseline creates. Nothing is changed in that case.
var ErrLegacySchemaIncomplete = errors.New("authkit: existing schema is missing expected tables or columns")

// ErrMigrationsDirty is returned by Migrate when the version table records a
// failed migration. Migrate never repairs it: fix the database by hand, then
// set the record to the last fully applied version and clear its dirty flag.
// Never delete the record: a missing record next to existing tables makes the
// database look unmigrated to authkit.
var ErrMigrationsDirty = errors.New("authkit: migrations are in a dirty state")

// migrationsFS holds the embedded *.sql files at its root.
var migrationsFS fs.FS = migrations.FS

func embeddedSource() (source.Driver, error) { return iofs.New(migrationsFS, ".") }

// Migrate brings the database to the schema authkit needs, using the embedded
// migrations and the MigrationsTable version table in the connection's current
// schema. It is safe to call on every start. Instances that start at the same
// time serialize on an advisory lock and all succeed; run it on a direct
// database connection, not through a transaction-pooling proxy.
//
//   - Empty database: applies all migrations.
//   - Database that already has the users table but no version record (created
//     by the original project): the schema is checked against what the baseline
//     creates; when complete it is only stamped as BaselineVersion, and the
//     baseline SQL is never run, because its seed data would undo changes made
//     to roles, permissions and menus. Any later migration then applies
//     normally. When incomplete, ErrLegacySchemaIncomplete is returned and
//     nothing is changed.
//   - Database with a version record: applies pending migrations. A dirty
//     record is reported as ErrMigrationsDirty.
//
// ctx bounds the schema inspection only; waiting for the advisory lock and a
// migration that has started are not canceled by it. Run Migrate before the host project's migrations.
// The caller's database handle stays open.
func (k *Kit) Migrate(ctx context.Context) error {
	return migrateUp(ctx, k.cfg.DB, embeddedSource)
}

func migrateUp(ctx context.Context, gdb *gorm.DB, newSource func() (source.Driver, error)) error {
	sqlDB, err := gdb.DB()
	if err != nil {
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	// A dedicated connection: the driver holds its advisory lock on it, and
	// closing the driver only returns it to the caller's pool.
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() { _ = conn.Close() }()

	legacy, err := detectLegacy(ctx, conn)
	if err != nil {
		return err
	}

	src, err := newSource()
	if err != nil {
		return fmt.Errorf("authkit: migrate: source: %w", err)
	}
	drv, err := postgres.WithConnection(ctx, conn, &postgres.Config{MigrationsTable: MigrationsTable})
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", drv)
	if err != nil {
		_ = src.Close()
		_ = drv.Close()
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if legacy {
		if err := stampBaseline(drv); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	err = m.Up()
	var dirty migrate.ErrDirty
	switch {
	case err == nil, errors.Is(err, migrate.ErrNoChange):
		return nil
	case errors.As(err, &dirty):
		return dirtyError(dirty.Version)
	default:
		return fmt.Errorf("authkit: migrate: %w", err)
	}
}

func dirtyError(version int) error {
	return fmt.Errorf("%w: table %q records a failed migration at version %d; repair the database by hand, then set the record to the last fully applied version and clear its dirty flag (never delete the record: a missing record next to existing tables makes the database look unmigrated)",
		ErrMigrationsDirty, MigrationsTable, version)
}

// stampBaseline records BaselineVersion without running any SQL, under the
// library's advisory lock, unless another instance already recorded a version.
func stampBaseline(drv database.Driver) (err error) {
	if err := drv.Lock(); err != nil {
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() {
		if e := drv.Unlock(); e != nil {
			err = errors.Join(err, fmt.Errorf("authkit: migrate: unlock: %w", e))
		}
	}()
	v, dirty, err := drv.Version()
	if err != nil {
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	if dirty {
		return dirtyError(v)
	}
	if v != database.NilVersion {
		return nil
	}
	if err := drv.SetVersion(BaselineVersion, false); err != nil {
		return fmt.Errorf("authkit: migrate: stamp baseline: %w", err)
	}
	return nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// detectLegacy reports whether the database was created before authkit: the
// users table exists in the current schema and no version has been recorded. It
// returns ErrLegacySchemaIncomplete (and creates nothing) when such a database
// lacks part of the baseline schema. A version table that holds any row means
// "not legacy", dirty or not: a dirty row may belong to an instance that is
// migrating right now, so the dirty verdict is left to the locked Up().
//
// The two table lookups are one statement, hence one snapshot: the library
// creates the version table before the first migration creates users, so a
// snapshot that shows users but no version table cannot belong to a migration
// that another instance is running right now.
func detectLegacy(ctx context.Context, conn *sql.Conn) (bool, error) {
	var schema sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return false, fmt.Errorf("authkit: migrate: %w", err)
	}
	if !schema.Valid {
		return false, errors.New("authkit: migrate: the connection has no current schema (check search_path)")
	}

	hasUsers, hasVersionTable, err := presentTables(ctx, conn)
	if err != nil {
		return false, err
	}

	hasVersion := false
	if hasVersionTable {
		var one int
		err := conn.QueryRowContext(ctx,
			`SELECT 1 FROM `+quoteIdent(schema.String)+`.`+quoteIdent(MigrationsTable)+` LIMIT 1`).Scan(&one)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return false, fmt.Errorf("authkit: migrate: %w", err)
		default:
			hasVersion = true
		}
	}

	// An existing version record always wins. An empty version table next to
	// existing data (a stamp that was interrupted) is still a legacy database.
	if hasVersion || !hasUsers {
		return false, nil
	}

	actual, err := currentColumns(ctx, conn)
	if err != nil {
		return false, err
	}
	if missing := missingFromSchema(baselineSchema, actual); len(missing) > 0 {
		return false, fmt.Errorf("%w: %s (schema %q); nothing was changed, complete the schema or migrate it by hand",
			ErrLegacySchemaIncomplete, strings.Join(missing, ", "), schema.String)
	}
	return true, nil
}

func currentColumns(ctx context.Context, conn *sql.Conn) (map[string][]string, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT c.relname, a.attname
		 FROM pg_catalog.pg_attribute a
		 JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped`)
	if err != nil {
		return nil, fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			return nil, fmt.Errorf("authkit: migrate: %w", err)
		}
		out[table] = append(out[table], column)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authkit: migrate: %w", err)
	}
	return out, nil
}

// presentTables reports whether the users and version tables exist in the
// current schema, from a single statement. It reads pg_catalog, which, unlike
// information_schema, shows every table whatever the role's privileges.
func presentTables(ctx context.Context, conn *sql.Conn) (hasUsers, hasVersionTable bool, err error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT c.relname FROM pg_catalog.pg_class c
		 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND c.relname IN ('users', $1)`,
		MigrationsTable)
	if err != nil {
		return false, false, fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, false, fmt.Errorf("authkit: migrate: %w", err)
		}
		switch name {
		case "users":
			hasUsers = true
		case MigrationsTable:
			hasVersionTable = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, fmt.Errorf("authkit: migrate: %w", err)
	}
	return hasUsers, hasVersionTable, nil
}

// baselineSchema lists, per table, every column the baseline migrations
// (000001 to 000004) create. A database that already has the tables but no
// version table is only adopted when it has all of them. Keep it in step with
// the SQL; TestMigrateEmptyDatabase checks the two against a real database.
var baselineSchema = map[string][]string{
	"users": {
		"id", "name", "email", "phone", "password", "role", "role_id",
		"email_verified_at", "phone_verified_at", "last_login_at", "last_login_ip",
		"last_login_user_agent", "locked_until", "password_changed_at",
		"login_provider", "avatar_url", "metadata", "created_at", "updated_at", "deleted_at",
	},
	"blacklist": {"id", "token", "created_at", "expires_at"},
	"roles": {
		"id", "name", "display_name", "description", "is_system",
		"created_at", "updated_at", "deleted_at",
	},
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

// missingFromSchema returns what expected requires and actual lacks, as "table"
// for a missing table and "table.column" for a missing column, sorted. Extra
// tables and columns in actual are ignored.
func missingFromSchema(expected, actual map[string][]string) []string {
	var missing []string
	for table, cols := range expected {
		have, ok := actual[table]
		if !ok {
			missing = append(missing, table)
			continue
		}
		set := make(map[string]struct{}, len(have))
		for _, c := range have {
			set[c] = struct{}{}
		}
		for _, c := range cols {
			if _, ok := set[c]; !ok {
				missing = append(missing, table+"."+c)
			}
		}
	}
	sort.Strings(missing)
	return missing
}
