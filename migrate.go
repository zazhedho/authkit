package authkit

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"
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
// correct or delete the version record.
var ErrMigrationsDirty = errors.New("authkit: migrations are in a dirty state")

//go:embed migrations/*.sql
var migrationsFS embed.FS

func embeddedSource() (source.Driver, error) { return iofs.New(migrationsFS, "migrations") }

// Migrate brings the database to the schema authkit needs, using the embedded
// migrations and the MigrationsTable version table in the connection's current
// schema. It is safe to call on every start and from several instances at once.
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
// ctx bounds the schema inspection only; a migration that has started is not
// canceled mid-statement. Run Migrate before the host project's migrations.
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
	return fmt.Errorf("%w: table %q records a failed migration at version %d; repair the database by hand and then fix or delete that record",
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
// lacks part of the baseline schema, and ErrMigrationsDirty for a dirty record.
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
		var (
			version int
			dirty   bool
		)
		err := conn.QueryRowContext(ctx,
			`SELECT version, dirty FROM `+quoteIdent(schema.String)+`.`+quoteIdent(MigrationsTable)+` LIMIT 1`).Scan(&version, &dirty)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return false, fmt.Errorf("authkit: migrate: %w", err)
		case dirty:
			return false, dirtyError(version)
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
		`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()`)
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
// current schema, from a single statement.
func presentTables(ctx context.Context, conn *sql.Conn) (hasUsers, hasVersionTable bool, err error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('users', $1)`,
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
