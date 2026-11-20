// Package migrate applies the embedded authkit migrations: its own version
// table, an advisory lock so instances serialize, and dirty-state handling.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/internal/migrations"
)

// Table is the version table authkit uses, so it never collides with the host
// project's own golang-migrate table (schema_migrations by default).
const Table = "authkit_schema_migrations"

// ErrDirty means the version table records a failed migration. Fix the
// database by hand and clear the dirty flag; never delete the record.
var ErrDirty = errors.New("authkit: migrations are in a dirty state")

// migrationsFS holds the embedded *.sql files at its root.
var migrationsFS fs.FS = migrations.FS

func embeddedSource() (source.Driver, error) { return iofs.New(migrationsFS, ".") }

// Up applies pending migrations; safe on every start (instances serialize on an
// advisory lock). ctx bounds the connection checkout only; see README, Migrations.
func Up(ctx context.Context, gdb *gorm.DB) error {
	return up(ctx, gdb, embeddedSource)
}

func up(ctx context.Context, gdb *gorm.DB, newSource func() (source.Driver, error)) error {
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

	src, err := newSource()
	if err != nil {
		return fmt.Errorf("authkit: migrate: source: %w", err)
	}
	drv, err := postgres.WithConnection(ctx, conn, &postgres.Config{MigrationsTable: Table})
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	m, err := gomigrate.NewWithInstance("iofs", src, "postgres", drv)
	if err != nil {
		_ = src.Close()
		_ = drv.Close()
		return fmt.Errorf("authkit: migrate: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := ctx.Err(); err != nil {
		return err
	}
	err = m.Up()
	var dirty gomigrate.ErrDirty
	switch {
	case err == nil, errors.Is(err, gomigrate.ErrNoChange):
		return nil
	case errors.As(err, &dirty):
		return dirtyError(dirty.Version)
	default:
		return fmt.Errorf("authkit: migrate: %w", err)
	}
}

func dirtyError(version int) error {
	return fmt.Errorf("%w: table %q records a failed migration at version %d; repair the database by hand, then set the record to the last fully applied version and clear its dirty flag (never delete the record: a missing record next to existing tables makes the database look unmigrated)",
		ErrDirty, Table, version)
}
