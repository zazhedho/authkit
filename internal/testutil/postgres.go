package testutil

import (
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/zazhedho/authkit/internal/migrate"
)

// PostgresSchema returns a connection on a fresh schema with every migration
// applied, dropped when the test ends. An empty dsn (the tests pass
// AUTHKIT_TEST_DATABASE_URL) skips the test.
func PostgresSchema(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL is not set")
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := "authkit_t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := admin.Exec(`CREATE SCHEMA ` + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := gorm.Open(postgres.Open(u.String()), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`).Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := migrate.Up(t.Context(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
